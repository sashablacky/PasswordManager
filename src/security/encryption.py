import os
import logging
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

logger = logging.getLogger(__name__)


class EncryptionError(Exception):
    """Custom exception for encryption-related errors"""
    pass


class DecryptionError(Exception):
    """Custom exception for decryption-related errors"""
    pass


class EncryptionEngine:
    """Handles AES-256-GCM encryption and decryption"""

    # Constants
    KEY_SIZE = 32  # 256 bits
    IV_SIZE = 12  # 96 bits (recommended for GCM)
    TAG_SIZE = 16  # 128 bits (included in ciphertext by AESGCM)

    def __init__(self):
        # Kept in a mutable bytearray (which AESGCM uses directly), so clear_key()
        # can overwrite the key in place instead of leaving it in memory
        self._key: Optional[bytearray] = None
        self._cipher: Optional[AESGCM] = None
        # Vault format 2 binds every stored ciphertext to its entry and field
        # (see record_aad); a format 1 vault that could not be upgraded turns this off
        self.bind_records = True
        logger.info("EncryptionEngine initialized")

    def set_key(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)):
            raise EncryptionError("Key must be bytes")

        if len(key) != self.KEY_SIZE:
            raise EncryptionError(f"Key must be {self.KEY_SIZE} bytes (256 bits), got {len(key)} bytes")

        new_key = bytearray(key)
        self.clear_key()
        self._key = new_key
        self._cipher = AESGCM(self._key)
        logger.info("Encryption key set successfully")

    def copy_key(self) -> bytearray:
        """A separate copy of the key (e.g. for a worker thread); the caller wipes it when done"""
        if self._key is None:
            raise EncryptionError("Encryption key not set. Call set_key() first.")
        return bytearray(self._key)

    def encrypt(self, plaintext: str, associated_data: Optional[bytes] = None) -> bytes:
        if self._cipher is None:
            raise EncryptionError("Encryption key not set. Call set_key() first.")

        if not isinstance(plaintext, str):
            raise EncryptionError("Plaintext must be a string")

        try:
            # Convert string to bytes
            data = plaintext.encode('utf-8')

            # Generate random initialization vector (IV)
            # Each encryption MUST use a unique IV for security
            iv = os.urandom(self.IV_SIZE)

            # Encrypt the data
            # GCM mode automatically adds authentication tag to ciphertext
            ciphertext = self._cipher.encrypt(iv, data, associated_data)

            # Combine IV + ciphertext for storage
            # We need the IV to decrypt later
            encrypted_data = iv + ciphertext

            logger.debug(f"Encrypted {len(data)} bytes → {len(encrypted_data)} bytes")

            return encrypted_data

        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise EncryptionError(f"Encryption failed: {e}")

    def decrypt(self, encrypted_data: bytes, associated_data: Optional[bytes] = None) -> str:
        if self._cipher is None:
            raise DecryptionError("Encryption key not set. Call set_key() first.")

        if not isinstance(encrypted_data, bytes):
            raise DecryptionError("Encrypted data must be bytes")

        if len(encrypted_data) < self.IV_SIZE:
            raise DecryptionError(f"Encrypted data too short. Need at least {self.IV_SIZE} bytes for IV")

        try:
            # Extract IV from the beginning
            iv = encrypted_data[:self.IV_SIZE]

            # Extract ciphertext (includes authentication tag)
            ciphertext = encrypted_data[self.IV_SIZE:]

            # Decrypt and verify authentication tag
            # If tag doesn't match, this will raise InvalidTag exception
            plaintext_bytes = self._cipher.decrypt(iv, ciphertext, associated_data)

            # Convert bytes back to string
            plaintext = plaintext_bytes.decode('utf-8')

            logger.debug(f"Decrypted {len(encrypted_data)} bytes → {len(plaintext)} chars")

            return plaintext

        except InvalidTag:
            logger.error("Decryption failed: Authentication tag invalid (data may be tampered)")
            raise DecryptionError("Decryption failed: Data has been tampered with or corrupted")

        except UnicodeDecodeError:
            logger.error("Decryption failed: Invalid UTF-8 data")
            raise DecryptionError("Decryption failed: Invalid data encoding")

        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise DecryptionError(f"Decryption failed: {e}")

    def clear_key(self) -> None:
        if self._key is not None:
            # Overwrite the key bytes in place (the cipher object uses this same buffer)
            wipe(self._key)
            self._key = None
            self._cipher = None
            logger.info("Encryption key cleared from memory")

    def is_key_set(self) -> bool:
        return self._cipher is not None

    @staticmethod
    def generate_key() -> bytes:
        key = os.urandom(EncryptionEngine.KEY_SIZE)
        logger.info("Generated new 256-bit encryption key")
        return key

    def __del__(self):
        if self._key is not None:
            self.clear_key()


# Field name used in the associated data of an encrypted breach check result
BREACH_RESULT_FIELD = "breach_result"


def wipe(buffer: Optional[bytearray]) -> None:
    """Overwrite a key held in a bytearray with zeros"""
    if buffer is not None:
        for i in range(len(buffer)):
            buffer[i] = 0


def record_aad(engine: EncryptionEngine, password_id: int, field: str) -> Optional[bytes]:
    """Associated data that ties a stored ciphertext to its entry and field

    With it, a ciphertext copied into another entry or another column of the
    database no longer decrypts, instead of silently showing the wrong secret.
    """
    if not engine.bind_records:
        return None
    return f"securevault/v2/{password_id}/{field}".encode("utf-8")

def browser_client_aad(client_id: str) -> bytes:
    """Associated data of the stored pairing key of a browser extension"""
    return f"securevault/browser/{client_id}/key".encode("utf-8")
