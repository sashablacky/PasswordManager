import os
import logging
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Set up logging
logging.basicConfig(level=logging.INFO)
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
        self._key: Optional[bytes] = None
        self._cipher: Optional[AESGCM] = None
        logger.info("EncryptionEngine initialized")

    def set_key(self, key: bytes) -> None:
        if not isinstance(key, bytes):
            raise EncryptionError("Key must be bytes")

        if len(key) != self.KEY_SIZE:
            raise EncryptionError(f"Key must be {self.KEY_SIZE} bytes (256 bits), got {len(key)} bytes")

        self._key = key
        self._cipher = AESGCM(key)
        logger.info("Encryption key set successfully")

    def encrypt(self, plaintext: str) -> bytes:
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
            ciphertext = self._cipher.encrypt(iv, data, None)

            # Combine IV + ciphertext for storage
            # We need the IV to decrypt later
            encrypted_data = iv + ciphertext

            logger.debug(f"Encrypted {len(data)} bytes → {len(encrypted_data)} bytes")

            return encrypted_data

        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise EncryptionError(f"Encryption failed: {e}")

    def decrypt(self, encrypted_data: bytes) -> str:
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
            plaintext_bytes = self._cipher.decrypt(iv, ciphertext, None)

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
        if self._key:
            # Overwrite key with zeros before deleting
            self._key = b'\x00' * len(self._key)
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
        if self._key:
            self.clear_key()