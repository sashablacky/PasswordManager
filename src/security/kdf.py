import os
import hashlib
import logging
import hmac
from typing import Optional, Tuple
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())  # Prevents logging spam in libraries

# Vault formats (stored in users.kdf_version):
# 1 - the Argon2 output is the encryption key and SHA-256 of it is the stored
#     verifier; ciphertexts are not bound to their entry (no associated data).
# 2 - the encryption key and the verifier are separate HKDF subkeys of the
#     Argon2 output, all Argon2 parameters are stored, and every ciphertext is
#     bound to its entry and field. Version 1 vaults are upgraded at login.
VAULT_FORMAT_LEGACY = 1
VAULT_FORMAT_CURRENT = 2

_HKDF_INFO_ENCRYPTION = b"SecureVault v2 encryption key"
_HKDF_INFO_VERIFIER = b"SecureVault v2 password verifier"


class KDFError(Exception):
    """Custom exception for KDF-related errors"""
    pass


class KeyDerivationFunction:
    # Argon2id parameters (OWASP-aligned)
    TIME_COST = 3
    MEMORY_COST = 65536  # 64 MB (in KiB)
    PARALLELISM = 4
    HASH_LENGTH = 32  # 256 bits
    SALT_LENGTH = 16  # 128 bits

    def __init__(self):
        logger.debug(
            f"KDF initialized: time={self.TIME_COST}, "
            f"memory={self.MEMORY_COST}KB, parallelism={self.PARALLELISM}"
        )

    def derive_key(self, password: str, salt: bytes, time_cost: Optional[int] = None,
                   memory_cost: Optional[int] = None, parallelism: Optional[int] = None) -> bytes:
        """Derive a cryptographic key from a password and salt

        The Argon2 parameters default to the current ones; vaults pass the
        parameters they were created with, so changing the defaults in a later
        version does not lock existing vaults out.
        """
        if not isinstance(password, str):
            raise KDFError("Password must be a string")

        if not isinstance(salt, bytes):
            raise KDFError("Salt must be bytes")

        if len(salt) != self.SALT_LENGTH:
            raise KDFError(f"Salt must be {self.SALT_LENGTH} bytes")

        if not password:
            raise KDFError("Password cannot be empty")

        try:
            password_bytes = password.encode("utf-8")

            key = hash_secret_raw(
                secret=password_bytes,
                salt=salt,
                time_cost=time_cost or self.TIME_COST,
                memory_cost=memory_cost or self.MEMORY_COST,
                parallelism=parallelism or self.PARALLELISM,
                hash_len=self.HASH_LENGTH,
                type=Type.ID  # Argon2id
            )

            return key

        except Exception as e:
            logger.error(f"Key derivation failed: {e}")
            raise KDFError(f"Key derivation failed: {e}")

    @staticmethod
    def generate_salt() -> bytes:
        """Generate a secure random salt"""
        return os.urandom(KeyDerivationFunction.SALT_LENGTH)

    def hash_password(self, password: str) -> Tuple[str, bytes]:
        """Hash password for storage"""
        if not isinstance(password, str):
            raise KDFError("Password must be a string")

        if not password:
            raise KDFError("Password cannot be empty")

        salt = self.generate_salt()
        key = self.derive_key(password, salt)

        # Store SHA-256 of derived key (keeps tests intact)
        password_hash = hashlib.sha256(key).hexdigest()

        return password_hash, salt

    def verify_password(self, password: str, stored_hash: str, salt: bytes) -> bool:
        """Verify password against stored hash"""
        try:
            key = self.derive_key(password, salt)
            computed_hash = hashlib.sha256(key).hexdigest()

            return self._constant_time_compare(computed_hash, stored_hash)

        except Exception as e:
            logger.warning(f"Password verification failed: {e}")
            return False

    @staticmethod
    def split_master_key(master_key: bytes) -> Tuple[bytearray, str]:
        """Derive the encryption key and the stored verifier from the Argon2 output (format 2)

        The verifier is an independent subkey, so the value kept in the
        database says nothing about the key that encrypts the entries.
        """
        def subkey(info: bytes) -> bytes:
            return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(bytes(master_key))

        encryption_key = bytearray(subkey(_HKDF_INFO_ENCRYPTION))
        verifier = subkey(_HKDF_INFO_VERIFIER).hex()
        return encryption_key, verifier

    def open_vault(self, password: str, stored_hash: str, salt: bytes, kdf_version: int,
                   time_cost: Optional[int] = None, memory_cost: Optional[int] = None,
                   parallelism: Optional[int] = None) -> Optional[bytearray]:
        """Check the master password and return the encryption key, or None if it is wrong"""
        try:
            master = self.derive_key(password, salt, time_cost, memory_cost, parallelism)
        except KDFError as e:
            logger.warning(f"Password verification failed: {e}")
            return None

        if kdf_version >= VAULT_FORMAT_CURRENT:
            encryption_key, verifier = self.split_master_key(master)
        else:
            encryption_key, verifier = bytearray(master), hashlib.sha256(master).hexdigest()

        if self._constant_time_compare(verifier, stored_hash):
            return encryption_key

        encryption_key[:] = bytes(len(encryption_key))
        return None

    def new_vault_secrets(self, password: str) -> Tuple[str, bytes, bytearray]:
        """Fresh salt, verifier and encryption key for a format 2 vault with the current parameters"""
        salt = self.generate_salt()
        encryption_key, verifier = self.split_master_key(self.derive_key(password, salt))
        return verifier, salt, encryption_key

    @staticmethod
    def _constant_time_compare(a: str, b: str) -> bool:
        """Constant-time comparison to prevent timing attacks"""
        return hmac.compare_digest(a, b)

    def estimate_derivation_time(self, iterations: int = 10) -> float:
        """Estimate average key derivation time"""
        import time

        test_password = "TestPassword123!"
        test_salt = self.generate_salt()

        times = []
        for _ in range(iterations):
            start = time.time()
            self.derive_key(test_password, test_salt)
            times.append(time.time() - start)

        return sum(times) / len(times)