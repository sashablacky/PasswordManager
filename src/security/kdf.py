import os
import hashlib
import logging
import hmac
from typing import Tuple
from argon2.low_level import hash_secret_raw, Type


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())  # Prevents logging spam in libraries


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

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a cryptographic key from a password and salt"""
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
                time_cost=self.TIME_COST,
                memory_cost=self.MEMORY_COST,
                parallelism=self.PARALLELISM,
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