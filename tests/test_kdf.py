"""
Unit tests for Key Derivation Function
"""

import pytest
import sys
import os
import time

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.security.kdf import KeyDerivationFunction, KDFError


@pytest.fixture
def kdf():
    """Fixture to create KDF instance"""
    return KeyDerivationFunction()


class TestSaltGeneration:
    """Test salt generation"""

    def test_generate_salt_length(self):
        """Test salt has correct length"""
        salt = KeyDerivationFunction.generate_salt()

        assert isinstance(salt, bytes)
        assert len(salt) == 16  # 128 bits

    def test_generate_salt_unique(self):
        """Test that salts are unique"""
        salt1 = KeyDerivationFunction.generate_salt()
        salt2 = KeyDerivationFunction.generate_salt()
        salt3 = KeyDerivationFunction.generate_salt()

        # All should be different
        assert salt1 != salt2
        assert salt2 != salt3
        assert salt1 != salt3

    def test_generate_salt_randomness(self):
        """Test salt appears random (not all zeros)"""
        salt = KeyDerivationFunction.generate_salt()

        # Should not be all zeros
        assert salt != b'\x00' * 16

        # Should have variety of bytes
        unique_bytes = len(set(salt))
        assert unique_bytes > 5  # At least some variety


class TestKeyDerivation:
    """Test key derivation from password"""

    def test_derive_key_basic(self, kdf):
        """Test basic key derivation"""
        password = "TestPassword123"
        salt = KeyDerivationFunction.generate_salt()

        key = kdf.derive_key(password, salt)

        assert isinstance(key, bytes)
        assert len(key) == 32  # 256 bits for AES-256

    def test_derive_key_deterministic(self, kdf):
        """Test same password + salt produces same key"""
        password = "MyPassword"
        salt = KeyDerivationFunction.generate_salt()

        key1 = kdf.derive_key(password, salt)
        key2 = kdf.derive_key(password, salt)
        key3 = kdf.derive_key(password, salt)

        assert key1 == key2
        assert key2 == key3

    def test_derive_key_different_salts(self, kdf):
        """Test different salts produce different keys"""
        password = "SamePassword"
        salt1 = KeyDerivationFunction.generate_salt()
        salt2 = KeyDerivationFunction.generate_salt()

        key1 = kdf.derive_key(password, salt1)
        key2 = kdf.derive_key(password, salt2)

        assert key1 != key2

    def test_derive_key_different_passwords(self, kdf):
        """Test different passwords produce different keys"""
        salt = KeyDerivationFunction.generate_salt()

        key1 = kdf.derive_key("Password1", salt)
        key2 = kdf.derive_key("Password2", salt)

        assert key1 != key2

    def test_derive_key_empty_password(self, kdf):
        """Test empty password raises error"""
        salt = KeyDerivationFunction.generate_salt()

        with pytest.raises(KDFError, match="Password cannot be empty"):
            kdf.derive_key("", salt)

    def test_derive_key_invalid_password_type(self, kdf):
        """Test non-string password raises error"""
        salt = KeyDerivationFunction.generate_salt()

        with pytest.raises(KDFError, match="Password must be a string"):
            kdf.derive_key(12345, salt)

    def test_derive_key_invalid_salt_type(self, kdf):
        """Test non-bytes salt raises error"""
        with pytest.raises(KDFError, match="Salt must be bytes"):
            kdf.derive_key("password", "not_bytes")

    def test_derive_key_wrong_salt_length(self, kdf):
        """Test salt with wrong length raises error"""
        short_salt = b'short'

        with pytest.raises(KDFError, match="Salt must be 16 bytes"):
            kdf.derive_key("password", short_salt)

    def test_derive_key_unicode_password(self, kdf):
        """Test deriving key from Unicode password"""
        password = "密码测试 🔐 Ñoño"
        salt = KeyDerivationFunction.generate_salt()

        key = kdf.derive_key(password, salt)

        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_derive_key_long_password(self, kdf):
        """Test deriving key from very long password"""
        password = "A" * 1000  # 1000 characters
        salt = KeyDerivationFunction.generate_salt()

        key = kdf.derive_key(password, salt)

        assert len(key) == 32

    def test_derive_key_special_characters(self, kdf):
        """Test password with special characters"""
        password = "P@$$w0rd!#$%^&*()"
        salt = KeyDerivationFunction.generate_salt()

        key = kdf.derive_key(password, salt)

        assert len(key) == 32


class TestPasswordHashing:
    """Test password hashing for storage"""

    def test_hash_password_basic(self, kdf):
        """Test basic password hashing"""
        password = "TestPassword123"

        password_hash, salt = kdf.hash_password(password)

        assert isinstance(password_hash, str)
        assert isinstance(salt, bytes)
        assert len(password_hash) == 64  # SHA-256 hex = 64 chars
        assert len(salt) == 16

    def test_hash_password_unique(self, kdf):
        """Test same password produces different hashes (due to different salts)"""
        password = "SamePassword"

        hash1, salt1 = kdf.hash_password(password)
        hash2, salt2 = kdf.hash_password(password)

        # Different salts
        assert salt1 != salt2

        # Different hashes
        assert hash1 != hash2

    def test_hash_password_empty(self, kdf):
        """Test hashing empty password raises error"""
        with pytest.raises(KDFError, match="Password cannot be empty"):
            kdf.hash_password("")


class TestPasswordVerification:
    """Test password verification"""

    def test_verify_password_correct(self, kdf):
        """Test verifying correct password"""
        password = "CorrectPassword123"
        password_hash, salt = kdf.hash_password(password)

        is_valid = kdf.verify_password(password, password_hash, salt)

        assert is_valid is True

    def test_verify_password_wrong(self, kdf):
        """Test verifying wrong password"""
        password = "CorrectPassword"
        password_hash, salt = kdf.hash_password(password)

        wrong_password = "WrongPassword"
        is_valid = kdf.verify_password(wrong_password, password_hash, salt)

        assert is_valid is False

    def test_verify_password_case_sensitive(self, kdf):
        """Test password verification is case-sensitive"""
        password = "Password"
        password_hash, salt = kdf.hash_password(password)

        wrong_case = "password"  # lowercase
        is_valid = kdf.verify_password(wrong_case, password_hash, salt)

        assert is_valid is False

    def test_verify_password_slight_difference(self, kdf):
        """Test that even slight differences are caught"""
        password = "Password123"
        password_hash, salt = kdf.hash_password(password)

        # Very similar but wrong
        similar = "Password124"
        is_valid = kdf.verify_password(similar, password_hash, salt)

        assert is_valid is False

    def test_verify_password_wrong_salt(self, kdf):
        """Test verification fails with wrong salt"""
        password = "TestPassword"
        password_hash, salt1 = kdf.hash_password(password)

        # Generate different salt
        salt2 = KeyDerivationFunction.generate_salt()

        # Should fail even with correct password
        is_valid = kdf.verify_password(password, password_hash, salt2)

        assert is_valid is False


class TestConstantTimeCompare:
    """Test constant-time comparison"""

    def test_constant_time_compare_equal(self, kdf):
        """Test comparing equal strings"""
        result = kdf._constant_time_compare("hello", "hello")
        assert result is True

    def test_constant_time_compare_different(self, kdf):
        """Test comparing different strings"""
        result = kdf._constant_time_compare("hello", "world")
        assert result is False

    def test_constant_time_compare_different_length(self, kdf):
        """Test comparing strings of different lengths"""
        result = kdf._constant_time_compare("short", "verylongstring")
        assert result is False

    def test_constant_time_compare_empty(self, kdf):
        """Test comparing empty strings"""
        result = kdf._constant_time_compare("", "")
        assert result is True


class TestSecurityProperties:
    """Test security properties of key derivation"""

    def test_avalanche_effect(self, kdf):
        """Test that small password change creates large key change"""
        salt = KeyDerivationFunction.generate_salt()

        # Two very similar passwords
        password1 = "Password123"
        password2 = "Password124"  # Only last char different

        key1 = kdf.derive_key(password1, salt)
        key2 = kdf.derive_key(password2, salt)

        # Count different bytes
        different_bytes = sum(a != b for a, b in zip(key1, key2))

        # Should have significant differences (avalanche effect)
        # At least 40% of bytes should be different
        assert different_bytes > len(key1) * 0.4

    def test_key_not_predictable(self, kdf):
        """Test derived key appears random"""
        password = "TestPassword"
        salt = KeyDerivationFunction.generate_salt()

        key = kdf.derive_key(password, salt)

        # Key should not be all zeros
        assert key != b'\x00' * 32

        # Key should have variety of bytes
        unique_bytes = len(set(key))
        assert unique_bytes > 15  # Good randomness

    def test_salt_not_in_key(self, kdf):
        """Test that salt doesn't appear in derived key"""
        password = "TestPassword"
        salt = KeyDerivationFunction.generate_salt()

        key = kdf.derive_key(password, salt)

        # Salt should not appear in key
        assert salt not in key

    def test_password_not_in_key(self, kdf):
        """Test that password doesn't appear in derived key"""
        password = "TestPassword1234567890"  # Long enough to be meaningful
        salt = KeyDerivationFunction.generate_salt()

        key = kdf.derive_key(password, salt)

        # Password (as bytes) should not appear in key
        assert password.encode() not in key


class TestPerformance:
    """Test performance characteristics"""

    def test_derivation_time_acceptable(self, kdf):
        """Test key derivation completes in reasonable time"""
        password = "TestPassword123"
        salt = KeyDerivationFunction.generate_salt()

        start = time.time()
        kdf.derive_key(password, salt)
        elapsed = time.time() - start

        # Should complete in under 2 seconds (target ~300ms)
        assert elapsed < 2.0, f"Key derivation too slow: {elapsed * 1000:.0f}ms"

    def test_derivation_slow_enough(self, kdf):
        """Test key derivation is slow enough to prevent brute force"""
        password = "TestPassword"
        salt = KeyDerivationFunction.generate_salt()

        start = time.time()
        kdf.derive_key(password, salt)
        elapsed = time.time() - start

        # Should take at least 50ms (prevents fast brute force)
        assert elapsed > 0.05, f"Key derivation too fast: {elapsed * 1000:.0f}ms"

    def test_estimate_derivation_time(self, kdf):
        """Test derivation time estimation"""
        avg_time = kdf.estimate_derivation_time(iterations=3)

        assert isinstance(avg_time, float)
        assert 0.05 < avg_time < 2.0  # Between 50ms and 2s


class TestIntegration:
    """Test integration scenarios"""

    def test_complete_login_flow(self, kdf):
        """Test complete account creation and login flow"""
        # User creates account
        password = "UserPassword123!"
        password_hash, salt = kdf.hash_password(password)

        # Store these in database (simulated)
        stored_hash = password_hash
        stored_salt = salt

        # User logs in
        login_attempt = "UserPassword123!"

        # Verify password
        is_valid = kdf.verify_password(login_attempt, stored_hash, stored_salt)
        assert is_valid is True

        # Derive encryption key for session
        encryption_key = kdf.derive_key(login_attempt, stored_salt)
        assert len(encryption_key) == 32

    def test_failed_login_flow(self, kdf):
        """Test failed login attempt"""
        # User creates account
        password = "CorrectPassword"
        password_hash, salt = kdf.hash_password(password)

        # User attempts wrong password
        wrong_attempt = "WrongPassword"
        is_valid = kdf.verify_password(wrong_attempt, password_hash, salt)

        assert is_valid is False

    def test_multiple_users(self, kdf):
        """Test multiple users with different passwords"""
        # User 1
        pass1 = "User1Password"
        hash1, salt1 = kdf.hash_password(pass1)

        # User 2
        pass2 = "User2Password"
        hash2, salt2 = kdf.hash_password(pass2)

        # User 3
        pass3 = "User3Password"
        hash3, salt3 = kdf.hash_password(pass3)

        # All should have different hashes and salts
        assert hash1 != hash2 != hash3
        assert salt1 != salt2 != salt3

        # Each user can verify their own password
        assert kdf.verify_password(pass1, hash1, salt1) is True
        assert kdf.verify_password(pass2, hash2, salt2) is True
        assert kdf.verify_password(pass3, hash3, salt3) is True

        # But not other users' passwords
        assert kdf.verify_password(pass1, hash2, salt2) is False
        assert kdf.verify_password(pass2, hash3, salt3) is False


class TestEdgeCases:
    """Test edge cases"""

    def test_very_short_password(self, kdf):
        """Test very short password (1 character)"""
        password = "a"
        salt = KeyDerivationFunction.generate_salt()

        key = kdf.derive_key(password, salt)

        assert len(key) == 32

    def test_very_long_password(self, kdf):
        """Test very long password"""
        password = "A" * 10000  # 10,000 chars
        salt = KeyDerivationFunction.generate_salt()

        key = kdf.derive_key(password, salt)

        assert len(key) == 32

    def test_password_with_null_bytes(self, kdf):
        """Test password containing null bytes"""
        password = "Pass\x00word"
        salt = KeyDerivationFunction.generate_salt()

        key = kdf.derive_key(password, salt)

        assert len(key) == 32

    def test_password_all_spaces(self, kdf):
        """Test password that's all spaces"""
        password = "     "
        salt = KeyDerivationFunction.generate_salt()

        key = kdf.derive_key(password, salt)

        assert len(key) == 32


# Run tests if executed directly
if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])