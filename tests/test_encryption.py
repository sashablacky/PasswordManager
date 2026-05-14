"""
Unit tests for EncryptionEngine
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.security.encryption import EncryptionEngine, EncryptionError, DecryptionError


@pytest.fixture
def engine():
    """Fixture to create encryption engine with key set"""
    eng = EncryptionEngine()
    key = EncryptionEngine.generate_key()
    eng.set_key(key)
    return eng


@pytest.fixture
def engine_no_key():
    """Fixture to create encryption engine without key"""
    return EncryptionEngine()


class TestKeyManagement:
    """Test encryption key management"""

    def test_generate_key(self):
        """Test key generation"""
        key = EncryptionEngine.generate_key()

        assert isinstance(key, bytes)
        assert len(key) == 32  # 256 bits

    def test_generate_key_unique(self):
        """Test that generated keys are unique"""
        key1 = EncryptionEngine.generate_key()
        key2 = EncryptionEngine.generate_key()
        key3 = EncryptionEngine.generate_key()

        # All keys should be different
        assert key1 != key2
        assert key2 != key3
        assert key1 != key3

    def test_set_key_valid(self, engine_no_key):
        """Test setting a valid key"""
        key = EncryptionEngine.generate_key()
        engine_no_key.set_key(key)

        assert engine_no_key.is_key_set() is True

    def test_set_key_invalid_type(self, engine_no_key):
        """Test setting invalid key type"""
        with pytest.raises(EncryptionError, match="Key must be bytes"):
            engine_no_key.set_key("not_bytes")

    def test_set_key_invalid_length(self, engine_no_key):
        """Test setting key with wrong length"""
        short_key = b'short'

        with pytest.raises(EncryptionError, match="Key must be 32 bytes"):
            engine_no_key.set_key(short_key)

    def test_clear_key(self, engine):
        """Test clearing encryption key"""
        assert engine.is_key_set() is True

        engine.clear_key()

        assert engine.is_key_set() is False

    def test_is_key_set(self, engine_no_key):
        """Test checking if key is set"""
        assert engine_no_key.is_key_set() is False

        key = EncryptionEngine.generate_key()
        engine_no_key.set_key(key)

        assert engine_no_key.is_key_set() is True


class TestEncryption:
    """Test encryption operations"""

    def test_encrypt_basic(self, engine):
        """Test basic encryption"""
        plaintext = "MySecretPassword123"
        encrypted = engine.encrypt(plaintext)

        assert isinstance(encrypted, bytes)
        assert len(encrypted) > len(plaintext)  # Encrypted data is longer (IV + ciphertext + tag)
        assert encrypted != plaintext.encode()  # Should not be plaintext

    def test_encrypt_without_key(self, engine_no_key):
        """Test encrypting without setting key"""
        with pytest.raises(EncryptionError, match="Encryption key not set"):
            engine_no_key.encrypt("test")

    def test_encrypt_empty_string(self, engine):
        """Test encrypting empty string"""
        encrypted = engine.encrypt("")

        assert isinstance(encrypted, bytes)
        assert len(encrypted) > 0  # Should still have IV and tag

    def test_encrypt_unicode(self, engine):
        """Test encrypting Unicode characters"""
        plaintext = "密码测试 🔐 Ññ"
        encrypted = engine.encrypt(plaintext)

        assert isinstance(encrypted, bytes)

    def test_encrypt_long_text(self, engine):
        """Test encrypting long text"""
        plaintext = "A" * 10000  # 10,000 characters
        encrypted = engine.encrypt(plaintext)

        assert isinstance(encrypted, bytes)
        assert len(encrypted) > len(plaintext)

    def test_encrypt_special_characters(self, engine):
        """Test encrypting special characters"""
        plaintext = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
        encrypted = engine.encrypt(plaintext)

        assert isinstance(encrypted, bytes)

    def test_encrypt_invalid_type(self, engine):
        """Test encrypting non-string type"""
        with pytest.raises(EncryptionError, match="Plaintext must be a string"):
            engine.encrypt(12345)

    def test_encrypt_unique_ivs(self, engine):
        """Test that same plaintext produces different ciphertext (unique IVs)"""
        plaintext = "SamePassword"

        encrypted1 = engine.encrypt(plaintext)
        encrypted2 = engine.encrypt(plaintext)
        encrypted3 = engine.encrypt(plaintext)

        # All encryptions should be different due to random IVs
        assert encrypted1 != encrypted2
        assert encrypted2 != encrypted3
        assert encrypted1 != encrypted3

        # But all should decrypt to same plaintext
        assert engine.decrypt(encrypted1) == plaintext
        assert engine.decrypt(encrypted2) == plaintext
        assert engine.decrypt(encrypted3) == plaintext


class TestDecryption:
    """Test decryption operations"""

    def test_decrypt_basic(self, engine):
        """Test basic decryption"""
        plaintext = "TestPassword123"
        encrypted = engine.encrypt(plaintext)
        decrypted = engine.decrypt(encrypted)

        assert decrypted == plaintext

    def test_decrypt_without_key(self, engine_no_key):
        """Test decrypting without setting key"""
        with pytest.raises(DecryptionError, match="Encryption key not set"):
            engine_no_key.decrypt(b"some_data")

    def test_decrypt_empty_string(self, engine):
        """Test decrypting empty string"""
        encrypted = engine.encrypt("")
        decrypted = engine.decrypt(encrypted)

        assert decrypted == ""

    def test_decrypt_unicode(self, engine):
        """Test decrypting Unicode text"""
        plaintext = "密码 🔐 Test Ññ"
        encrypted = engine.encrypt(plaintext)
        decrypted = engine.decrypt(encrypted)

        assert decrypted == plaintext

    def test_decrypt_multiple_passwords(self, engine):
        """Test encrypting and decrypting multiple passwords"""
        passwords = [
            "Password1",
            "AnotherPassword456",
            "Special!@#$%",
            "密码测试",
            ""
        ]

        for password in passwords:
            encrypted = engine.encrypt(password)
            decrypted = engine.decrypt(encrypted)
            assert decrypted == password

    def test_decrypt_invalid_type(self, engine):
        """Test decrypting non-bytes type"""
        with pytest.raises(DecryptionError, match="Encrypted data must be bytes"):
            engine.decrypt("not_bytes")

    def test_decrypt_too_short(self, engine):
        """Test decrypting data that's too short"""
        short_data = b"short"

        with pytest.raises(DecryptionError, match="Encrypted data too short"):
            engine.decrypt(short_data)

    def test_decrypt_tampered_data(self, engine):
        """Test decrypting tampered data (should fail authentication)"""
        plaintext = "SecretPassword"
        encrypted = engine.encrypt(plaintext)

        # Tamper with the data
        tampered = bytearray(encrypted)
        tampered[-1] ^= 0xFF  # Flip bits in authentication tag

        with pytest.raises(DecryptionError, match="tampered"):
            engine.decrypt(bytes(tampered))

    def test_decrypt_wrong_key(self):
        """Test decrypting with wrong key"""
        # Encrypt with first key
        engine1 = EncryptionEngine()
        key1 = EncryptionEngine.generate_key()
        engine1.set_key(key1)

        plaintext = "SecretMessage"
        encrypted = engine1.encrypt(plaintext)

        # Try to decrypt with different key
        engine2 = EncryptionEngine()
        key2 = EncryptionEngine.generate_key()
        engine2.set_key(key2)

        with pytest.raises(DecryptionError):
            engine2.decrypt(encrypted)

    def test_decrypt_corrupted_iv(self, engine):
        """Test decrypting data with corrupted IV"""
        plaintext = "TestPassword"
        encrypted = engine.encrypt(plaintext)

        # Corrupt the IV (first 12 bytes)
        corrupted = bytearray(encrypted)
        corrupted[0] ^= 0xFF

        with pytest.raises(DecryptionError):
            engine.decrypt(bytes(corrupted))


class TestRoundTrip:
    """Test complete encrypt-decrypt cycles"""

    def test_roundtrip_basic(self, engine):
        """Test basic encrypt-decrypt roundtrip"""
        original = "MyPassword123"
        encrypted = engine.encrypt(original)
        decrypted = engine.decrypt(encrypted)

        assert decrypted == original

    def test_roundtrip_multiple(self, engine):
        """Test multiple sequential roundtrips"""
        original = "Password"

        # Encrypt and decrypt 10 times
        for _ in range(10):
            encrypted = engine.encrypt(original)
            decrypted = engine.decrypt(encrypted)
            assert decrypted == original

    def test_roundtrip_nested(self, engine):
        """Test encrypting already encrypted data"""
        original = "Secret"

        # First encryption
        encrypted1 = engine.encrypt(original)

        # Decrypt and verify
        decrypted1 = engine.decrypt(encrypted1)
        assert decrypted1 == original

        # Second encryption
        encrypted2 = engine.encrypt(decrypted1)

        # Should be different from first encryption
        assert encrypted2 != encrypted1

        # But decrypt to same value
        decrypted2 = engine.decrypt(encrypted2)
        assert decrypted2 == original

    def test_roundtrip_with_key_change(self):
        """Test that data encrypted with one key can't be decrypted with another"""
        engine1 = EncryptionEngine()
        key1 = EncryptionEngine.generate_key()
        engine1.set_key(key1)

        plaintext = "SecretData"
        encrypted = engine1.encrypt(plaintext)

        # Clear key and set new one
        engine1.clear_key()
        key2 = EncryptionEngine.generate_key()
        engine1.set_key(key2)

        # Should not be able to decrypt with new key
        with pytest.raises(DecryptionError):
            engine1.decrypt(encrypted)

        # But should work with original key
        engine1.set_key(key1)
        decrypted = engine1.decrypt(encrypted)
        assert decrypted == plaintext


class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_very_long_password(self, engine):
        """Test encrypting very long password"""
        long_password = "A" * 100000  # 100KB

        encrypted = engine.encrypt(long_password)
        decrypted = engine.decrypt(encrypted)

        assert decrypted == long_password

    def test_password_with_null_bytes(self, engine):
        """Test password containing null bytes"""
        password = "Pass\x00word\x00Test"

        encrypted = engine.encrypt(password)
        decrypted = engine.decrypt(encrypted)

        assert decrypted == password

    def test_all_printable_ascii(self, engine):
        """Test encrypting all printable ASCII characters"""
        import string
        plaintext = string.printable

        encrypted = engine.encrypt(plaintext)
        decrypted = engine.decrypt(encrypted)

        assert decrypted == plaintext

    def test_binary_looking_string(self, engine):
        """Test string that looks like binary data"""
        plaintext = "\x01\x02\x03\x04\x05"

        encrypted = engine.encrypt(plaintext)
        decrypted = engine.decrypt(encrypted)

        assert decrypted == plaintext


class TestSecurity:
    """Test security properties"""

    def test_encrypted_data_not_predictable(self, engine):
        """Test that encrypted data appears random"""
        plaintext = "AAAAAAAAAA"  # Repetitive pattern
        encrypted = engine.encrypt(plaintext)

        # Encrypted data should not contain the pattern
        assert b'AAAAAAAAAA' not in encrypted

        # Should not have obvious patterns (weak test, but better than nothing)
        # Check that not all bytes are the same
        unique_bytes = len(set(encrypted))
        assert unique_bytes > 10  # Should have good variety

    def test_no_key_leakage_in_encrypted_data(self, engine):
        """Test that encryption key is not present in encrypted data"""
        key = EncryptionEngine.generate_key()
        engine.set_key(key)

        plaintext = "TestPassword"
        encrypted = engine.encrypt(plaintext)

        # Key should not appear in encrypted data
        assert key not in encrypted

        # No part of key should appear
        for i in range(len(key) - 4):
            assert key[i:i + 4] not in encrypted

    def test_iv_is_included(self, engine):
        """Test that IV is included in encrypted data"""
        plaintext = "Test"
        encrypted = engine.encrypt(plaintext)

        # First 12 bytes should be the IV
        assert len(encrypted) >= 12

        # Each encryption should have different IV
        encrypted2 = engine.encrypt(plaintext)

        iv1 = encrypted[:12]
        iv2 = encrypted2[:12]

        assert iv1 != iv2


class TestPerformance:
    """Test performance characteristics"""

    def test_encryption_speed(self, engine):
        """Test that encryption is reasonably fast"""
        import time

        plaintext = "TestPassword123"
        iterations = 100

        start = time.time()
        for _ in range(iterations):
            engine.encrypt(plaintext)
        elapsed = time.time() - start

        avg_time = elapsed / iterations

        # Should be faster than 10ms per encryption
        assert avg_time < 0.01, f"Encryption too slow: {avg_time * 1000:.2f}ms"

    def test_decryption_speed(self, engine):
        """Test that decryption is reasonably fast"""
        import time

        plaintext = "TestPassword123"
        encrypted = engine.encrypt(plaintext)
        iterations = 100

        start = time.time()
        for _ in range(iterations):
            engine.decrypt(encrypted)
        elapsed = time.time() - start

        avg_time = elapsed / iterations

        # Should be faster than 10ms per decryption
        assert avg_time < 0.01, f"Decryption too slow: {avg_time * 1000:.2f}ms"


# Run tests if executed directly
if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])