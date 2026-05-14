"""
Integration test: Database + Encryption + KDF working together
Tests the complete flow of storing and retrieving encrypted passwords
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.database.db_manager import DatabaseManager
from src.security.encryption import EncryptionEngine
from src.security.kdf import KeyDerivationFunction


@pytest.fixture
def setup_system():
    """Fixture to set up complete system"""
    # Create in-memory database
    db = DatabaseManager(':memory:')
    db.connect()
    db.create_tables()

    # Create encryption engine
    encryption = EncryptionEngine()

    # Create KDF
    kdf = KeyDerivationFunction()

    yield db, encryption, kdf

    db.disconnect()


class TestCompleteFlow:
    """Test complete password manager flow"""

    def test_account_creation_and_login(self, setup_system):
        """Test creating account and logging in"""
        db, encryption, kdf = setup_system

        # User creates account
        master_password = "MyMasterPassword123!"

        # Hash password for storage
        password_hash, salt = kdf.hash_password(master_password)

        # Store in database
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            (password_hash, salt)
        )

        # Verify account created
        user = db.fetch_one("SELECT * FROM users WHERE user_id = ?", (1,))
        assert user is not None
        assert user['master_password_hash'] == password_hash
        assert user['salt'] == salt

        # User logs in
        login_attempt = "MyMasterPassword123!"

        # Retrieve from database
        stored_user = db.fetch_one("SELECT * FROM users WHERE user_id = ?", (1,))

        # Verify password
        is_valid = kdf.verify_password(
            login_attempt,
            stored_user['master_password_hash'],
            stored_user['salt']
        )

        assert is_valid is True

        # Derive encryption key
        encryption_key = kdf.derive_key(login_attempt, stored_user['salt'])
        encryption.set_key(encryption_key)

        assert encryption.is_key_set() is True

    def test_store_and_retrieve_encrypted_password(self, setup_system):
        """Test complete flow: create account → login → store password → retrieve password"""
        db, encryption, kdf = setup_system

        # === ACCOUNT CREATION ===
        master_password = "SecureMaster123!"
        password_hash, salt = kdf.hash_password(master_password)

        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            (password_hash, salt)
        )

        # === LOGIN ===
        user = db.fetch_one("SELECT * FROM users WHERE user_id = ?", (1,))
        is_valid = kdf.verify_password(master_password, user['master_password_hash'], user['salt'])
        assert is_valid is True

        # Derive encryption key from master password
        encryption_key = kdf.derive_key(master_password, user['salt'])
        encryption.set_key(encryption_key)

        # === STORE ENCRYPTED PASSWORD ===
        # User adds their Facebook password
        facebook_password = "MyFacebookPassword123"
        facebook_username = "john.doe@email.com"
        facebook_url = "https://facebook.com"

        # Encrypt all fields
        encrypted_password = encryption.encrypt(facebook_password)
        encrypted_username = encryption.encrypt(facebook_username)
        encrypted_url = encryption.encrypt(facebook_url)

        # Store in database
        db.execute_query(
            """INSERT INTO passwords 
               (user_id, encrypted_password, encrypted_username, encrypted_url, strength_score)
               VALUES (?, ?, ?, ?, ?)""",
            (1, encrypted_password, encrypted_username, encrypted_url, 85)
        )

        # === RETRIEVE AND DECRYPT PASSWORD ===
        # User wants to see their Facebook password
        result = db.fetch_one("SELECT * FROM passwords WHERE password_id = ?", (1,))

        # Decrypt fields
        decrypted_password = encryption.decrypt(result['encrypted_password'])
        decrypted_username = encryption.decrypt(result['encrypted_username'])
        decrypted_url = encryption.decrypt(result['encrypted_url'])

        # Verify decryption worked
        assert decrypted_password == facebook_password
        assert decrypted_username == facebook_username
        assert decrypted_url == facebook_url

    def test_multiple_passwords(self, setup_system):
        """Test storing and retrieving multiple encrypted passwords"""
        db, encryption, kdf = setup_system

        # Setup account
        master_password = "Master123!"
        password_hash, salt = kdf.hash_password(master_password)
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            (password_hash, salt)
        )

        # Login
        user = db.fetch_one("SELECT * FROM users WHERE user_id = ?", (1,))
        encryption_key = kdf.derive_key(master_password, user['salt'])
        encryption.set_key(encryption_key)

        # Store multiple passwords
        passwords = [
            ("Facebook", "facebook_pass_123", "john@email.com"),
            ("Gmail", "gmail_secure_456", "john.doe@gmail.com"),
            ("Amazon", "amazon_shop_789", "johndoe"),
            ("Netflix", "netflix_watch_000", "john.doe@email.com")
        ]

        for title, password, username in passwords:
            encrypted_pass = encryption.encrypt(password)
            encrypted_user = encryption.encrypt(username)
            encrypted_url = encryption.encrypt(f"https://{title.lower()}.com")

            db.execute_query(
                """INSERT INTO passwords 
                   (user_id, encrypted_password, encrypted_username, encrypted_url)
                   VALUES (?, ?, ?, ?)""",
                (1, encrypted_pass, encrypted_user, encrypted_url)
            )

        # Retrieve all passwords
        all_passwords = db.fetch_all("SELECT * FROM passwords WHERE user_id = ?", (1,))

        assert len(all_passwords) == 4

        # Decrypt and verify each
        for i, (title, password, username) in enumerate(passwords):
            encrypted_data = all_passwords[i]
            decrypted_pass = encryption.decrypt(encrypted_data['encrypted_password'])
            decrypted_user = encryption.decrypt(encrypted_data['encrypted_username'])

            assert decrypted_pass == password
            assert decrypted_user == username

    def test_wrong_master_password_cannot_decrypt(self, setup_system):
        """Test that wrong master password produces wrong encryption key"""
        db, encryption, kdf = setup_system

        # Create account with correct password
        correct_password = "CorrectPassword123"
        password_hash, salt = kdf.hash_password(correct_password)
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            (password_hash, salt)
        )

        # Login with correct password and store encrypted data
        user = db.fetch_one("SELECT * FROM users WHERE user_id = ?", (1,))
        correct_key = kdf.derive_key(correct_password, user['salt'])
        encryption.set_key(correct_key)

        secret_message = "SuperSecretPassword"
        encrypted = encryption.encrypt(secret_message)

        db.execute_query(
            "INSERT INTO passwords (user_id, encrypted_password) VALUES (?, ?)",
            (1, encrypted)
        )

        # Now try to decrypt with wrong password
        wrong_password = "WrongPassword123"
        wrong_key = kdf.derive_key(wrong_password, user['salt'])

        # Set wrong key
        encryption.clear_key()
        encryption.set_key(wrong_key)

        # Try to decrypt
        result = db.fetch_one("SELECT * FROM passwords WHERE password_id = ?", (1,))

        from src.security.encryption import DecryptionError
        with pytest.raises(DecryptionError):
            encryption.decrypt(result['encrypted_password'])

    def test_session_workflow(self, setup_system):
        """Test typical user session workflow"""
        db, encryption, kdf = setup_system

        # === SESSION 1: Account Creation ===
        print("\n=== Session 1: Account Creation ===")

        master_password = "UserMasterPass123!"
        password_hash, salt = kdf.hash_password(master_password)

        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            (password_hash, salt)
        )

        user = db.fetch_one("SELECT * FROM users WHERE user_id = ?", (1,))
        encryption_key = kdf.derive_key(master_password, user['salt'])
        encryption.set_key(encryption_key)

        # User adds some passwords
        passwords_to_add = [
            ("Gmail", "gmail_pass_123"),
            ("Twitter", "twitter_pass_456")
        ]

        for title, password in passwords_to_add:
            encrypted = encryption.encrypt(password)
            db.execute_query(
                "INSERT INTO passwords (user_id, encrypted_password) VALUES (?, ?)",
                (1, encrypted)
            )

        # User logs out (clear key)
        encryption.clear_key()
        assert encryption.is_key_set() is False

        # === SESSION 2: User Logs Back In ===
        print("\n=== Session 2: Login ===")

        # User enters master password
        login_password = "UserMasterPass123!"

        # Fetch user data
        user = db.fetch_one("SELECT * FROM users WHERE user_id = ?", (1,))

        # Verify password
        is_valid = kdf.verify_password(login_password, user['master_password_hash'], user['salt'])
        assert is_valid is True

        # Derive key again
        encryption_key = kdf.derive_key(login_password, user['salt'])
        encryption.set_key(encryption_key)

        # User can access their passwords
        all_passwords = db.fetch_all("SELECT * FROM passwords WHERE user_id = ?", (1,))

        for i, (title, original_pass) in enumerate(passwords_to_add):
            encrypted_data = all_passwords[i]
            decrypted = encryption.decrypt(encrypted_data['encrypted_password'])
            assert decrypted == original_pass

        # User adds another password
        new_password = "NewPassword789"
        encrypted_new = encryption.encrypt(new_password)
        db.execute_query(
            "INSERT INTO passwords (user_id, encrypted_password) VALUES (?, ?)",
            (1, encrypted_new)
        )

        # Verify it's stored
        count = db.get_table_count('passwords')
        assert count == 3

        # User logs out again
        encryption.clear_key()

    def test_data_persists_across_sessions(self, setup_system):
        """Test that encrypted data persists even after clearing key"""
        db, encryption, kdf = setup_system

        # Session 1: Create and store
        master_password = "TestMaster123"
        password_hash, salt = kdf.hash_password(master_password)
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            (password_hash, salt)
        )

        user = db.fetch_one("SELECT * FROM users WHERE user_id = ?", (1,))
        key = kdf.derive_key(master_password, user['salt'])
        encryption.set_key(key)

        original_password = "PersistentPassword123"
        encrypted = encryption.encrypt(original_password)
        db.execute_query(
            "INSERT INTO passwords (user_id, encrypted_password) VALUES (?, ?)",
            (1, encrypted)
        )

        # Clear key (simulate logout/close app)
        encryption.clear_key()

        # Verify encrypted data still in database
        result = db.fetch_one("SELECT * FROM passwords WHERE password_id = ?", (1,))
        assert result is not None
        assert result['encrypted_password'] == encrypted

        # Session 2: Login and decrypt
        key2 = kdf.derive_key(master_password, user['salt'])
        encryption.set_key(key2)

        # Should be able to decrypt
        decrypted = encryption.decrypt(result['encrypted_password'])
        assert decrypted == original_password


class TestSecurityScenarios:
    """Test security-related scenarios"""

    def test_cannot_decrypt_without_key(self, setup_system):
        """Test that data cannot be decrypted without key"""
        db, encryption, kdf = setup_system

        # Create and encrypt
        key = kdf.derive_key("password", kdf.generate_salt())
        encryption.set_key(key)

        encrypted = encryption.encrypt("secret")

        # Clear key
        encryption.clear_key()

        # Try to decrypt without key
        from src.security.encryption import DecryptionError
        with pytest.raises(DecryptionError, match="key not set"):
            encryption.decrypt(encrypted)

    def test_different_users_different_keys(self, setup_system):
        """Test that different users have different encryption keys"""
        db, encryption, kdf = setup_system

        # User 1
        pass1 = "User1Password"
        hash1, salt1 = kdf.hash_password(pass1)
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            (hash1, salt1)
        )

        # User 2
        pass2 = "User2Password"
        hash2, salt2 = kdf.hash_password(pass2)
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            (hash2, salt2)
        )

        # Derive keys
        key1 = kdf.derive_key(pass1, salt1)
        key2 = kdf.derive_key(pass2, salt2)

        # Keys should be different
        assert key1 != key2

        # User 1 encrypts data with their key
        encryption.set_key(key1)
        user1_secret = "User1Secret"
        encrypted1 = encryption.encrypt(user1_secret)

        # User 2 cannot decrypt with their key
        encryption.set_key(key2)

        from src.security.encryption import DecryptionError
        with pytest.raises(DecryptionError):
            encryption.decrypt(encrypted1)


# Run tests if executed directly
if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short']) 