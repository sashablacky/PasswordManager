"""
Unit tests for Authentication Manager
"""

import pytest
import sys
import os
import time

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.database.db_manager import DatabaseManager
from src.security.encryption import EncryptionEngine
from src.managers.auth_manager import AuthenticationManager, AuthenticationError


@pytest.fixture
def setup():
    """Fixture to set up test environment"""
    db = DatabaseManager(':memory:')
    db.connect()
    db.create_tables()

    encryption = EncryptionEngine()
    auth = AuthenticationManager(db, encryption)

    yield db, encryption, auth

    db.disconnect()


class TestAccountCreation:
    """Test account creation functionality"""

    def test_create_account_success(self, setup):
        """Test successful account creation"""
        db, encryption, auth = setup

        success, msg = auth.create_account("ValidPass123!")

        assert success is True
        assert "successfully" in msg.lower()

        # Verify user in database
        user = db.fetch_one("SELECT * FROM users")
        assert user is not None
        assert user['master_password_hash'] is not None
        assert user['salt'] is not None

    def test_create_account_weak_password(self, setup):
        """Test account creation with weak password"""
        db, encryption, auth = setup

        weak_passwords = [
            "short",  # Too short
            "nouppercase123!",  # No uppercase
            "NOLOWERCASE123!",  # No lowercase
            "NoNumbers!",  # No numbers
            "NoSpecialChar123"  # No special chars
        ]

        for password in weak_passwords:
            success, msg = auth.create_account(password)
            assert success is False

    def test_create_account_already_exists(self, setup):
        """Test creating second account (should fail)"""
        db, encryption, auth = setup

        # Create first account
        auth.create_account("FirstAccount123!")

        # Try to create second account
        success, msg = auth.create_account("SecondAccount123!")

        assert success is False
        assert "already exists" in msg.lower()

    def test_create_account_creates_categories(self, setup):
        """Test that default categories are created"""
        db, encryption, auth = setup

        auth.create_account("TestPass123!")

        categories = db.fetch_all("SELECT * FROM categories")

        assert len(categories) > 0
        assert any("Social Media" in cat['name'] for cat in categories)
        assert any("Banking" in cat['name'] for cat in categories)

    def test_create_account_logs_action(self, setup):
        """Test that account creation is logged"""
        db, encryption, auth = setup

        auth.create_account("TestPass123!")

        logs = db.fetch_all("SELECT * FROM audit_log WHERE action_type = 'ACCOUNT_CREATED'")

        assert len(logs) == 1


class TestAuthentication:
    """Test authentication functionality"""

    def test_authenticate_success(self, setup):
        """Test successful authentication"""
        db, encryption, auth = setup

        password = "TestPass123!"
        auth.create_account(password)

        success, msg = auth.authenticate(password)

        assert success is True
        assert auth.is_logged_in() is True
        assert auth.get_current_user_id() is not None

    def test_authenticate_wrong_password(self, setup):
        """Test authentication with wrong password"""
        db, encryption, auth = setup

        auth.create_account("CorrectPass123!")

        success, msg = auth.authenticate("WrongPass123!")

        assert success is False
        assert auth.is_logged_in() is False

    def test_authenticate_no_account(self, setup):
        """Test authentication when no account exists"""
        db, encryption, auth = setup

        success, msg = auth.authenticate("AnyPass123!")

        assert success is False
        assert "no account" in msg.lower()

    def test_authenticate_sets_encryption_key(self, setup):
        """Test that authentication sets encryption key"""
        db, encryption, auth = setup

        password = "TestPass123!"
        auth.create_account(password)

        # Initially no key set
        assert encryption.is_key_set() is False

        # After authentication, key should be set
        auth.authenticate(password)
        assert encryption.is_key_set() is True

    def test_authenticate_updates_last_login(self, setup):
        """Test that last_login is updated"""
        db, encryption, auth = setup

        password = "TestPass123!"
        auth.create_account(password)

        # Get initial last_login
        user1 = db.fetch_one("SELECT * FROM users")
        initial_login = user1['last_login']

        # Wait a moment and login again
        time.sleep(0.1)
        auth.authenticate(password)

        # Check last_login updated
        user2 = db.fetch_one("SELECT * FROM users")
        assert user2['last_login'] != initial_login


class TestFailedAttempts:
    """Test failed login attempt tracking"""

    def test_failed_attempts_counter(self, setup):
        """Test that failed attempts are counted"""
        db, encryption, auth = setup

        auth.create_account("CorrectPass123!")

        # Make failed attempts
        for i in range(3):
            success, msg = auth.authenticate("WrongPass123!")
            assert success is False
            assert f"{5 - i - 1} attempts remaining" in msg

    def test_account_lockout(self, setup):
        """Test account locks after max attempts"""
        db, encryption, auth = setup

        auth.create_account("CorrectPass123!")

        # Make 5 failed attempts
        for i in range(5):
            auth.authenticate("WrongPass123!")

        # Next attempt should indicate lockout
        success, msg = auth.authenticate("CorrectPass123!")

        assert success is False
        assert "locked" in msg.lower()

    def test_failed_attempts_reset_on_success(self, setup):
        """Test that failed attempts reset after successful login"""
        db, encryption, auth = setup

        password = "CorrectPass123!"
        auth.create_account(password)

        # Make some failed attempts
        auth.authenticate("WrongPass1!")
        auth.authenticate("WrongPass2!")

        # Successful login
        auth.authenticate(password)
        auth.logout()

        # Should have all 5 attempts again
        for i in range(4):
            success, msg = auth.authenticate("WrongPass!")
            assert "5 attempts remaining" not in msg or i == 0


class TestLogout:
    """Test logout functionality"""

    def test_logout_clears_session(self, setup):
        """Test logout clears session"""
        db, encryption, auth = setup

        password = "TestPass123!"
        auth.create_account(password)
        auth.authenticate(password)

        assert auth.is_logged_in() is True

        auth.logout()

        assert auth.is_logged_in() is False
        assert auth.get_current_user_id() is None

    def test_logout_clears_encryption_key(self, setup):
        """Test logout clears encryption key"""
        db, encryption, auth = setup

        password = "TestPass123!"
        auth.create_account(password)
        auth.authenticate(password)

        assert encryption.is_key_set() is True

        auth.logout()

        assert encryption.is_key_set() is False

    def test_logout_logs_action(self, setup):
        """Test logout is logged"""
        db, encryption, auth = setup

        password = "TestPass123!"
        auth.create_account(password)
        auth.authenticate(password)
        auth.logout()

        logs = db.fetch_all("SELECT * FROM audit_log WHERE action_type = 'LOGOUT'")

        assert len(logs) == 1


class TestPasswordChange:
    """Test password change functionality"""

    def test_change_password_success(self, setup):
        """Test successful password change"""
        db, encryption, auth = setup

        old_pass = "OldPass123!"
        new_pass = "NewPass456!"

        auth.create_account(old_pass)
        auth.authenticate(old_pass)

        success, msg = auth.change_master_password(old_pass, new_pass)

        assert success is True

        # Verify new password works
        auth.logout()
        success, msg = auth.authenticate(new_pass)
        assert success is True

    def test_change_password_wrong_old(self, setup):
        """Test password change with wrong old password"""
        db, encryption, auth = setup

        auth.create_account("CorrectPass123!")
        auth.authenticate("CorrectPass123!")

        success, msg = auth.change_master_password("WrongPass123!", "NewPass456!")

        assert success is False
        assert "incorrect" in msg.lower()

    def test_change_password_weak_new(self, setup):
        """Test password change with weak new password"""
        db, encryption, auth = setup

        old_pass = "OldPass123!"
        auth.create_account(old_pass)
        auth.authenticate(old_pass)

        success, msg = auth.change_master_password(old_pass, "weak")

        assert success is False

    def test_change_password_re_encrypts_data(self, setup):
        """Test that password change re-encrypts existing passwords"""
        db, encryption, auth = setup

        old_pass = "OldPass123!"
        new_pass = "NewPass456!"

        # Create account and add password
        auth.create_account(old_pass)
        auth.authenticate(old_pass)

        # Store encrypted password
        test_password = "MySecretPassword"
        encrypted = encryption.encrypt(test_password)
        db.execute_query(
            "INSERT INTO passwords (user_id, encrypted_password) VALUES (?, ?)",
            (auth.get_current_user_id(), encrypted)
        )

        # Change password
        auth.change_master_password(old_pass, new_pass)

        # Logout and login with new password
        auth.logout()
        auth.authenticate(new_pass)

        # Should be able to decrypt with new key
        result = db.fetch_one("SELECT encrypted_password FROM passwords")
        decrypted = encryption.decrypt(result['encrypted_password'])

        assert decrypted == test_password


class TestPasswordStrengthValidation:
    """Test password strength validation"""

    def test_password_too_short(self, setup):
        """Test password too short"""
        db, encryption, auth = setup

        success, msg = auth.create_account("Short1!")

        assert success is False
        assert "at least 8 characters" in msg.lower()

    def test_password_no_uppercase(self, setup):
        """Test password without uppercase"""
        db, encryption, auth = setup

        success, msg = auth.create_account("nouppercase123!")

        assert success is False
        assert "uppercase" in msg.lower()

    def test_password_no_lowercase(self, setup):
        """Test password without lowercase"""
        db, encryption, auth = setup

        success, msg = auth.create_account("NOLOWERCASE123!")

        assert success is False
        assert "lowercase" in msg.lower()

    def test_password_no_number(self, setup):
        """Test password without number"""
        db, encryption, auth = setup

        success, msg = auth.create_account("NoNumbers!")

        assert success is False
        assert "number" in msg.lower()

    def test_password_no_special(self, setup):
        """Test password without special character"""
        db, encryption, auth = setup

        success, msg = auth.create_account("NoSpecial123")

        assert success is False
        assert "special character" in msg.lower()


class TestSessionManagement:
    """Test session management"""

    def test_is_logged_in(self, setup):
        """Test is_logged_in status"""
        db, encryption, auth = setup

        assert auth.is_logged_in() is False

        auth.create_account("TestPass123!")
        auth.authenticate("TestPass123!")

        assert auth.is_logged_in() is True

    def test_get_current_user_id(self, setup):
        """Test getting current user ID"""
        db, encryption, auth = setup

        assert auth.get_current_user_id() is None

        auth.create_account("TestPass123!")
        auth.authenticate("TestPass123!")

        user_id = auth.get_current_user_id()
        assert user_id is not None
        assert isinstance(user_id, int)


class TestAuditLogging:
    """Test audit logging"""

    def test_login_success_logged(self, setup):
        """Test successful login is logged"""
        db, encryption, auth = setup

        auth.create_account("TestPass123!")
        auth.authenticate("TestPass123!")

        logs = db.fetch_all("SELECT * FROM audit_log WHERE action_type = 'LOGIN_SUCCESS'")

        assert len(logs) == 1

    def test_login_failed_logged(self, setup):
        """Test failed login is logged"""
        db, encryption, auth = setup

        auth.create_account("TestPass123!")
        auth.authenticate("WrongPass123!")

        logs = db.fetch_all("SELECT * FROM audit_log WHERE action_type = 'LOGIN_FAILED'")

        assert len(logs) == 1

    def test_account_locked_logged(self, setup):
        """Test account lockout is logged"""
        db, encryption, auth = setup

        auth.create_account("TestPass123!")

        # Trigger lockout
        for _ in range(5):
            auth.authenticate("WrongPass!")

        logs = db.fetch_all("SELECT * FROM audit_log WHERE action_type = 'ACCOUNT_LOCKED'")

        assert len(logs) == 1

    def test_password_change_logged(self, setup):
        """Test password change is logged"""
        db, encryption, auth = setup

        auth.create_account("OldPass123!")
        auth.authenticate("OldPass123!")
        auth.change_master_password("OldPass123!", "NewPass456!")

        logs = db.fetch_all("SELECT * FROM audit_log WHERE action_type = 'PASSWORD_CHANGED'")

        assert len(logs) == 1


# Run tests if executed directly
if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short']) 