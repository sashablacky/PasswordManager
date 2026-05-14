"""
Unit tests for Password Manager
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database.db_manager import DatabaseManager
from security.encryption import EncryptionEngine
from security.kdf import KeyDerivationFunction
from managers.password_manager import PasswordManager, PasswordManagerError


@pytest.fixture
def setup():
    """Fixture to set up test environment"""
    db = DatabaseManager(':memory:')
    db.connect()
    db.create_tables()

    encryption = EncryptionEngine()
    kdf = KeyDerivationFunction()
    pm = PasswordManager(db, encryption)

    # Create user and set encryption key
    master_password = "TestMaster123!"
    password_hash, salt = kdf.hash_password(master_password)
    db.execute_query(
        "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
        (password_hash, salt)
    )

    key = kdf.derive_key(master_password, salt)
    encryption.set_key(key)

    user_id = 1

    yield db, encryption, pm, user_id

    db.disconnect()


class TestAddPassword:
    """Test adding passwords"""

    def test_add_password_basic(self, setup):
        """Test basic password addition"""
        db, encryption, pm, user_id = setup

        pwd_id = pm.add_password(
            user_id, "Facebook", "john@email.com", "FBPass123!",
            "https://facebook.com", "My personal account"
        )

        assert pwd_id > 0

        # Verify in database
        result = db.fetch_one("SELECT * FROM passwords WHERE password_id = ?", (pwd_id,))
        assert result is not None

    def test_add_password_minimal(self, setup):
        """Test adding password with minimal info"""
        db, encryption, pm, user_id = setup

        pwd_id = pm.add_password(user_id, "Test", "", "password123!")

        assert pwd_id > 0

    def test_add_password_no_title(self, setup):
        """Test adding password without title"""
        db, encryption, pm, user_id = setup

        with pytest.raises(PasswordManagerError, match="Title is required"):
            pm.add_password(user_id, "", "user", "pass123!")

    def test_add_password_no_password(self, setup):
        """Test adding password without password"""
        db, encryption, pm, user_id = setup

        with pytest.raises(PasswordManagerError, match="Password is required"):
            pm.add_password(user_id, "Test", "user", "")

    def test_add_password_without_encryption_key(self, setup):
        """Test adding password without encryption key set"""
        db, encryption, pm, user_id = setup

        encryption.clear_key()

        with pytest.raises(PasswordManagerError, match="Encryption key not set"):
            pm.add_password(user_id, "Test", "user", "pass123!")

    def test_add_password_calculates_strength(self, setup):
        """Test that password strength is calculated"""
        db, encryption, pm, user_id = setup

        pwd_id = pm.add_password(user_id, "Strong", "user", "StrongPass123!")

        result = db.fetch_one("SELECT strength_score FROM passwords WHERE password_id = ?", (pwd_id,))
        assert result['strength_score'] > 0


class TestGetPassword:
    """Test retrieving passwords"""

    def test_get_password_success(self, setup):
        """Test successful password retrieval"""
        db, encryption, pm, user_id = setup

        # Add password
        pwd_id = pm.add_password(user_id, "Test", "john", "TestPass123!", "https://test.com", "notes")

        # Get password
        pwd = pm.get_password(pwd_id, user_id)

        assert pwd.password_id == pwd_id
        assert pwd.username == "john"
        assert pwd.password == "TestPass123!"
        assert pwd.url == "https://test.com"
        assert pwd.notes == "notes"

    def test_get_password_not_found(self, setup):
        """Test getting non-existent password"""
        db, encryption, pm, user_id = setup

        with pytest.raises(PasswordManagerError, match="not found"):
            pm.get_password(9999, user_id)

    def test_get_password_wrong_user(self, setup):
        """Test getting password with wrong user ID"""
        db, encryption, pm, user_id = setup

        pwd_id = pm.add_password(user_id, "Test", "user", "pass123!")

        with pytest.raises(PasswordManagerError, match="not found"):
            pm.get_password(pwd_id, 999)  # Wrong user ID


class TestGetAllPasswords:
    """Test retrieving all passwords"""

    def test_get_all_passwords_empty(self, setup):
        """Test getting passwords when none exist"""
        db, encryption, pm, user_id = setup

        passwords = pm.get_all_passwords(user_id)

        assert len(passwords) == 0

    def test_get_all_passwords_multiple(self, setup):
        """Test getting multiple passwords"""
        db, encryption, pm, user_id = setup

        # Add multiple passwords
        pm.add_password(user_id, "Test1", "user1", "pass1!")
        pm.add_password(user_id, "Test2", "user2", "pass2!")
        pm.add_password(user_id, "Test3", "user3", "pass3!")

        passwords = pm.get_all_passwords(user_id)

        assert len(passwords) == 3


class TestUpdatePassword:
    """Test updating passwords"""

    def test_update_password_success(self, setup):
        """Test successful password update"""
        db, encryption, pm, user_id = setup

        pwd_id = pm.add_password(user_id, "Test", "olduser", "oldpass!", "", "")

        pm.update_password(pwd_id, user_id, username="newuser", password="newpass!")

        pwd = pm.get_password(pwd_id, user_id)
        assert pwd.username == "newuser"
        assert pwd.password == "newpass!"

    def test_update_password_partial(self, setup):
        """Test updating only some fields"""
        db, encryption, pm, user_id = setup

        pwd_id = pm.add_password(user_id, "Test", "user", "oldpass!", "oldurl", "oldnotes")

        # Update only password
        pm.update_password(pwd_id, user_id, password="newpass!")

        pwd = pm.get_password(pwd_id, user_id)
        assert pwd.password == "newpass!"
        assert pwd.username == "user"  # Unchanged
        assert pwd.url == "oldurl"  # Unchanged

    def test_update_password_not_found(self, setup):
        """Test updating non-existent password"""
        db, encryption, pm, user_id = setup

        with pytest.raises(PasswordManagerError, match="not found"):
            pm.update_password(9999, user_id, password="newpass!")


class TestDeletePassword:
    """Test deleting passwords"""

    def test_delete_password_success(self, setup):
        """Test successful password deletion"""
        db, encryption, pm, user_id = setup

        pwd_id = pm.add_password(user_id, "Test", "user", "pass123!")

        result = pm.delete_password(pwd_id, user_id)

        assert result is True

        # Verify deleted from database
        db_result = db.fetch_one("SELECT * FROM passwords WHERE password_id = ?", (pwd_id,))
        assert db_result is None

    def test_delete_password_not_found(self, setup):
        """Test deleting non-existent password"""
        db, encryption, pm, user_id = setup

        with pytest.raises(PasswordManagerError, match="not found"):
            pm.delete_password(9999, user_id)


class TestSearchPasswords:
    """Test password search"""

    def test_search_passwords_by_title(self, setup):
        """Test searching by title"""
        db, encryption, pm, user_id = setup

        pm.add_password(user_id, "Facebook", "user1", "pass1!", "https://facebook.com", "")
        pm.add_password(user_id, "Gmail", "user2", "pass2!", "https://gmail.com", "")
        pm.add_password(user_id, "Amazon", "user3", "pass3!", "https://amazon.com", "")

        results = pm.search_passwords(user_id, "gmail")

        assert len(results) == 1
        assert "gmail" in results[0].url.lower()

    def test_search_passwords_empty_query(self, setup):
        """Test search with empty query returns all"""
        db, encryption, pm, user_id = setup

        pm.add_password(user_id, "Test1", "user", "pass1!")
        pm.add_password(user_id, "Test2", "user", "pass2!")

        results = pm.search_passwords(user_id, "")

        assert len(results) == 2

    def test_search_passwords_no_results(self, setup):
        """Test search with no matching results"""
        db, encryption, pm, user_id = setup

        pm.add_password(user_id, "Test", "user", "pass123!")

        results = pm.search_passwords(user_id, "nonexistent")

        assert len(results) == 0


class TestFavorites:
    """Test favorite functionality"""

    def test_toggle_favorite(self, setup):
        """Test toggling favorite status"""
        db, encryption, pm, user_id = setup

        pwd_id = pm.add_password(user_id, "Test", "user", "pass123!")

        # Toggle on
        status = pm.toggle_favorite(pwd_id, user_id)
        assert status is True

        # Toggle off
        status = pm.toggle_favorite(pwd_id, user_id)
        assert status is False

    def test_get_favorites(self, setup):
        """Test getting favorite passwords"""
        db, encryption, pm, user_id = setup

        pwd1 = pm.add_password(user_id, "Test1", "user", "pass1!")
        pwd2 = pm.add_password(user_id, "Test2", "user", "pass2!")
        pwd3 = pm.add_password(user_id, "Test3", "user", "pass3!")

        # Mark first two as favorites
        pm.toggle_favorite(pwd1, user_id)
        pm.toggle_favorite(pwd2, user_id)

        favorites = pm.get_favorites(user_id)

        assert len(favorites) == 2


class TestPasswordStrength:
    """Test password strength calculation"""

    def test_strength_calculation(self, setup):
        """Test strength scores for various passwords"""
        db, encryption, pm, user_id = setup

        # Strong password
        strong_id = pm.add_password(user_id, "Strong", "user", "VeryStrong123!@#")
        strong_pwd = pm.get_password(strong_id, user_id)

        # Weak password
        weak_id = pm.add_password(user_id, "Weak", "user", "password")
        weak_pwd = pm.get_password(weak_id, user_id)

        assert strong_pwd.strength_score > weak_pwd.strength_score

    def test_get_weak_passwords(self, setup):
        """Test getting weak passwords"""
        db, encryption, pm, user_id = setup

        pm.add_password(user_id, "Strong", "user", "StrongPass123!")
        pm.add_password(user_id, "Weak", "user", "weak")

        weak = pm.get_weak_passwords(user_id, threshold=50)

        assert len(weak) >= 1


class TestStatistics:
    """Test password statistics"""

    def test_get_statistics(self, setup):
        """Test getting password statistics"""
        db, encryption, pm, user_id = setup

        pm.add_password(user_id, "Strong", "user", "VeryStrong123!@#")
        pm.add_password(user_id, "Weak", "user", "weak")
        pm.add_password(user_id, "Medium", "user", "Medium123")

        stats = pm.get_statistics(user_id)

        assert stats['total'] == 3
        assert 'weak' in stats
        assert 'strong' in stats
        assert 'average_strength' in stats

    def test_get_statistics_empty(self, setup):
        """Test statistics with no passwords"""
        db, encryption, pm, user_id = setup

        stats = pm.get_statistics(user_id)

        assert stats['total'] == 0
        assert stats['average_strength'] == 0


class TestLastUsed:
    """Test last used tracking"""

    def test_update_last_used(self, setup):
        """Test updating last used date"""
        db, encryption, pm, user_id = setup

        pwd_id = pm.add_password(user_id, "Test", "user", "pass123!")

        # Initially None
        pwd = pm.get_password(pwd_id, user_id)
        assert pwd.last_used_date is None

        # Update last used
        pm.update_last_used(pwd_id, user_id)

        # Should now have a date
        pwd = pm.get_password(pwd_id, user_id)
        assert pwd.last_used_date is not None


# Run tests if executed directly
if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])