"""
Unit tests for DatabaseManager
"""

import pytest
import sys
import os
from datetime import datetime

# Add parent directory to path so we can import from src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.database.db_manager import DatabaseManager


@pytest.fixture
def db():
    """Fixture to create a fresh in-memory database for each test"""
    database = DatabaseManager(':memory:')
    database.connect()
    database.create_tables()
    yield database
    database.disconnect()


class TestDatabaseCreation:
    """Test database creation and initialization"""

    def test_connection(self, db):
        """Test database connection"""
        assert db.connection is not None
        assert db.connection.row_factory is not None

    def test_all_tables_created(self, db):
        """Test that all required tables are created"""
        required_tables = ['users', 'passwords', 'categories', 'breach_checks', 'audit_log']

        for table in required_tables:
            assert db.table_exists(table), f"Table '{table}' was not created"

    def test_table_structure(self, db):
        """Test that tables have correct columns"""
        # Test users table structure
        result = db.fetch_all("PRAGMA table_info(users)")
        column_names = [col['name'] for col in result]

        expected_columns = ['user_id', 'master_password_hash', 'salt', 'kdf_iterations',
                          'created_date', 'last_login', 'settings_json']

        for col in expected_columns:
            assert col in column_names, f"Column '{col}' missing from users table"

    def test_integrity_check(self, db):
        """Test database integrity check"""
        assert db.verify_integrity() is True


class TestUsersTable:
    """Test operations on users table"""

    def test_insert_user(self, db):
        """Test inserting a user"""
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt, kdf_iterations) VALUES (?, ?, ?)",
            ('hash123', b'salt123', 3)
        )

        count = db.get_table_count('users')
        assert count == 1

    def test_fetch_user(self, db):
        """Test fetching a user"""
        # Insert user
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            ('test_hash', b'test_salt')
        )

        # Fetch user
        user = db.fetch_one("SELECT * FROM users WHERE user_id = ?", (1,))

        assert user is not None
        assert user['user_id'] == 1
        assert user['master_password_hash'] == 'test_hash'
        assert user['salt'] == b'test_salt'
        assert user['kdf_iterations'] == 3  # Default value

    def test_update_last_login(self, db):
        """Test updating last login timestamp"""
        # Insert user
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            ('hash', b'salt')
        )

        # Update last login
        now = datetime.now()
        db.execute_query(
            "UPDATE users SET last_login = ? WHERE user_id = ?",
            (now, 1)
        )

        # Verify update
        user = db.fetch_one("SELECT * FROM users WHERE user_id = ?", (1,))
        assert user['last_login'] is not None


class TestPasswordsTable:
    """Test operations on passwords table"""

    def test_insert_password(self, db):
        """Test inserting a password entry"""
        # First create a user
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            ('hash', b'salt')
        )

        # Insert password
        db.execute_query(
            """INSERT INTO passwords 
               (user_id, encrypted_password, encrypted_username, encrypted_url, strength_score) 
               VALUES (?, ?, ?, ?, ?)""",
            (1, b'encrypted_pass', b'encrypted_user', b'encrypted_url', 85)
        )

        count = db.get_table_count('passwords')
        assert count == 1

    def test_fetch_passwords_for_user(self, db):
        """Test fetching all passwords for a specific user"""
        # Create user
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            ('hash', b'salt')
        )

        # Insert multiple passwords
        for i in range(3):
            db.execute_query(
                "INSERT INTO passwords (user_id, encrypted_password) VALUES (?, ?)",
                (1, f'pass{i}'.encode())
            )

        # Fetch all passwords for user
        passwords = db.fetch_all("SELECT * FROM passwords WHERE user_id = ?", (1,))

        assert len(passwords) == 3

    def test_delete_password(self, db):
        """Test deleting a password"""
        # Create user and password
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            ('hash', b'salt')
        )
        db.execute_query(
            "INSERT INTO passwords (user_id, encrypted_password) VALUES (?, ?)",
            (1, b'test_pass')
        )

        # Delete password
        db.execute_query("DELETE FROM passwords WHERE password_id = ?", (1,))

        count = db.get_table_count('passwords')
        assert count == 0

    def test_update_password(self, db):
        """Test updating a password entry"""
        # Create user and password
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            ('hash', b'salt')
        )
        db.execute_query(
            "INSERT INTO passwords (user_id, encrypted_password, strength_score) VALUES (?, ?, ?)",
            (1, b'old_pass', 50)
        )

        # Update password
        db.execute_query(
            "UPDATE passwords SET encrypted_password = ?, strength_score = ? WHERE password_id = ?",
            (b'new_pass', 90, 1)
        )

        # Verify update
        password = db.fetch_one("SELECT * FROM passwords WHERE password_id = ?", (1,))
        assert password['encrypted_password'] == b'new_pass'
        assert password['strength_score'] == 90


class TestCategoriesTable:
    """Test operations on categories table"""

    def test_insert_category(self, db):
        """Test inserting a category"""
        # Create user
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            ('hash', b'salt')
        )

        # Insert category
        db.execute_query(
            "INSERT INTO categories (user_id, name, icon, color) VALUES (?, ?, ?, ?)",
            (1, 'Social Media', '📱', '#3498db')
        )

        count = db.get_table_count('categories')
        assert count == 1

    def test_fetch_categories(self, db):
        """Test fetching categories for a user"""
        # Create user
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            ('hash', b'salt')
        )

        # Insert categories
        categories = [
            ('Social Media', '📱'),
            ('Banking', '💳'),
            ('Email', '📧')
        ]

        for name, icon in categories:
            db.execute_query(
                "INSERT INTO categories (user_id, name, icon) VALUES (?, ?, ?)",
                (1, name, icon)
            )

        # Fetch all categories
        result = db.fetch_all("SELECT * FROM categories WHERE user_id = ?", (1,))

        assert len(result) == 3
        assert result[0]['name'] == 'Social Media'


class TestBreachChecksTable:
    """Test operations on breach_checks table"""

    def test_insert_breach_check(self, db):
        """Test inserting a breach check result"""
        # Create user and password
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            ('hash', b'salt')
        )
        db.execute_query(
            "INSERT INTO passwords (user_id, encrypted_password) VALUES (?, ?)",
            (1, b'test_pass')
        )

        # Insert breach check
        db.execute_query(
            "INSERT INTO breach_checks (password_id, breach_found, breach_count) VALUES (?, ?, ?)",
            (1, 1, 12543)
        )

        count = db.get_table_count('breach_checks')
        assert count == 1

    def test_fetch_breach_results(self, db):
        """Test fetching breach check results"""
        # Setup
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            ('hash', b'salt')
        )
        db.execute_query(
            "INSERT INTO passwords (user_id, encrypted_password) VALUES (?, ?)",
            (1, b'test_pass')
        )
        db.execute_query(
            "INSERT INTO breach_checks (password_id, breach_found, breach_count) VALUES (?, ?, ?)",
            (1, 1, 12543)
        )

        # Fetch
        result = db.fetch_one("SELECT * FROM breach_checks WHERE password_id = ?", (1,))

        assert result is not None
        assert result['breach_found'] == 1
        assert result['breach_count'] == 12543


class TestAuditLogTable:
    """Test operations on audit_log table"""

    def test_insert_audit_log(self, db):
        """Test inserting an audit log entry"""
        # Create user
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            ('hash', b'salt')
        )

        # Insert log entry
        db.execute_query(
            "INSERT INTO audit_log (user_id, action_type, details_json) VALUES (?, ?, ?)",
            (1, 'LOGIN_SUCCESS', '{"ip": "192.168.1.1"}')
        )

        count = db.get_table_count('audit_log')
        assert count == 1

    def test_fetch_audit_logs(self, db):
        """Test fetching audit logs for a user"""
        # Create user
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            ('hash', b'salt')
        )

        # Insert multiple log entries
        actions = ['LOGIN_SUCCESS', 'PASSWORD_ADDED', 'PASSWORD_VIEWED']
        for action in actions:
            db.execute_query(
                "INSERT INTO audit_log (user_id, action_type) VALUES (?, ?)",
                (1, action)
            )

        # Fetch all logs
        logs = db.fetch_all("SELECT * FROM audit_log WHERE user_id = ?", (1,))

        assert len(logs) == 3


class TestTransactions:
    """Test transaction handling"""

    def test_commit_transaction(self, db):
        """Test committing a transaction"""
        db.begin_transaction()

        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            ('hash', b'salt')
        )

        db.commit()

        count = db.get_table_count('users')
        assert count == 1

    def test_rollback_transaction(self, db):
        """Test rolling back a transaction"""
        # Note: execute_query auto-commits, so we need to use cursor directly
        db.connection.execute("BEGIN")

        cursor = db.connection.cursor()
        cursor.execute(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            ('hash', b'salt')
        )

        db.rollback()

        count = db.get_table_count('users')
        assert count == 0


class TestDatabaseInfo:
    """Test database information retrieval"""

    def test_get_database_info(self, db):
        """Test getting database information"""
        info = db.get_database_info()

        assert 'path' in info
        assert 'tables' in info
        assert 'total_size_kb' in info

        # Should have all 5 main tables (might have sqlite_sequence for autoincrement)
        assert len(info['tables']) >= 5

        # Verify our main tables exist
        assert 'users' in info['tables']
        assert 'passwords' in info['tables']
        assert 'categories' in info['tables']
        assert 'breach_checks' in info['tables']
        assert 'audit_log' in info['tables']

    def test_table_exists(self, db):
        """Test checking if table exists"""
        assert db.table_exists('users') is True
        assert db.table_exists('nonexistent_table') is False


class TestForeignKeys:
    """Test foreign key constraints"""

    def test_cascade_delete_user(self, db):
        """Test that deleting user cascades to passwords"""
        # Create user
        db.execute_query(
            "INSERT INTO users (master_password_hash, salt) VALUES (?, ?)",
            ('hash', b'salt')
        )

        # Create passwords
        for i in range(3):
            db.execute_query(
                "INSERT INTO passwords (user_id, encrypted_password) VALUES (?, ?)",
                (1, f'pass{i}'.encode())
            )

        # Verify passwords exist
        assert db.get_table_count('passwords') == 3

        # Enable foreign keys (SQLite has them off by default in some cases)
        db.execute_query("PRAGMA foreign_keys = ON")

        # Delete user
        db.execute_query("DELETE FROM users WHERE user_id = ?", (1,))

        # Passwords should be automatically deleted due to CASCADE
        assert db.get_table_count('passwords') == 0


# Run tests if executed directly
if __name__ == '__main__':
    pytest.main([__file__, '-v'])