import sqlite3
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
import json
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseManager:

    def __init__(self, db_path: str = 'password_vault.db'):
        self.db_path = db_path
        self.connection: Optional[sqlite3.Connection] = None
        logger.info(f"DatabaseManager initialized with path: {db_path}")

    def connect(self) -> None:
        try:
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory = sqlite3.Row  # Return rows as dictionaries
            logger.info(f"Successfully connected to database: {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    def disconnect(self) -> None:
        if self.connection:
            self.connection.close()
            logger.info("Database connection closed")
            self.connection = None

    def create_tables(self) -> None:
        try:
            cursor = self.connection.cursor()

            # Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    master_password_hash TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    kdf_iterations INTEGER NOT NULL DEFAULT 3,
                    created_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    settings_json TEXT DEFAULT '{}'
                )
            """)
            logger.info("Users table created")

            # Passwords table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    password_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    encrypted_password BLOB NOT NULL,
                    encrypted_username BLOB,
                    encrypted_url BLOB,
                    encrypted_notes BLOB,
                    category_id INTEGER,
                    strength_score INTEGER DEFAULT 0,
                    created_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    modified_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_used_date TIMESTAMP,
                    is_favorite INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                    FOREIGN KEY (category_id) REFERENCES categories(category_id) ON DELETE SET NULL
                )
            """)
            logger.info("Passwords table created")

            # Categories table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS categories (
                    category_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    icon TEXT DEFAULT '📁',
                    color TEXT DEFAULT '#667eea',
                    sort_order INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
                )
            """)
            logger.info("Categories table created")

            # Breach checks table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS breach_checks (
                    check_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    password_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    check_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    breach_found INTEGER DEFAULT 0,
                    breach_count INTEGER DEFAULT 0,
                    risk_level TEXT DEFAULT 'low',
                    breach_details TEXT,
                    recommendations TEXT,
                    FOREIGN KEY (password_id) REFERENCES passwords(password_id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
                )
            """)
            logger.info("Breach checks table created")

            # Audit log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    action_type TEXT NOT NULL,
                    details_json TEXT DEFAULT '{}',
                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
                )
            """)
            logger.info("Audit log table created")

            # Create indexes for better performance
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_passwords_user_id 
                ON passwords(user_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_passwords_category_id 
                ON passwords(category_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_log_user_id 
                ON audit_log(user_id)
            """)

            logger.info("Database indexes created")

            self.connection.commit()
            logger.info("All tables created successfully")

        except sqlite3.Error as e:
            logger.error(f"Error creating tables: {e}")
            raise

    def execute_query(self, query: str, params: Tuple = ()) -> sqlite3.Cursor:
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            self.connection.commit()
            return cursor
        except sqlite3.Error as e:
            logger.error(f"Query execution failed: {e}")
            logger.error(f"Query: {query}")
            logger.error(f"Params: {params}")
            raise

    def fetch_one(self, query: str, params: Tuple = ()) -> Optional[Dict[str, Any]]:
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            row = cursor.fetchone()

            if row:
                return dict(row)
            return None

        except sqlite3.Error as e:
            logger.error(f"Fetch one failed: {e}")
            raise

    def fetch_all(self, query: str, params: Tuple = ()) -> List[Dict[str, Any]]:
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()

            return [dict(row) for row in rows]

        except sqlite3.Error as e:
            logger.error(f"✗ Fetch all failed: {e}")
            raise

    def begin_transaction(self) -> None:
        self.connection.execute("BEGIN")
        logger.debug("Transaction started")

    def commit(self) -> None:
        self.connection.commit()
        logger.debug("Transaction committed")

    def rollback(self) -> None:
        self.connection.rollback()
        logger.warning("Transaction rolled back")

    def verify_integrity(self) -> bool:
        try:
            cursor = self.connection.cursor()
            cursor.execute("PRAGMA integrity_check")
            result = cursor.fetchone()

            if result and result[0] == 'ok':
                logger.info("✓ Database integrity check passed")
                return True
            else:
                logger.error(f"✗ Database integrity check failed: {result}")
                return False

        except sqlite3.Error as e:
            logger.error(f"✗ Integrity check error: {e}")
            return False

    def get_table_count(self, table_name: str) -> int:
        try:
            ALLOWED_TABLES = {'users', 'passwords', 'categories', 'breach_checks', 'audit_log'}
            if table_name not in ALLOWED_TABLES:
                raise ValueError(f"Unknown table: {table_name}")
            result = self.fetch_one(f"SELECT COUNT(*) as count FROM {table_name}")
            return result['count'] if result else 0
        except sqlite3.Error as e:
            logger.error(f"✗ Error getting table count: {e}")
            return 0

    def table_exists(self, table_name: str) -> bool:
        result = self.fetch_one(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,)
        )
        return result is not None

    def get_database_info(self) -> Dict[str, Any]:
        info = {
            'path': self.db_path,
            'tables': {},
            'total_size_kb': 0
        }

        # Get all tables
        tables = self.fetch_all(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )

        # Get row count for each table
        for table in tables:
            table_name = table['name']
            count = self.get_table_count(table_name)
            info['tables'][table_name] = count

        # Get database file size (if not in-memory)
        if self.db_path != ':memory:':
            import os
            if os.path.exists(self.db_path):
                info['total_size_kb'] = os.path.getsize(self.db_path) // 1024

        return info

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.rollback()
        self.disconnect()

    def __del__(self):
        if self.connection:
            self.disconnect()