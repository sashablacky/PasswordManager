import logging
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Tuple

from database.db_manager import DatabaseManager
from security.encryption import EncryptionEngine
from security.kdf import KeyDerivationFunction

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Custom exception for authentication-related errors"""
    pass


class AuthenticationManager:

    # Security constants
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 5
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128

    def __init__(self, db_manager: DatabaseManager, encryption_engine: EncryptionEngine):
        self.db = db_manager
        self.encryption = encryption_engine
        self.kdf = KeyDerivationFunction()

        self._current_user_id: Optional[int] = None
        self._failed_attempts: dict = {}  # {user_id: count}
        self._lockout_until: dict = {}  # {user_id: datetime}

        logger.info("AuthenticationManager initialized")

    def create_account(self, master_password: str) -> Tuple[bool, str]:
        try:
            is_valid, message = self._validate_password_strength(master_password)
            if not is_valid:
                logger.warning(f"Account creation failed: {message}")
                return False, message

            existing_user = self.db.fetch_one("SELECT user_id FROM users LIMIT 1")
            if existing_user:
                logger.warning("Account creation failed: Account already exists")
                return False, "An account already exists. Only one account per database."

            password_hash, salt = self.kdf.hash_password(master_password)

            self.db.execute_query(
                """INSERT INTO users (master_password_hash, salt, kdf_iterations, created_date)
                   VALUES (?, ?, ?, ?)""",
                (password_hash, salt, self.kdf.TIME_COST, datetime.now())
            )

            user = self.db.fetch_one("SELECT user_id FROM users ORDER BY user_id DESC LIMIT 1")
            user_id = user['user_id']

            self._create_default_categories(user_id)

            self._log_action(user_id, "ACCOUNT_CREATED", {})

            logger.info(f"Account created successfully for user {user_id}")
            return True, "Account created successfully"

        except Exception as e:
            logger.error(f"Account creation failed: {e}")
            return False, f"Account creation failed: {str(e)}"

    def authenticate(self, master_password: str) -> Tuple[bool, str]:
        try:
            if len(master_password) > self.MAX_PASSWORD_LENGTH:
                logger.warning("Authentication rejected: password exceeds maximum length")
                return False, f"Password must not exceed {self.MAX_PASSWORD_LENGTH} characters."

            user = self.db.fetch_one("SELECT * FROM users LIMIT 1")

            if not user:
                logger.warning("Authentication failed: No account exists")
                return False, "No account found. Please create an account first."

            user_id = user['user_id']

            if self._is_locked_out(user_id):
                remaining = self._get_lockout_remaining(user_id)
                logger.warning(f"Authentication failed: Account locked (user {user_id})")
                return False, f"Account locked due to too many failed attempts. Try again in {remaining} seconds."

            is_valid = self.kdf.verify_password(
                master_password,
                user['master_password_hash'],
                user['salt']
            )

            if is_valid:
                self._reset_failed_attempts(user_id)

                encryption_key = self.kdf.derive_key(master_password, user['salt'])
                self.encryption.set_key(encryption_key)

                self.db.execute_query(
                    "UPDATE users SET last_login = ? WHERE user_id = ?",
                    (datetime.now(), user_id)
                )

                self._current_user_id = user_id

                self._log_action(user_id, "LOGIN_SUCCESS", {})

                logger.info(f"Authentication successful for user {user_id}")
                return True, "Login successful"

            else:
                self._increment_failed_attempts(user_id)

                if self._failed_attempts.get(user_id, 0) >= self.MAX_FAILED_ATTEMPTS:
                    self._lockout_until[user_id] = datetime.now() + timedelta(minutes=self.LOCKOUT_DURATION_MINUTES)

                    self._log_action(user_id, "ACCOUNT_LOCKED", {
                        "reason": "Too many failed login attempts"
                    })

                    logger.warning(f"Account locked due to failed attempts (user {user_id})")
                    return False, f"Too many failed attempts. Account locked for {self.LOCKOUT_DURATION_MINUTES} minutes."

                self._log_action(user_id, "LOGIN_FAILED", {
                    "attempts": self._failed_attempts.get(user_id, 0)
                })

                remaining_attempts = self.MAX_FAILED_ATTEMPTS - self._failed_attempts.get(user_id, 0)
                logger.warning(f"Authentication failed (user {user_id}). {remaining_attempts} attempts remaining")

                return False, f"Invalid password. {remaining_attempts} attempts remaining."

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False, f"Authentication error: {str(e)}"

    def logout(self) -> None:
        if self._current_user_id:
            self._log_action(self._current_user_id, "LOGOUT", {})
            logger.info(f"User {self._current_user_id} logged out")

        self._current_user_id = None
        self.encryption.clear_key()

    def change_master_password(self, old_password: str, new_password: str) -> Tuple[bool, str]:
        try:
            is_valid, message = self._validate_password_strength(new_password)
            if not is_valid:
                return False, message

            success, msg = self.authenticate(old_password)
            if not success:
                return False, "Current password is incorrect"

            user_id = self._current_user_id

            user = self.db.fetch_one("SELECT * FROM users WHERE user_id = ?", (user_id,))

            old_key = self.kdf.derive_key(old_password, user['salt'])

            new_hash, new_salt = self.kdf.hash_password(new_password)
            new_key = self.kdf.derive_key(new_password, new_salt)

            passwords = self.db.fetch_all(
                "SELECT password_id, encrypted_password, encrypted_username, encrypted_url, encrypted_notes FROM passwords WHERE user_id = ?",
                (user_id,)
            )

            self.encryption.set_key(old_key)

            self.db.begin_transaction()

            try:
                for pwd in passwords:
                    decrypted_password = self.encryption.decrypt(pwd['encrypted_password']) if pwd[
                        'encrypted_password'] else None
                    decrypted_username = self.encryption.decrypt(pwd['encrypted_username']) if pwd[
                        'encrypted_username'] else None
                    decrypted_url = self.encryption.decrypt(pwd['encrypted_url']) if pwd['encrypted_url'] else None
                    decrypted_notes = self.encryption.decrypt(pwd['encrypted_notes']) if pwd[
                        'encrypted_notes'] else None

                    self.encryption.set_key(new_key)

                    new_encrypted_password = self.encryption.encrypt(decrypted_password) if decrypted_password else None
                    new_encrypted_username = self.encryption.encrypt(decrypted_username) if decrypted_username else None
                    new_encrypted_url = self.encryption.encrypt(decrypted_url) if decrypted_url else None
                    new_encrypted_notes = self.encryption.encrypt(decrypted_notes) if decrypted_notes else None

                    self.db.execute_query(
                        """UPDATE passwords 
                           SET encrypted_password = ?, encrypted_username = ?, 
                               encrypted_url = ?, encrypted_notes = ?, modified_date = ?
                           WHERE password_id = ?""",
                        (new_encrypted_password, new_encrypted_username, new_encrypted_url,
                         new_encrypted_notes, datetime.now(), pwd['password_id'])
                    )

                    self.encryption.set_key(old_key)

                self.db.execute_query(
                    "UPDATE users SET master_password_hash = ?, salt = ? WHERE user_id = ?",
                    (new_hash, new_salt, user_id)
                )

                self.db.commit()

                self.encryption.set_key(new_key)

                self._log_action(user_id, "PASSWORD_CHANGED", {})

                logger.info(f"Master password changed for user {user_id}")
                return True, "Master password changed successfully"

            except Exception as e:
                self.db.rollback()
                raise e

        except Exception as e:
            logger.error(f"Password change failed: {e}")
            return False, f"Password change failed: {str(e)}"

    def is_logged_in(self) -> bool:
        return self._current_user_id is not None and self.encryption.is_key_set()

    def get_current_user_id(self) -> Optional[int]:
        return self._current_user_id

    def _validate_password_strength(self, password: str) -> Tuple[bool, str]:
        if len(password) > self.MAX_PASSWORD_LENGTH:
            return False, f"Password must not exceed {self.MAX_PASSWORD_LENGTH} characters"

        if len(password) < self.MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {self.MIN_PASSWORD_LENGTH} characters"

        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"

        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"

        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number"

        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            return False, "Password must contain at least one special character"

        return True, "Password meets security requirements"

    def _is_locked_out(self, user_id: int) -> bool:
        if user_id not in self._lockout_until:
            return False

        lockout_time = self._lockout_until[user_id]
        if datetime.now() >= lockout_time:
            # Lockout expired
            del self._lockout_until[user_id]
            self._reset_failed_attempts(user_id)
            return False

        return True

    def _get_lockout_remaining(self, user_id: int) -> int:
        if user_id not in self._lockout_until:
            return 0

        remaining = (self._lockout_until[user_id] - datetime.now()).total_seconds()
        return max(0, int(remaining))

    def _increment_failed_attempts(self, user_id: int) -> None:
        self._failed_attempts[user_id] = self._failed_attempts.get(user_id, 0) + 1

    def _reset_failed_attempts(self, user_id: int) -> None:
        if user_id in self._failed_attempts:
            del self._failed_attempts[user_id]
        if user_id in self._lockout_until:
            del self._lockout_until[user_id]

    def _create_default_categories(self, user_id: int) -> None:
        default_categories = [
            ("Social Media", "📱", "#3498db"),
            ("Banking", "💳", "#e74c3c"),
            ("Email", "📧", "#2ecc71"),
            ("Shopping", "🛒", "#f39c12"),
            ("Work", "💼", "#9b59b6"),
            ("Entertainment", "🎮", "#1abc9c")
        ]

        for i, (name, icon, color) in enumerate(default_categories):
            self.db.execute_query(
                """INSERT INTO categories (user_id, name, icon, color, sort_order)
                   VALUES (?, ?, ?, ?, ?)""",
                (user_id, name, icon, color, i)
            )

        logger.info(f"Created {len(default_categories)} default categories for user {user_id}")

    def _log_action(self, user_id: int, action_type: str, details: dict) -> None:
        import json

        self.db.execute_query(
            """INSERT INTO audit_log (user_id, timestamp, action_type, details_json)
               VALUES (?, ?, ?, ?)""",
            (user_id, datetime.now(), action_type, json.dumps(details))
        )