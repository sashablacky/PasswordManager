import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Tuple

from database.db_manager import DatabaseManager
from security.encryption import EncryptionEngine, BREACH_RESULT_FIELD, record_aad, wipe
from security.kdf import KeyDerivationFunction, VAULT_FORMAT_CURRENT, VAULT_FORMAT_LEGACY

logger = logging.getLogger(__name__)

# Columns of the passwords table that hold ciphertext
ENCRYPTED_FIELDS = ("encrypted_title", "encrypted_password", "encrypted_username",
                    "encrypted_url", "encrypted_notes")

# Master passwords containing one of these are refused (lower-cased match)
WEAK_PASSWORD_PATTERNS = (
    "password", "passw0rd", "p@ssword", "p@ssw0rd", "qwerty", "123456", "654321",
    "abcdef", "letmein", "iloveyou", "111111", "000000",
)


class AuthenticationError(Exception):
    """Custom exception for authentication-related errors"""
    pass


class AuthenticationManager:

    # Security constants
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 5
    MIN_PASSWORD_LENGTH = 12
    # Without three character types the password must be at least this long (a passphrase)
    MIN_PASSPHRASE_LENGTH = 16

    def __init__(self, db_manager: DatabaseManager, encryption_engine: EncryptionEngine):
        self.db = db_manager
        self.encryption = encryption_engine
        self.kdf = KeyDerivationFunction()

        self._current_user_id: Optional[int] = None
        self._failed_attempts: dict = {}  # {user_id: count}
        self._lockout_until: dict = {}  # {user_id: datetime}

        # Set when an old-format vault could not be upgraded at login (it still works)
        self.upgrade_error: Optional[str] = None

        logger.info("AuthenticationManager initialized")

    def account_exists(self) -> bool:
        return self.db.fetch_one("SELECT user_id FROM users LIMIT 1") is not None

    def create_account(self, master_password: str, overwrite: bool = False) -> Tuple[bool, str]:
        """
        Create the vault account.

        With overwrite=True an existing account and ALL its data are deleted first
        (used when the master password is forgotten). A backup copy of the old
        vault file is written before anything is deleted.
        """
        try:
            is_valid, message = self._validate_password_strength(master_password)
            if not is_valid:
                logger.warning(f"Account creation failed: {message}")
                return False, message

            if self.account_exists():
                if not overwrite:
                    logger.warning("Account creation failed: Account already exists")
                    return False, "An account already exists. Only one account per database."
                self._reset_vault()

            verifier, salt, encryption_key = self.kdf.new_vault_secrets(master_password)
            wipe(encryption_key)  # the key is derived again at login

            self.db.execute_query(
                """INSERT INTO users (master_password_hash, salt, kdf_iterations, kdf_memory_cost,
                                      kdf_parallelism, kdf_version, created_date)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (verifier, salt, self.kdf.TIME_COST, self.kdf.MEMORY_COST,
                 self.kdf.PARALLELISM, VAULT_FORMAT_CURRENT, datetime.now())
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

    def _reset_vault(self) -> None:
        """Back up the vault file, then delete the account and all its data"""
        self.logout()
        self._failed_attempts.clear()
        self._lockout_until.clear()

        if self.db.db_path != ':memory:':
            import os
            stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base, ext = os.path.splitext(self.db.db_path)
            backup_path = f"{base}_before_reset_{stamp}{ext or '.db'}"
            self.db.backup_to(backup_path)
            logger.warning(f"Vault reset: previous vault saved to {backup_path}")

        self.db.begin_transaction()
        try:
            for table in ("breach_checks", "audit_log", "passwords", "categories", "users"):
                self.db.execute_query(f"DELETE FROM {table}")
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def authenticate(self, master_password: str) -> Tuple[bool, str]:
        try:
            user = self.db.fetch_one("SELECT * FROM users LIMIT 1")

            if not user:
                logger.warning("Authentication failed: No account exists")
                return False, "No account found. Please create an account first."

            user_id = user['user_id']

            # Failed attempts are kept in the database so restarting the app doesn't reset them
            self._load_lockout_state(user)

            if self._is_locked_out(user_id):
                remaining = self._get_lockout_remaining(user_id)
                logger.warning(f"Authentication failed: Account locked (user {user_id})")
                return False, f"Account locked due to too many failed attempts. Try again in {remaining} seconds."

            encryption_key = self._open_vault(master_password, user)

            if encryption_key is not None:
                self._reset_failed_attempts(user_id)

                self.encryption.set_key(encryption_key)
                wipe(encryption_key)
                self.encryption.bind_records = self._vault_format(user) >= VAULT_FORMAT_CURRENT

                self.db.execute_query(
                    "UPDATE users SET last_login = ? WHERE user_id = ?",
                    (datetime.now(), user_id)
                )

                self._current_user_id = user_id

                self._log_action(user_id, "LOGIN_SUCCESS", {})

                if self._vault_format(user) < VAULT_FORMAT_CURRENT:
                    self._upgrade_vault(user_id, master_password)

                logger.info(f"Authentication successful for user {user_id}")
                return True, "Login successful"

            else:
                self._increment_failed_attempts(user_id)

                if self._failed_attempts.get(user_id, 0) >= self.MAX_FAILED_ATTEMPTS:
                    self._lockout_until[user_id] = datetime.now() + timedelta(minutes=self.LOCKOUT_DURATION_MINUTES)
                    self._save_lockout_state(user_id)

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
        """
        Re-encrypt every entry with a key derived from the new password.

        All updates run in a single transaction: if anything fails, nothing is
        changed and the old master password keeps working.
        """
        try:
            is_valid, message = self._validate_password_strength(new_password)
            if not is_valid:
                return False, message

            user_id = self._current_user_id
            if user_id is None:
                return False, "Please log in first"

            user = self.db.fetch_one("SELECT * FROM users WHERE user_id = ?", (user_id,))
            # Checked directly rather than through authenticate(), so a typo here
            # does not count as a failed login
            old_key = self._open_vault(old_password, user) if user else None
            if old_key is None:
                return False, "Current password is incorrect"
            wipe(old_key)

            self._rekey_vault(user_id, new_password)

            self._log_action(user_id, "PASSWORD_CHANGED", {})

            logger.info(f"Master password changed for user {user_id}")
            return True, "Master password changed successfully"

        except Exception as e:
            logger.error(f"Password change failed: {e}")
            return False, f"Password change failed: {str(e)}"

    def verify_master_password(self, master_password: str) -> bool:
        """Re-check the master password of the logged-in user (e.g. before a plain-text export)"""
        if self._current_user_id is None or not master_password:
            return False
        user = self.db.fetch_one("SELECT * FROM users WHERE user_id = ?", (self._current_user_id,))
        key = self._open_vault(master_password, user) if user else None
        wipe(key)
        return key is not None

    def check_backup_password(self, backup_path: str, master_password: str) -> bool:
        """True if master_password opens the vault in the backup file (read-only check)"""
        import sqlite3
        try:
            conn = sqlite3.connect(f"file:{backup_path}?mode=ro", uri=True)
            try:
                conn.row_factory = sqlite3.Row
                row = conn.execute("SELECT * FROM users LIMIT 1").fetchone()
                user = dict(row) if row else None
            finally:
                conn.close()
        except sqlite3.Error as e:
            logger.warning(f"Could not read backup: {e}")
            return False

        if not user or not master_password:
            return False
        key = self._open_vault(master_password, user)
        wipe(key)
        return key is not None

    @staticmethod
    def _vault_format(user: dict) -> int:
        return user.get('kdf_version') or VAULT_FORMAT_LEGACY

    def _open_vault(self, master_password: str, user: dict):
        """The vault's encryption key if master_password is right, otherwise None"""
        return self.kdf.open_vault(
            master_password,
            user['master_password_hash'],
            user['salt'],
            self._vault_format(user),
            user.get('kdf_iterations'),
            user.get('kdf_memory_cost'),
            user.get('kdf_parallelism'),
        )

    def _upgrade_vault(self, user_id: int, master_password: str) -> None:
        """Convert an old-format vault to the current format (same master password)

        If anything fails nothing is changed and the vault keeps working in the
        old format; the upgrade is tried again at the next login.
        """
        try:
            self._rekey_vault(user_id, master_password)
            self.upgrade_error = None
            self._log_action(user_id, "VAULT_UPGRADED", {"format": VAULT_FORMAT_CURRENT})
            logger.warning(f"Vault upgraded to format {VAULT_FORMAT_CURRENT}")
        except Exception as e:
            self.upgrade_error = str(e)
            logger.error(f"Vault upgrade failed, keeping the old format: {e}")

    def _rekey_vault(self, user_id: int, new_password: str) -> None:
        """Re-encrypt every stored secret under a key derived from new_password

        Writes the current vault format: fresh salt, current Argon2 parameters,
        separate verifier, ciphertexts bound to their entry and field. Runs in
        one transaction, so on any error (e.g. an entry that can't be decrypted)
        nothing is changed and the old master password keeps working.
        """
        old_engine = self.encryption
        verifier, salt, new_key = self.kdf.new_vault_secrets(new_password)
        new_engine = EncryptionEngine()
        new_engine.set_key(new_key)
        wipe(new_key)

        try:
            def reencrypt(value, password_id, field):
                if not value:
                    return None
                plaintext = old_engine.decrypt(value, record_aad(old_engine, password_id, field))
                return new_engine.encrypt(plaintext, record_aad(new_engine, password_id, field))

            passwords = self.db.fetch_all(
                f"SELECT password_id, {', '.join(ENCRYPTED_FIELDS)} FROM passwords WHERE user_id = ?",
                (user_id,)
            )
            breach_rows = self.db.fetch_all(
                "SELECT check_id, password_id, encrypted_result FROM breach_checks "
                "WHERE user_id = ? AND encrypted_result IS NOT NULL",
                (user_id,)
            )

            self.db.begin_transaction()
            try:
                for pwd in passwords:
                    new_values = [reencrypt(pwd[field], pwd['password_id'], field)
                                  for field in ENCRYPTED_FIELDS]
                    self.db.execute_query(
                        f"UPDATE passwords SET {', '.join(f + ' = ?' for f in ENCRYPTED_FIELDS)} "
                        f"WHERE password_id = ?",
                        (*new_values, pwd['password_id'])
                    )

                for row in breach_rows:
                    self.db.execute_query(
                        "UPDATE breach_checks SET encrypted_result = ? WHERE check_id = ?",
                        (reencrypt(row['encrypted_result'], row['password_id'], BREACH_RESULT_FIELD),
                         row['check_id'])
                    )

                self.db.execute_query(
                    """UPDATE users SET master_password_hash = ?, salt = ?, kdf_iterations = ?,
                                        kdf_memory_cost = ?, kdf_parallelism = ?, kdf_version = ?
                       WHERE user_id = ?""",
                    (verifier, salt, self.kdf.TIME_COST, self.kdf.MEMORY_COST,
                     self.kdf.PARALLELISM, VAULT_FORMAT_CURRENT, user_id)
                )

                self.db.commit()

            except Exception:
                self.db.rollback()
                raise

            self.encryption.set_key(new_engine.copy_key())
            self.encryption.bind_records = True

        finally:
            new_engine.clear_key()

    def is_logged_in(self) -> bool:
        return self._current_user_id is not None and self.encryption.is_key_set()

    def get_current_user_id(self) -> Optional[int]:
        return self._current_user_id

    def _validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """Rules for the master password

        Length matters most: at least 12 characters with three kinds of
        characters, or a passphrase of 16+ characters of any kind. Passwords
        built around well-known weak passwords are refused.
        """
        if len(password) < self.MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {self.MIN_PASSWORD_LENGTH} characters"

        lowered = password.lower()
        for pattern in WEAK_PASSWORD_PATTERNS:
            if pattern in lowered:
                return False, f"Password contains a commonly used password ('{pattern}'). Choose something less predictable"

        if len(set(password)) < 6:
            return False, "Password has too many repeated characters"

        kinds = sum((
            any(c.isupper() for c in password),
            any(c.islower() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        ))
        if kinds < 3 and len(password) < self.MIN_PASSPHRASE_LENGTH:
            return False, (
                f"Use at least {self.MIN_PASSPHRASE_LENGTH} characters, or mix at least three of: "
                "uppercase letters, lowercase letters, numbers, symbols"
            )

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
        self._save_lockout_state(user_id)

    def _reset_failed_attempts(self, user_id: int) -> None:
        if user_id in self._failed_attempts:
            del self._failed_attempts[user_id]
        if user_id in self._lockout_until:
            del self._lockout_until[user_id]
        self._save_lockout_state(user_id)

    @staticmethod
    def _parse_settings(settings_json: Optional[str]) -> dict:
        try:
            settings = json.loads(settings_json or '{}')
            return settings if isinstance(settings, dict) else {}
        except ValueError:
            return {}

    def _load_lockout_state(self, user: dict) -> None:
        user_id = user['user_id']
        settings = self._parse_settings(user.get('settings_json'))

        attempts = settings.get('failed_attempts', 0)
        if isinstance(attempts, int) and attempts > 0:
            self._failed_attempts[user_id] = attempts
        else:
            self._failed_attempts.pop(user_id, None)

        self._lockout_until.pop(user_id, None)
        lockout_until = settings.get('lockout_until')
        if lockout_until:
            try:
                self._lockout_until[user_id] = datetime.fromisoformat(lockout_until)
            except (TypeError, ValueError):
                pass

    def _save_lockout_state(self, user_id: int) -> None:
        row = self.db.fetch_one("SELECT settings_json FROM users WHERE user_id = ?", (user_id,))
        if not row:
            return

        settings = self._parse_settings(row['settings_json'])
        settings.pop('failed_attempts', None)
        settings.pop('lockout_until', None)

        if self._failed_attempts.get(user_id):
            settings['failed_attempts'] = self._failed_attempts[user_id]
        if user_id in self._lockout_until:
            settings['lockout_until'] = self._lockout_until[user_id].isoformat()

        self.db.execute_query(
            "UPDATE users SET settings_json = ? WHERE user_id = ?",
            (json.dumps(settings), user_id)
        )

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