import logging
import re
import json
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple

from database.db_manager import DatabaseManager
from security.encryption import EncryptionEngine

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PasswordManagerError(Exception):
    pass


class Password:
    def __init__(self, password_id: int, user_id: int, title: str, username: str,
                 password: str, url: str, notes: str, category_id: Optional[int],
                 strength_score: int, created_date, modified_date,
                 last_used_date, is_favorite: bool):
        self.password_id = password_id
        self.user_id = user_id
        self.title = title
        self.username = username
        self.password = password
        self.url = url
        self.notes = notes
        self.category_id = category_id
        self.strength_score = strength_score

        # Convert string dates to datetime objects if they're strings
        self.created_date = self._parse_date(created_date)
        self.modified_date = self._parse_date(modified_date)
        self.last_used_date = self._parse_date(last_used_date) if last_used_date else None

        self.is_favorite = bool(is_favorite)

    def _parse_date(self, date_value):
        if date_value is None:
            return None
        if isinstance(date_value, datetime):
            return date_value
        if isinstance(date_value, str):
            try:
                # Try common datetime formats
                for fmt in ['%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d']:
                    try:
                        return datetime.strptime(date_value, fmt)
                    except ValueError:
                        continue
            except Exception:
                pass
        return date_value

    def to_dict(self) -> Dict[str, Any]:
        return {
            'password_id': self.password_id,
            'user_id': self.user_id,
            'title': self.title,
            'username': self.username,
            'password': self.password,
            'url': self.url,
            'notes': self.notes,
            'category_id': self.category_id,
            'strength_score': self.strength_score,
            'created_date': self.created_date.strftime('%Y-%m-%d %H:%M:%S') if self.created_date else None,
            'modified_date': self.modified_date.strftime('%Y-%m-%d %H:%M:%S') if self.modified_date else None,
            'last_used_date': self.last_used_date.strftime('%Y-%m-%d %H:%M:%S') if self.last_used_date else None,
            'is_favorite': self.is_favorite
        }


class PasswordManager:
    def __init__(self, db_manager: DatabaseManager, encryption_engine: EncryptionEngine):
        self.db = db_manager
        self.encryption = encryption_engine

        # Ensure audit_log table exists
        try:
            self.db.execute_query("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    action_type TEXT NOT NULL,
                    details_json TEXT DEFAULT '{}'
                )
            """)
            logger.info("Ensured audit_log table exists")
        except Exception as e:
            logger.warning(f"Could not create audit_log table: {e}")

        logger.info("PasswordManager initialized")

    def add_password(self, user_id: int, title: str, username: str, password: str,
                     url: str = "", notes: str = "", category_id: Optional[int] = None) -> int:
        if not self.encryption.is_key_set():
            raise PasswordManagerError("Encryption key not set. Please login first.")

        if not title or not title.strip():
            raise PasswordManagerError("Title is required")

        if not password or not password.strip():
            raise PasswordManagerError("Password is required")

        try:
            # Calculate password strength
            strength = self._calculate_strength(password)

            # Encrypt sensitive fields
            encrypted_password = self.encryption.encrypt(password)
            encrypted_username = self.encryption.encrypt(username) if username else None
            encrypted_url = self.encryption.encrypt(url) if url else None
            encrypted_notes = self.encryption.encrypt(notes) if notes else None

            # Store in database
            now = datetime.now()
            cursor = self.db.execute_query(
                """INSERT INTO passwords 
                   (user_id, encrypted_password, encrypted_username, encrypted_url, 
                    encrypted_notes, category_id, strength_score, created_date, modified_date)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (user_id, encrypted_password, encrypted_username, encrypted_url,
                 encrypted_notes, category_id, strength, now, now)
            )

            password_id = cursor.lastrowid

            # Log action
            self._log_action(user_id, "PASSWORD_ADDED", {
                "password_id": password_id,
                "title": title,
                "strength": strength
            })

            logger.info(f"✓ Password '{title}' added (ID: {password_id}, strength: {strength})")

            return password_id

        except Exception as e:
            logger.error(f"✗ Failed to add password: {e}")
            raise PasswordManagerError(f"Failed to add password: {str(e)}")

    def get_password(self, password_id: int, user_id: int) -> Password:
        if not self.encryption.is_key_set():
            raise PasswordManagerError("Encryption key not set. Please login first.")

        try:
            # Fetch from database
            result = self.db.fetch_one(
                "SELECT * FROM passwords WHERE password_id = ? AND user_id = ?",
                (password_id, user_id)
            )

            if not result:
                raise PasswordManagerError(f"Password with ID {password_id} not found")

            # Decrypt sensitive fields
            password = self.encryption.decrypt(result['encrypted_password'])
            username = self.encryption.decrypt(result['encrypted_username']) if result['encrypted_username'] else ""
            url = self.encryption.decrypt(result['encrypted_url']) if result['encrypted_url'] else ""
            notes = self.encryption.decrypt(result['encrypted_notes']) if result['encrypted_notes'] else ""

            # Get title from URL or use generic name
            title = self._extract_title_from_url(url) if url else f"Password {password_id}"

            return Password(
                password_id=result['password_id'],
                user_id=result['user_id'],
                title=title,
                username=username,
                password=password,
                url=url,
                notes=notes,
                category_id=result['category_id'],
                strength_score=result['strength_score'],
                created_date=result['created_date'],
                modified_date=result['modified_date'],
                last_used_date=result['last_used_date'],
                is_favorite=bool(result['is_favorite'])
            )

        except Exception as e:
            logger.error(f"✗ Failed to get password: {e}")
            raise PasswordManagerError(f"Failed to get password: {str(e)}")

    def get_all_passwords(self, user_id: int) -> List[Password]:
        if not self.encryption.is_key_set():
            raise PasswordManagerError("Encryption key not set. Please login first.")

        try:
            results = self.db.fetch_all(
                "SELECT * FROM passwords WHERE user_id = ? ORDER BY modified_date DESC",
                (user_id,)
            )

            passwords = []
            for result in results:
                try:
                    password = self.encryption.decrypt(result['encrypted_password'])
                    username = self.encryption.decrypt(result['encrypted_username']) if result[
                        'encrypted_username'] else ""
                    url = self.encryption.decrypt(result['encrypted_url']) if result['encrypted_url'] else ""
                    notes = self.encryption.decrypt(result['encrypted_notes']) if result['encrypted_notes'] else ""

                    title = self._extract_title_from_url(url) if url else f"Password {result['password_id']}"

                    passwords.append(Password(
                        password_id=result['password_id'],
                        user_id=result['user_id'],
                        title=title,
                        username=username,
                        password=password,
                        url=url,
                        notes=notes,
                        category_id=result['category_id'],
                        strength_score=result['strength_score'],
                        created_date=result['created_date'],
                        modified_date=result['modified_date'],
                        last_used_date=result['last_used_date'],
                        is_favorite=bool(result['is_favorite'])
                    ))
                except Exception as e:
                    logger.warning(f"Failed to decrypt password {result['password_id']}: {e}")
                    continue

            logger.info(f"✓ Retrieved {len(passwords)} passwords for user {user_id}")
            return passwords

        except Exception as e:
            logger.error(f"✗ Failed to get passwords: {e}")
            raise PasswordManagerError(f"Failed to get passwords: {str(e)}")

    def update_password(self, password_id: int, user_id: int,
                        title: str = None,
                        username: str = None,
                        password: str = None,
                        url: str = None,
                        notes: str = None,
                        category_id: int = None) -> bool:
        """
        Update a password entry

        Args:
            password_id: ID of the password to update
            user_id: ID of the user (for security check)
            username: New username (optional)
            password: New password (optional)
            url: New URL (optional)
            notes: New notes (optional)
            category_id: New category ID (optional)

        Returns:
            bool: True if update successful
        """
        if not self.encryption.is_key_set():
            raise PasswordManagerError("Encryption key not set. Please login first.")

        try:
            # Get existing password
            existing = self.db.fetch_one(
                "SELECT * FROM passwords WHERE password_id = ? AND user_id = ?",
                (password_id, user_id)
            )

            if not existing:
                raise PasswordManagerError(f"Password with ID {password_id} not found")

            # Build update query dynamically
            updates = []
            params = []
            update_details = {}

            if password is not None:
                encrypted_password = self.encryption.encrypt(password)
                strength = self._calculate_strength(password)
                updates.append("encrypted_password = ?")
                updates.append("strength_score = ?")
                params.extend([encrypted_password, strength])
                update_details['password_changed'] = True

            if username is not None:
                encrypted_username = self.encryption.encrypt(username) if username else None
                updates.append("encrypted_username = ?")
                params.append(encrypted_username)
                update_details['username_changed'] = True

            if url is not None:
                encrypted_url = self.encryption.encrypt(url) if url else None
                updates.append("encrypted_url = ?")
                params.append(encrypted_url)
                update_details['url_changed'] = True

            if notes is not None:
                encrypted_notes = self.encryption.encrypt(notes) if notes else None
                updates.append("encrypted_notes = ?")
                params.append(encrypted_notes)
                update_details['notes_changed'] = True

            if category_id is not None:
                updates.append("category_id = ?")
                params.append(category_id)
                update_details['category_changed'] = True

            if not updates:
                logger.warning("No fields to update")
                return True

            # Always update modified_date
            updates.append("modified_date = ?")
            params.append(datetime.now())

            # Add WHERE clause params
            params.extend([password_id, user_id])

            # Execute update
            query = f"UPDATE passwords SET {', '.join(updates)} WHERE password_id = ? AND user_id = ?"
            self.db.execute_query(query, tuple(params))

            # Log action
            self._log_action(user_id, "PASSWORD_UPDATED", {
                "password_id": password_id,
                **update_details
            })

            logger.info(f"✓ Password {password_id} updated")
            return True

        except Exception as e:
            logger.error(f"✗ Failed to update password: {e}")
            raise PasswordManagerError(f"Failed to update password: {str(e)}")

    def delete_password(self, password_id: int, user_id: int) -> bool:
        """
        Delete a password entry

        Args:
            password_id: ID of the password to delete
            user_id: ID of the user (for security check)

        Returns:
            bool: True if deletion successful
        """
        try:
            # Verify password exists and belongs to user
            existing = self.db.fetch_one(
                "SELECT * FROM passwords WHERE password_id = ? AND user_id = ?",
                (password_id, user_id)
            )

            if not existing:
                raise PasswordManagerError(f"Password with ID {password_id} not found")

            # Get title for logging
            try:
                url = self.encryption.decrypt(existing['encrypted_url']) if existing['encrypted_url'] else ""
                title = self._extract_title_from_url(url)
            except:
                title = f"Password {password_id}"

            # Delete associated breach checks
            self.db.execute_query(
                "DELETE FROM breach_checks WHERE password_id = ?",
                (password_id,)
            )

            # Delete password
            self.db.execute_query(
                "DELETE FROM passwords WHERE password_id = ? AND user_id = ?",
                (password_id, user_id)
            )

            # Log action
            self._log_action(user_id, "PASSWORD_DELETED", {
                "password_id": password_id,
                "title": title
            })

            logger.info(f"✓ Password {password_id} deleted")
            return True

        except Exception as e:
            logger.error(f"✗ Failed to delete password: {e}")
            raise PasswordManagerError(f"Failed to delete password: {str(e)}")

    def search_passwords(self, user_id: int, query: str) -> List[Password]:
        """
        Search passwords by query string

        Searches in decrypted username, URL, and notes

        Args:
            user_id: ID of the user
            query: Search query string

        Returns:
            List[Password]: List of matching passwords
        """
        if not query or not query.strip():
            return self.get_all_passwords(user_id)

        query_lower = query.lower().strip()

        try:
            all_passwords = self.get_all_passwords(user_id)

            matching = []
            for pwd in all_passwords:
                # Search in title, username, URL, notes
                if (query_lower in pwd.title.lower() or
                        query_lower in pwd.username.lower() or
                        query_lower in pwd.url.lower() or
                        query_lower in pwd.notes.lower()):
                    matching.append(pwd)

            logger.info(f"✓ Search '{query}' found {len(matching)} results")
            return matching
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []

    def get_favorites(self, user_id: int) -> List[Password]:
        """
        Get all favorite passwords

        Args:
            user_id: ID of the user

        Returns:
            List[Password]: List of favorite passwords
        """
        try:
            all_passwords = self.get_all_passwords(user_id)
            favorites = [pwd for pwd in all_passwords if pwd.is_favorite]
            logger.info(f"Found {len(favorites)} favorite passwords for user {user_id}")
            return favorites
        except Exception as e:
            logger.error(f"Failed to get favorites: {e}")
            return []

    def get_weak_passwords(self, user_id: int, threshold: int = 50) -> List[Password]:
        """
        Get passwords with strength below threshold

        Args:
            user_id: ID of the user
            threshold: Strength threshold (0-100, default 50)

        Returns:
            List[Password]: List of weak passwords
        """
        try:
            all_passwords = self.get_all_passwords(user_id)
            weak = [pwd for pwd in all_passwords if pwd.strength_score < threshold]
            logger.info(f"Found {len(weak)} weak passwords for user {user_id}")
            return weak
        except Exception as e:
            logger.error(f"Failed to get weak passwords: {e}")
            return []

    def get_statistics(self, user_id: int) -> Dict[str, Any]:
        """
        Get password statistics for user

        Args:
            user_id: ID of the user

        Returns:
            Dict with statistics
        """
        try:
            all_passwords = self.get_all_passwords(user_id)

            if not all_passwords:
                return {
                    'total': 0,
                    'weak': 0,
                    'medium': 0,
                    'strong': 0,
                    'favorites': 0,
                    'average_strength': 0
                }

            weak = len([p for p in all_passwords if p.strength_score < 50])
            medium = len([p for p in all_passwords if 50 <= p.strength_score < 75])
            strong = len([p for p in all_passwords if p.strength_score >= 75])
            favorites = len([p for p in all_passwords if p.is_favorite])

            if all_passwords:
                avg_strength = sum(p.strength_score for p in all_passwords) / len(all_passwords)
            else:
                avg_strength = 0

            return {
                'total': len(all_passwords),
                'weak': weak,
                'medium': medium,
                'strong': strong,
                'favorites': favorites,
                'average_strength': round(avg_strength, 1)
            }
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {
                'total': 0,
                'weak': 0,
                'medium': 0,
                'strong': 0,
                'favorites': 0,
                'average_strength': 0
            }

    def toggle_favorite(self, password_id: int, user_id: int) -> bool:
        """
        Toggle favorite status of a password

        Args:
            password_id: ID of the password
            user_id: ID of the user

        Returns:
            bool: New favorite status
        """
        try:
            # Get current status
            result = self.db.fetch_one(
                "SELECT is_favorite FROM passwords WHERE password_id = ? AND user_id = ?",
                (password_id, user_id)
            )

            if not result:
                raise PasswordManagerError(f"Password with ID {password_id} not found")

            # Toggle status
            new_status = not bool(result['is_favorite'])

            self.db.execute_query(
                "UPDATE passwords SET is_favorite = ? WHERE password_id = ? AND user_id = ?",
                (int(new_status), password_id, user_id)
            )

            # Log action
            self._log_action(user_id, "FAVORITE_TOGGLED", {
                "password_id": password_id,
                "new_status": new_status
            })

            logger.info(f"✓ Password {password_id} favorite status: {new_status}")
            return new_status

        except Exception as e:
            logger.error(f"✗ Failed to toggle favorite: {e}")
            raise PasswordManagerError(f"Failed to toggle favorite: {str(e)}")

    def update_last_used(self, password_id: int, user_id: int) -> None:
        """
        Update the last_used_date for a password

        Call this when user copies or views a password

        Args:
            password_id: ID of the password
            user_id: ID of the user
        """
        try:
            now = datetime.now()
            self.db.execute_query(
                "UPDATE passwords SET last_used_date = ? WHERE password_id = ? AND user_id = ?",
                (now, password_id, user_id)
            )

            logger.debug(f"Updated last_used for password {password_id}")

        except Exception as e:
            logger.warning(f"Failed to update last_used: {e}")

    def _calculate_strength(self, password: str) -> int:
        """
        Calculate password strength score (0-100)

        Factors:
        - Length
        - Character variety (uppercase, lowercase, numbers, symbols)
        - No common patterns

        Args:
            password: Password to evaluate

        Returns:
            int: Strength score (0-100)
        """
        if not password:
            return 0

        score = 0

        # Length (max 30 points)
        length = len(password)
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        else:
            score += length * 2  # Give some points for shorter passwords

        # Character variety (max 40 points)
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

        variety_count = sum([has_lower, has_upper, has_digit, has_symbol])
        score += variety_count * 10

        # Unique characters (max 20 points)
        if len(password) > 0:
            unique_ratio = len(set(password)) / len(password)
            score += int(unique_ratio * 20)

        # Penalties for common patterns (max -30 points)
        password_lower = password.lower()

        common_patterns = ['password', '123456', 'qwerty', 'abc123', 'letmein', 'admin', 'welcome']
        for pattern in common_patterns:
            if pattern in password_lower:
                score -= 20
                break

        # Sequential characters penalty
        for i in range(len(password_lower) - 2):
            if password_lower[i:i + 3] in 'abcdefghijklmnopqrstuvwxyz0123456789':
                score -= 5
                break

        # Repeated characters penalty
        if len(password) >= 3:
            for i in range(len(password) - 2):
                if password[i] == password[i + 1] == password[i + 2]:
                    score -= 10
                    break

        # Cap at 0-100
        return max(0, min(100, score))

    def _extract_title_from_url(self, url: str) -> str:
        """Extract a readable title from URL"""
        if not url:
            return "Untitled"

        # Extract domain name
        match = re.search(r'(?:https?://)?(?:www\.)?([^/]+)', url)
        if match:
            domain = match.group(1)
            # Remove common TLDs
            domain = re.sub(r'\.(com|org|net|co\.uk|io|edu|gov|mil|tv|info|biz)$', '', domain)
            # Split by dots and take the main part
            parts = domain.split('.')
            if parts:
                main_part = parts[0]
                # Capitalize first letter
                return main_part.capitalize()
            return domain.capitalize()

        return url[:30]  # Fallback: first 30 chars

    def _log_action(self, user_id: int, action_type: str, details: dict) -> None:
        """Log action to audit log"""
        try:
            # Check if audit_log table exists, if not, create it
            table_exists = self.db.fetch_one(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'"
            )

            if not table_exists:
                # Create audit_log table if it doesn't exist
                self.db.execute_query("""
                    CREATE TABLE IF NOT EXISTS audit_log (
                        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        timestamp TIMESTAMP NOT NULL,
                        action_type TEXT NOT NULL,
                        details_json TEXT DEFAULT '{}'
                    )
                """)
                logger.info("Created audit_log table")

            # Insert log entry
            self.db.execute_query(
                """INSERT INTO audit_log (user_id, timestamp, action_type, details_json)
                   VALUES (?, ?, ?, ?)""",
                (user_id, datetime.now(), action_type, json.dumps(details))
            )
            logger.debug(f"Logged action: {action_type} for user {user_id}")

        except Exception as e:
            # Don't let logging failures break the main operation
            logger.warning(f"Failed to log action {action_type}: {e}")