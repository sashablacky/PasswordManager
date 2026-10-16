"""
Paired browsers, stored in the vault database.

The pairing key of each browser is encrypted with the vault key, so a copy of
the database file is no use for talking to the program, and while the vault
is locked no browser can be authenticated at all.
"""

import base64
import logging
from datetime import datetime
from typing import List, Optional

from database.db_manager import DatabaseManager
from security.encryption import EncryptionEngine, browser_client_aad

logger = logging.getLogger(__name__)

TABLE = "browser_clients"

CREATE_TABLE_SQL = f"""
    CREATE TABLE IF NOT EXISTS {TABLE} (
        client_id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        browser TEXT NOT NULL DEFAULT '',
        encrypted_key BLOB NOT NULL,
        created_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_used TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
    )
"""


class BrowserClientStore:

    def __init__(self, db: DatabaseManager, encryption: EncryptionEngine):
        self.db = db
        self.encryption = encryption

    def _ensure_table(self) -> None:
        # Checked on every use: the database can be replaced by a backup at any time
        self.db.execute_query(CREATE_TABLE_SQL)

    def add(self, user_id: int, client_id: str, browser: str, pairing_key: bytes) -> None:
        self._ensure_table()
        encrypted = self.encryption.encrypt(base64.b64encode(pairing_key).decode("ascii"),
                                            browser_client_aad(client_id))
        self.db.execute_query(
            f"INSERT OR REPLACE INTO {TABLE} (client_id, user_id, browser, encrypted_key, created_date) "
            f"VALUES (?, ?, ?, ?, ?)",
            (client_id, user_id, browser[:40], encrypted, datetime.now())
        )

    def get_key(self, user_id: int, client_id: str) -> Optional[bytes]:
        """The pairing key of a browser, or None if it is not paired (or the vault is locked)"""
        if not isinstance(client_id, str) or not client_id or not self.encryption.is_key_set():
            return None
        self._ensure_table()
        row = self.db.fetch_one(f"SELECT encrypted_key FROM {TABLE} WHERE client_id = ? AND user_id = ?",
                                (client_id, user_id))
        if not row:
            return None
        try:
            return base64.b64decode(self.encryption.decrypt(row["encrypted_key"], browser_client_aad(client_id)))
        except Exception as e:
            logger.warning(f"Pairing key of a browser does not decrypt: {e}")
            return None

    def touch(self, client_id: str) -> None:
        self.db.execute_query(f"UPDATE {TABLE} SET last_used = ? WHERE client_id = ?",
                              (datetime.now(), client_id))

    def list(self, user_id: int) -> List[dict]:
        self._ensure_table()
        return self.db.fetch_all(
            f"SELECT client_id, browser, created_date, last_used FROM {TABLE} WHERE user_id = ? "
            f"ORDER BY created_date", (user_id,))

    def remove(self, user_id: int, client_id: str) -> None:
        self._ensure_table()
        self.db.execute_query(f"DELETE FROM {TABLE} WHERE client_id = ? AND user_id = ?", (client_id, user_id))

    def remove_all(self, user_id: int) -> None:
        self._ensure_table()
        self.db.execute_query(f"DELETE FROM {TABLE} WHERE user_id = ?", (user_id,))
