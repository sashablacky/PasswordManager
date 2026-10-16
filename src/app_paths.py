"""
Where the application keeps its files.

The vault used to be opened as a relative path ('password_vault.db'), so it
depended on the folder the program was started from: launching it from a
shortcut or another folder silently created a new, empty vault. The vault now
lives in a fixed per-user folder, and an existing vault from the old location
is copied there on first start.
"""

import os
import sys
import shutil
import sqlite3
import logging

logger = logging.getLogger(__name__)

APP_DIR_NAME = "SecureVault"
DB_FILE_NAME = "password_vault.db"
LOG_FILE_NAME = "error.log"

# Set this environment variable to use a different vault file (e.g. for testing)
DB_PATH_ENV = "PASSWORD_VAULT_DB"


def get_data_dir() -> str:
    """Per-user folder for the vault and the log, created if missing"""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")

    path = os.path.join(base, APP_DIR_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def get_log_path() -> str:
    return os.path.join(get_data_dir(), LOG_FILE_NAME)


def _program_dir() -> str:
    """Folder of the .exe when frozen by PyInstaller, otherwise of the sources"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def _has_account(db_path: str) -> bool:
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
            return bool(row and row[0])
        finally:
            conn.close()
    except sqlite3.Error:
        return False


def get_db_path() -> str:
    """Absolute path of the vault, migrating a vault from the old location if needed"""
    override = os.environ.get(DB_PATH_ENV)
    if override:
        return os.path.abspath(override)

    db_path = os.path.join(get_data_dir(), DB_FILE_NAME)
    if os.path.exists(db_path):
        return db_path

    # Older versions stored the vault next to the program or in the working folder
    legacy_candidates = [
        os.path.join(_program_dir(), DB_FILE_NAME),
        os.path.join(os.path.dirname(_program_dir()), DB_FILE_NAME),
        os.path.abspath(DB_FILE_NAME),
    ]
    for candidate in legacy_candidates:
        if os.path.exists(candidate) and _has_account(candidate):
            # Copy rather than move, so the old file stays as a fallback
            shutil.copy2(candidate, db_path)
            logger.warning(f"Copied existing vault from {candidate} to {db_path}")
            break

    return db_path
