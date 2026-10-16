"""
Tests for security hardening: no plaintext entry data in logs, persistent lockout,
clipboard auto-clear
"""

import json
import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from database.db_manager import DatabaseManager
from security.encryption import EncryptionEngine
from managers.auth_manager import AuthenticationManager
from managers.password_manager import PasswordManager


@pytest.fixture
def vault(tmp_path):
    db = DatabaseManager(str(tmp_path / 'vault.db'))
    db.connect()
    db.create_tables()
    encryption = EncryptionEngine()
    auth = AuthenticationManager(db, encryption)
    auth.create_account("CorrectPass123!")
    auth.authenticate("CorrectPass123!")
    pm = PasswordManager(db, encryption)
    yield db, encryption, auth, pm
    db.disconnect()


class TestNoPlaintextInLogs:

    def test_audit_log_has_no_titles(self, vault):
        db, _, auth, pm = vault
        user_id = auth.get_current_user_id()
        pid = pm.add_password(user_id, "My Secret Bank", "alice", "S3cret!pass", "https://mybank.example")
        pm.delete_password(pid, user_id)

        rows = db.fetch_all("SELECT details_json FROM audit_log")
        dump = " ".join(r['details_json'] for r in rows).lower()
        assert "secret bank" not in dump
        assert "mybank" not in dump

    def test_text_logs_have_no_titles_or_queries(self, vault, caplog):
        db, _, auth, pm = vault
        user_id = auth.get_current_user_id()
        with caplog.at_level(logging.DEBUG):
            pm.add_password(user_id, "My Secret Bank", "alice", "S3cret!pass", "https://mybank.example")
            pm.search_passwords(user_id, "mybank")
        assert "Secret Bank" not in caplog.text
        assert "mybank" not in caplog.text
        assert "S3cret!pass" not in caplog.text

    def test_failed_query_does_not_log_params(self, vault, caplog):
        db = vault[0]
        with caplog.at_level(logging.DEBUG):
            with pytest.raises(Exception):
                db.execute_query("INSERT INTO no_such_table VALUES (?)", ("very-private-value",))
        assert "very-private-value" not in caplog.text


class TestPersistentLockout:

    def test_lockout_survives_restart(self, vault):
        db, encryption, auth, _ = vault
        auth.logout()
        for _ in range(AuthenticationManager.MAX_FAILED_ATTEMPTS):
            auth.authenticate("WrongPass123!")

        # A fresh manager simulates restarting the app
        restarted = AuthenticationManager(db, EncryptionEngine())
        success, msg = restarted.authenticate("CorrectPass123!")
        assert success is False
        assert "locked" in msg.lower()

    def test_failed_attempts_survive_restart(self, vault):
        db, _, auth, _ = vault
        auth.logout()
        auth.authenticate("WrongPass123!")
        auth.authenticate("WrongPass123!")

        restarted = AuthenticationManager(db, EncryptionEngine())
        success, msg = restarted.authenticate("WrongPass123!")
        assert success is False
        assert "2 attempts remaining" in msg

    def test_success_clears_stored_state(self, vault):
        db, _, auth, _ = vault
        auth.logout()
        auth.authenticate("WrongPass123!")
        assert auth.authenticate("CorrectPass123!")[0] is True

        settings = json.loads(db.fetch_one("SELECT settings_json FROM users")['settings_json'])
        assert 'failed_attempts' not in settings
        assert 'lockout_until' not in settings

    def test_expired_lockout_unlocks(self, vault):
        db, _, auth, _ = vault
        db.execute_query(
            "UPDATE users SET settings_json = ?",
            (json.dumps({"failed_attempts": 5, "lockout_until": "2000-01-01T00:00:00"}),)
        )
        restarted = AuthenticationManager(db, EncryptionEngine())
        assert restarted.authenticate("CorrectPass123!")[0] is True


class TestClipboard:

    def test_secret_cleared_after_timeout(self, qtbot):
        from PyQt5.QtWidgets import QApplication
        from ui.clipboard import copy_secret

        copy_secret("p@ssw0rd-1", clear_after_ms=50)
        assert QApplication.clipboard().text() == "p@ssw0rd-1"
        qtbot.waitUntil(lambda: QApplication.clipboard().text() == "", timeout=2000)

    def test_newer_clipboard_content_is_kept(self, qtbot):
        from PyQt5.QtWidgets import QApplication
        from ui.clipboard import copy_secret

        copy_secret("p@ssw0rd-2", clear_after_ms=50)
        QApplication.clipboard().setText("something else")
        qtbot.wait(200)
        assert QApplication.clipboard().text() == "something else"
