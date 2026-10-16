"""
Regression tests for the bugs fixed in version 1.1
"""

import os
import logging
import sqlite3

import pytest

from database.db_manager import DatabaseManager
from security.encryption import EncryptionEngine
from security.generator import PasswordGenerator
from security.breach_detector import BreachDetector
from managers.auth_manager import AuthenticationManager
from managers.password_manager import PasswordManager

MASTER = "FirstPass11!"


@pytest.fixture
def vault(tmp_path):
    db = DatabaseManager(str(tmp_path / "vault.db"))
    db.connect()
    db.create_tables()
    encryption = EncryptionEngine()
    auth = AuthenticationManager(db, encryption)
    pm = PasswordManager(db, encryption)
    assert auth.create_account(MASTER)[0]
    assert auth.authenticate(MASTER)[0]
    yield db, auth, pm, auth.get_current_user_id()
    db.disconnect()


class TestTitles:
    def test_title_is_saved_and_encrypted(self, vault):
        db, auth, pm, uid = vault
        pid = pm.add_password(uid, "My Bank", "bob", "Secret123!")

        assert pm.get_password(pid, uid).title == "My Bank"

        row = db.fetch_one("SELECT encrypted_title FROM passwords WHERE password_id = ?", (pid,))
        assert b"My Bank" not in row['encrypted_title']

    def test_title_not_in_audit_log(self, vault):
        db, auth, pm, uid = vault
        pid = pm.add_password(uid, "My Bank", "bob", "Secret123!")
        pm.delete_password(pid, uid)

        logs = db.fetch_all("SELECT details_json FROM audit_log")
        assert all("My Bank" not in row['details_json'] for row in logs)

    def test_title_can_be_updated(self, vault):
        db, auth, pm, uid = vault
        pid = pm.add_password(uid, "Old", "bob", "Secret123!")
        pm.update_password(pid, uid, title="New")
        assert pm.get_password(pid, uid).title == "New"

    def test_old_entries_without_title_still_load(self, vault):
        db, auth, pm, uid = vault
        pid = pm.add_password(uid, "x", "bob", "Secret123!", url="https://github.com/login")
        db.execute_query("UPDATE passwords SET encrypted_title = NULL WHERE password_id = ?", (pid,))
        assert pm.get_password(pid, uid).title == "Github"

    def test_old_database_is_migrated(self, tmp_path):
        # A vault created by version 1.0 has no encrypted_title column
        path = str(tmp_path / "old.db")
        db = DatabaseManager(path)
        db.connect()
        db.create_tables()
        db.execute_query("ALTER TABLE passwords DROP COLUMN encrypted_title")
        db.disconnect()

        db = DatabaseManager(path)
        db.connect()
        db.create_tables()
        columns = [c['name'] for c in db.fetch_all("PRAGMA table_info(passwords)")]
        db.disconnect()
        assert 'encrypted_title' in columns


class TestPasswordValues:
    def test_spaces_in_password_are_kept(self, vault):
        db, auth, pm, uid = vault
        pid = pm.add_password(uid, "Site", "bob", "  pass with spaces  ")
        assert pm.get_password(pid, uid).password == "  pass with spaces  "

    def test_category_can_be_removed(self, vault):
        db, auth, pm, uid = vault
        category = db.fetch_one("SELECT category_id FROM categories LIMIT 1")['category_id']
        pid = pm.add_password(uid, "Site", "bob", "Secret123!", category_id=category)

        pm.update_password(pid, uid, category_id=None)
        assert pm.get_password(pid, uid).category_id is None

    def test_category_unchanged_when_not_given(self, vault):
        db, auth, pm, uid = vault
        category = db.fetch_one("SELECT category_id FROM categories LIMIT 1")['category_id']
        pid = pm.add_password(uid, "Site", "bob", "Secret123!", category_id=category)

        pm.update_password(pid, uid, notes="changed")
        assert pm.get_password(pid, uid).category_id == category

    @pytest.mark.parametrize("password", ["Summer2024!", "correct horse battery staple", "Xy9$mK#pL2@vN8qR"])
    def test_strength_matches_dialog(self, vault, password):
        db, auth, pm, uid = vault
        pid = pm.add_password(uid, "Site", "bob", password)
        assert pm.get_password(pid, uid).strength_score == PasswordGenerator().calculate_strength_score(password)


class TestMasterPasswordChange:
    def test_change_reencrypts_everything(self, vault):
        db, auth, pm, uid = vault
        pid = pm.add_password(uid, "Bank", "bob", "Secret123!", url="https://bank.com", notes="n")

        ok, msg = auth.change_master_password(MASTER, "SecondPass2@")
        assert ok, msg
        assert pm.get_password(pid, uid).title == "Bank"

        auth.logout()
        assert not auth.authenticate(MASTER)[0]
        assert auth.authenticate("SecondPass2@")[0]
        entry = pm.get_password(pid, uid)
        assert (entry.title, entry.password, entry.notes) == ("Bank", "Secret123!", "n")

    def test_failure_midway_changes_nothing(self, vault, monkeypatch):
        db, auth, pm, uid = vault
        ids = [pm.add_password(uid, f"Site {i}", "bob", f"Secret{i}23!") for i in range(3)]

        # Fail while re-encrypting the second entry
        calls = {"n": 0}
        original_encrypt = EncryptionEngine.encrypt

        def failing_encrypt(self, plaintext):
            calls["n"] += 1
            if calls["n"] == 5:
                raise RuntimeError("simulated crash")
            return original_encrypt(self, plaintext)

        monkeypatch.setattr(EncryptionEngine, "encrypt", failing_encrypt)
        ok, _ = auth.change_master_password(MASTER, "SecondPass2@")
        monkeypatch.setattr(EncryptionEngine, "encrypt", original_encrypt)
        assert not ok

        # Old password still works and every entry is still readable
        auth.logout()
        assert auth.authenticate(MASTER)[0]
        passwords = pm.get_all_passwords(uid)
        assert sorted(p.password_id for p in passwords) == sorted(ids)
        assert pm.last_decrypt_failures == 0

    def test_wrong_old_password_does_not_count_as_login(self, vault):
        db, auth, pm, uid = vault
        ok, msg = auth.change_master_password("WrongPass1!", "SecondPass2@")
        assert not ok
        assert msg == "Current password is incorrect"


class TestAccountReset:
    def test_create_account_without_overwrite_is_refused(self, vault):
        db, auth, pm, uid = vault
        ok, _ = auth.create_account("SecondPass2@")
        assert not ok

    def test_overwrite_deletes_old_vault_and_keeps_backup(self, vault, tmp_path):
        db, auth, pm, uid = vault
        pm.add_password(uid, "Bank", "bob", "Secret123!")

        ok, msg = auth.create_account("SecondPass2@", overwrite=True)
        assert ok, msg
        assert db.get_table_count('users') == 1
        assert db.get_table_count('passwords') == 0
        assert auth.authenticate("SecondPass2@")[0]

        backups = [f for f in os.listdir(tmp_path) if "_before_reset_" in f]
        assert len(backups) == 1
        conn = sqlite3.connect(str(tmp_path / backups[0]))
        assert conn.execute("SELECT COUNT(*) FROM passwords").fetchone()[0] == 1
        conn.close()


class TestDatabase:
    def test_foreign_keys_enabled(self, vault):
        db, auth, pm, uid = vault
        assert db.fetch_one("PRAGMA foreign_keys")['foreign_keys'] == 1

    def test_rollback_undoes_changes_inside_transaction(self, vault):
        db, auth, pm, uid = vault
        db.begin_transaction()
        db.execute_query("DELETE FROM categories")
        db.rollback()
        assert db.get_table_count('categories') == 6

    def test_backup_to(self, vault, tmp_path):
        db, auth, pm, uid = vault
        target = str(tmp_path / "copy.db")
        db.backup_to(target)
        conn = sqlite3.connect(target)
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
        conn.close()


class TestBreachDetectorOffline:
    def test_offline_is_not_reported_as_safe(self, monkeypatch):
        detector = BreachDetector()
        monkeypatch.setattr(detector, "_fetch_hibp_hashes", lambda prefix: None)

        found, count, sources = detector.check_password_hibp("anything")
        assert found is None

        assessment = detector.analyze_password_risk("Xy9$mK#pL2@vN8qR")
        assert assessment['check_failed'] is True
        assert assessment['breach_found'] is False
        assert "✓ Password appears secure" not in assessment['recommendations']

    def test_failed_result_is_not_cached(self, monkeypatch):
        detector = BreachDetector()
        monkeypatch.setattr(detector, "_fetch_hibp_hashes", lambda prefix: None)
        detector.check_password_hibp("anything")
        assert detector.cache == {}


class TestLogging:
    def test_importing_modules_does_not_configure_logging(self):
        # Modules used to call logging.basicConfig(), which made main.py's
        # log-file configuration a no-op
        import importlib
        import database.db_manager
        import managers.auth_manager
        import managers.password_manager
        import security.breach_detector
        import security.encryption
        import security.generator

        for module in (database.db_manager, managers.auth_manager, managers.password_manager,
                       security.breach_detector, security.encryption, security.generator):
            source = open(module.__file__, encoding="utf-8").read()
            assert "basicConfig" not in source, module.__name__


class TestAppPaths:
    def test_env_override(self, monkeypatch, tmp_path):
        import app_paths
        monkeypatch.setenv(app_paths.DB_PATH_ENV, str(tmp_path / "x.db"))
        assert app_paths.get_db_path() == str(tmp_path / "x.db")

    def test_legacy_vault_is_copied(self, monkeypatch, tmp_path):
        import app_paths
        monkeypatch.delenv(app_paths.DB_PATH_ENV, raising=False)
        data_dir = tmp_path / "data"
        work_dir = tmp_path / "work"
        data_dir.mkdir()
        work_dir.mkdir()
        monkeypatch.setattr(app_paths, "get_data_dir", lambda: str(data_dir))
        monkeypatch.setattr(app_paths, "_program_dir", lambda: str(tmp_path / "nowhere" / "prog"))
        monkeypatch.chdir(work_dir)

        legacy = DatabaseManager(str(work_dir / "password_vault.db"))
        legacy.connect()
        legacy.create_tables()
        AuthenticationManager(legacy, EncryptionEngine()).create_account(MASTER)
        legacy.disconnect()

        path = app_paths.get_db_path()
        assert path == str(data_dir / "password_vault.db")
        assert os.path.exists(path)
        assert os.path.exists(work_dir / "password_vault.db")  # original kept
