"""
Vault format 2 (risks 2 and 6-9 of the security review) and the upgrade of
vaults created by older versions
"""

import hashlib
import json
import sqlite3

import pytest

from database.db_manager import DatabaseManager
from security.encryption import EncryptionEngine, DecryptionError, record_aad
from security.kdf import KeyDerivationFunction, VAULT_FORMAT_CURRENT, VAULT_FORMAT_LEGACY
from security.breach_detector import BreachDetector
from managers.auth_manager import AuthenticationManager
from managers.password_manager import PasswordManager

MASTER = "FirstPass11!"


def open_db(path):
    db = DatabaseManager(str(path))
    db.connect()
    db.create_tables()
    return db


def make_legacy_vault(path, entries):
    """A vault as version 1.1 and older wrote it: format 1, no associated data"""
    db = open_db(path)
    kdf = KeyDerivationFunction()
    verifier, salt = kdf.hash_password(MASTER)
    db.execute_query(
        "INSERT INTO users (master_password_hash, salt, kdf_iterations, kdf_version) VALUES (?, ?, ?, ?)",
        (verifier, salt, kdf.TIME_COST, VAULT_FORMAT_LEGACY)
    )
    user_id = db.fetch_one("SELECT user_id FROM users")['user_id']

    engine = EncryptionEngine()
    engine.set_key(kdf.derive_key(MASTER, salt))
    engine.bind_records = False
    pm = PasswordManager(db, engine)
    ids = [pm.add_password(user_id, title, "user", password) for title, password in entries]
    engine.clear_key()
    return db, user_id, ids


@pytest.fixture
def vault(tmp_path):
    db = open_db(tmp_path / "vault.db")
    encryption = EncryptionEngine()
    auth = AuthenticationManager(db, encryption)
    assert auth.create_account(MASTER)[0]
    assert auth.authenticate(MASTER)[0]
    yield db, auth, PasswordManager(db, encryption), auth.get_current_user_id()
    db.disconnect()


class TestNewVault:
    def test_new_account_uses_current_format_and_stores_kdf_parameters(self, vault):
        db, auth, pm, uid = vault
        user = db.fetch_one("SELECT * FROM users")
        kdf = KeyDerivationFunction()
        assert user['kdf_version'] == VAULT_FORMAT_CURRENT
        assert user['kdf_iterations'] == kdf.TIME_COST
        assert user['kdf_memory_cost'] == kdf.MEMORY_COST
        assert user['kdf_parallelism'] == kdf.PARALLELISM

    def test_verifier_is_not_derived_from_the_encryption_key(self, vault):
        db, auth, pm, uid = vault
        user = db.fetch_one("SELECT * FROM users")
        key = bytes(auth.encryption.copy_key())
        argon_output = KeyDerivationFunction().derive_key(MASTER, user['salt'])

        assert key != argon_output
        assert user['master_password_hash'] != hashlib.sha256(key).hexdigest()
        assert user['master_password_hash'] != hashlib.sha256(argon_output).hexdigest()

    def test_vault_opens_after_default_kdf_parameters_change(self, vault, monkeypatch):
        db, auth, pm, uid = vault
        pid = pm.add_password(uid, "Bank", "bob", "Secret123!")
        auth.logout()

        # A later version raises the defaults: the stored parameters must still be used
        monkeypatch.setattr(KeyDerivationFunction, "MEMORY_COST", 32768)
        monkeypatch.setattr(KeyDerivationFunction, "PARALLELISM", 2)
        assert auth.authenticate(MASTER)[0]
        assert pm.get_password(pid, uid).password == "Secret123!"


class TestRecordBinding:
    def test_ciphertext_moved_to_another_entry_does_not_decrypt(self, vault):
        db, auth, pm, uid = vault
        a = pm.add_password(uid, "A", "alice", "PasswordA1!")
        b = pm.add_password(uid, "B", "bob", "PasswordB2!")

        stolen = db.fetch_one("SELECT encrypted_password FROM passwords WHERE password_id = ?", (a,))
        db.execute_query("UPDATE passwords SET encrypted_password = ? WHERE password_id = ?",
                         (stolen['encrypted_password'], b))

        with pytest.raises(Exception):
            pm.get_password(b, uid)
        assert pm.get_password(a, uid).password == "PasswordA1!"

    def test_ciphertext_moved_to_another_field_does_not_decrypt(self, vault):
        db, auth, pm, uid = vault
        pid = pm.add_password(uid, "A", "alice", "PasswordA1!", notes="note")
        row = db.fetch_one("SELECT * FROM passwords WHERE password_id = ?", (pid,))

        with pytest.raises(DecryptionError):
            auth.encryption.decrypt(row['encrypted_password'],
                                    record_aad(auth.encryption, pid, "encrypted_notes"))


class TestLegacyUpgrade:
    def test_legacy_vault_is_upgraded_at_login(self, tmp_path):
        db, uid, ids = make_legacy_vault(tmp_path / "old.db", [("Bank", "Secret123!"), ("Mail", "Other456!")])
        encryption = EncryptionEngine()
        auth = AuthenticationManager(db, encryption)
        pm = PasswordManager(db, encryption)

        assert auth.authenticate(MASTER)[0]
        assert auth.upgrade_error is None

        user = db.fetch_one("SELECT * FROM users")
        assert user['kdf_version'] == VAULT_FORMAT_CURRENT
        assert encryption.bind_records
        assert [pm.get_password(i, uid).password for i in ids] == ["Secret123!", "Other456!"]
        assert pm.get_password(ids[0], uid).title == "Bank"

        # Next login uses the new format
        auth.logout()
        assert auth.authenticate(MASTER)[0]
        assert pm.get_password(ids[1], uid).password == "Other456!"
        assert not auth.authenticate("WrongPass99!")[0]
        db.disconnect()

    def test_failed_upgrade_keeps_legacy_vault_working(self, tmp_path):
        db, uid, ids = make_legacy_vault(tmp_path / "old.db", [("Bank", "Secret123!"), ("Mail", "Other456!")])
        # One damaged entry: the upgrade can't re-encrypt it, so nothing may change
        db.execute_query("UPDATE passwords SET encrypted_notes = ? WHERE password_id = ?",
                         (b"x" * 40, ids[1]))
        before = db.fetch_one("SELECT * FROM users")

        encryption = EncryptionEngine()
        auth = AuthenticationManager(db, encryption)
        pm = PasswordManager(db, encryption)

        assert auth.authenticate(MASTER)[0]
        assert auth.upgrade_error

        after = db.fetch_one("SELECT * FROM users")
        assert after['kdf_version'] == VAULT_FORMAT_LEGACY
        assert after['master_password_hash'] == before['master_password_hash']
        assert not encryption.bind_records
        assert pm.get_password(ids[0], uid).password == "Secret123!"
        db.disconnect()

    def test_change_master_password_on_legacy_vault_converts_it(self, tmp_path):
        db, uid, ids = make_legacy_vault(tmp_path / "old.db", [("Bank", "Secret123!")])
        db.execute_query("UPDATE passwords SET encrypted_notes = ? WHERE password_id = ?",
                         (b"x" * 40, ids[0]))
        encryption = EncryptionEngine()
        auth = AuthenticationManager(db, encryption)
        assert auth.authenticate(MASTER)[0]

        # The damaged field blocks the change too, and nothing is lost
        ok, _ = auth.change_master_password(MASTER, "SecondPass22@")
        assert not ok
        db.execute_query("UPDATE passwords SET encrypted_notes = NULL WHERE password_id = ?", (ids[0],))

        ok, msg = auth.change_master_password(MASTER, "SecondPass22@")
        assert ok, msg
        auth.logout()
        assert auth.authenticate("SecondPass22@")[0]
        assert db.fetch_one("SELECT kdf_version FROM users")['kdf_version'] == VAULT_FORMAT_CURRENT
        assert PasswordManager(db, encryption).get_password(ids[0], uid).password == "Secret123!"
        db.disconnect()


class TestPlaintextMetadataScrub:
    def test_old_audit_titles_and_scores_are_removed(self, tmp_path):
        path = tmp_path / "old.db"
        db, uid, ids = make_legacy_vault(path, [("Bank", "Secret123!")])
        db.execute_query(
            "INSERT INTO audit_log (user_id, timestamp, action_type, details_json) VALUES (?, '2025-01-01', ?, ?)",
            (uid, "PASSWORD_ADDED", json.dumps({"password_id": ids[0], "title": "My Bank", "strength": 40}))
        )
        db.execute_query("UPDATE passwords SET strength_score = 40")
        db.execute_query(
            "INSERT INTO breach_checks (password_id, user_id, breach_found, breach_count, risk_level) "
            "VALUES (?, ?, 1, 500, 'high')", (ids[0], uid)
        )
        db.disconnect()

        db = open_db(path)  # what the app does at start
        db.disconnect()

        raw = sqlite3.connect(str(path))
        details = [json.loads(r[0]) for r in raw.execute("SELECT details_json FROM audit_log")]
        assert all('title' not in d and 'strength' not in d for d in details)
        assert raw.execute("SELECT MAX(strength_score) FROM passwords").fetchone()[0] == 0
        assert raw.execute("SELECT COUNT(*) FROM breach_checks").fetchone()[0] == 0
        raw.close()
        # VACUUM removed the old text from the file itself
        assert b"My Bank" not in path.read_bytes()


class TestEncryptedBreachResults:
    def test_breach_result_is_stored_encrypted(self, vault):
        db, auth, pm, uid = vault
        pid = pm.add_password(uid, "Bank", "bob", "Secret123!")
        detector = BreachDetector(db, auth.encryption)
        detector._store_breach_result(uid, pid, {
            'breach_found': True, 'breach_count': 1234, 'risk_level': 'high',
            'sources': ['x'], 'recommendations': ['change it'],
        })

        row = db.fetch_one("SELECT * FROM breach_checks WHERE password_id = ?", (pid,))
        assert row['breach_found'] == 0 and row['breach_count'] == 0
        assert row['risk_level'] == 'unknown'
        assert row['encrypted_result']

        compromised = detector.get_compromised_passwords(uid)
        assert [(c['password_id'], c['breach_count'], c['risk_level']) for c in compromised] == [(pid, 1234, 'high')]
        stats = detector.get_breach_statistics(uid)
        assert stats['compromised'] == 1 and stats['risk_levels'] == {'high': 1}

        # Survives a master password change
        assert auth.change_master_password(MASTER, "SecondPass22@")[0]
        assert detector.get_compromised_passwords(uid)[0]['breach_count'] == 1234

    def test_breach_sources_are_not_guessed_from_the_password(self):
        sources = BreachDetector()._identify_breach_sources("myfacebook2020", 50)
        assert not any("Facebook" in s for s in sources)


class TestKeyWiping:
    def test_clear_key_overwrites_the_key_buffer(self):
        engine = EncryptionEngine()
        engine.set_key(b"k" * 32)
        buffer = engine._key
        engine.clear_key()
        assert buffer == bytearray(32)
        assert not engine.is_key_set()

    def test_logout_wipes_the_key(self, vault):
        db, auth, pm, uid = vault
        buffer = auth.encryption._key
        auth.logout()
        assert buffer == bytearray(len(buffer))
