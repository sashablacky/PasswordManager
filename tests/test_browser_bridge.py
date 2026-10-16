"""
Browser bridge: site matching, pairing, encrypted sessions, the actions the
extension uses, and the native messaging host relaying to the local socket.
"""

import json
import os
import struct
import subprocess
import sys
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from database.db_manager import DatabaseManager
from integration import protocol
from integration.protocol import ProtocolError, b64d, b64e, url_matches
from integration.service import BridgeService, BridgeUI
from managers.auth_manager import AuthenticationManager
from managers.password_manager import PasswordManager
from security.encryption import EncryptionEngine
from security.generator import PasswordGenerator

MASTER = "FirstPass11!"
HOST_SCRIPT = os.path.join(os.path.dirname(__file__), "..", "browser-extension", "native-host",
                           "securevault_host.py")


# ------------------------------------------------------------------ site matching

@pytest.mark.parametrize("entry, page", [
    ("https://example.com", "https://example.com/login"),
    ("example.com", "https://example.com/"),
    ("https://www.example.com/path", "https://example.com"),
    ("https://example.com", "https://www.example.com/"),
    ("https://google.com", "https://accounts.google.com/signin"),
    ("http://example.com", "https://example.com"),
    ("http://192.168.1.1", "http://192.168.1.1/admin"),
    ("HTTPS://Example.COM", "https://example.com"),
])
def test_url_matches(entry, page):
    assert url_matches(entry, page)


@pytest.mark.parametrize("entry, page", [
    ("https://bank.com", "https://bank.com.evil.example/"),
    ("https://bank.com", "https://evilbank.com/"),
    ("https://accounts.google.com", "https://google.com/"),
    ("https://example.com", "http://example.com/"),
    ("https://example.com", "file:///C:/example.com"),
    ("https://example.com", "moz-extension://example.com/"),
    ("", "https://example.com/"),
    ("https://example.com", ""),
    ("com", "https://example.com/"),
    ("http://1.1.1.1", "http://11.1.1.1/"),
    ("ftp://example.com", "https://example.com/"),
])
def test_url_does_not_match(entry, page):
    assert not url_matches(entry, page)


def test_frames_round_trip_and_reject_oversized():
    buffer = bytearray(protocol.encode_frame({"a": 1}) + protocol.encode_frame({"b": "ü"}))
    buffer += protocol.encode_frame({"c": 3})[:5]
    assert protocol.decode_frames(buffer) == [{"a": 1}, {"b": "ü"}]
    assert len(buffer) == 5

    with pytest.raises(ProtocolError):
        protocol.decode_frames(bytearray(struct.pack("<I", protocol.MAX_FRAME + 1)))


# ------------------------------------------------------------------ reference client

class Client:
    """Does what the browser extension does (see browser-extension/extension/crypto.js)"""

    def __init__(self, send):
        self.send = send
        self.client_id = str(uuid.uuid4())
        self.pairing_key = None
        self.cipher = None
        self.seq = 0

    def pair_start(self, browser="Firefox"):
        self._private = protocol.generate_keypair()
        reply = self.send({"type": "pair_request", "client_id": self.client_id, "browser": browser,
                           "pub": b64e(protocol.public_bytes(self._private))})
        assert reply["type"] == "pair_pending", reply
        self._secret = protocol.shared_secret(self._private, b64d(reply["pub"]))
        self._pairing = reply["pairing"]
        return protocol.pairing_code(self._secret)

    def pair_poll(self):
        reply = self.send({"type": "pair_status", "pairing": self._pairing})
        if reply["state"] == "approved":
            keys = protocol.unwrap_pairing_key(self._secret, self.client_id, reply["iv"], reply["ct"])
            self.pairing_key, self.unlock_key = keys[:32], keys[32:]
        return reply["state"]

    def unlock(self, password):
        hello = self.send({"type": "hello", "client_id": self.client_id, "nonce": b64e(os.urandom(16))})
        challenge = hello.get("unlock")
        if challenge is None:
            return hello
        private = protocol.generate_keypair()
        secret = protocol.shared_secret(private, b64d(challenge["pub"]))
        iv, ct = protocol.seal_unlock(self.unlock_key, secret, b64d(challenge["nonce"]), self.client_id,
                                      challenge["id"], password)
        return self.send({"type": "unlock", "client_id": self.client_id, "id": challenge["id"],
                          "pub": b64e(protocol.public_bytes(private)), "iv": iv, "ct": ct})

    def hello(self):
        nonce = os.urandom(protocol.NONCE_SIZE)
        reply = self.send({"type": "hello", "client_id": self.client_id, "nonce": b64e(nonce)})
        if reply.get("state") == "ready":
            self.cipher = protocol.SessionCipher(reply["session"], self.pairing_key, nonce,
                                                 b64d(reply["nonce"]), is_client=True)
            self.seq = 0
        return reply["state"]

    def call(self, action, **params):
        self.seq += 1
        reply = self.send(self.cipher.seal(dict(params, action=action), self.seq))
        if reply.get("type") == "error":
            return reply
        assert reply["seq"] == self.seq
        return self.cipher.unseal(reply)


class RecordingUI(BridgeUI):
    def __init__(self):
        self.questions = []
        self.changes = []
        self.activity = 0
        self.shown = 0
        self.unlocks = 0
        self.app = None

    def ask_pairing(self, browser, code, on_answer):
        self.questions.append((browser, code, on_answer))

    def show_app(self):
        self.shown += 1

    def entries_changed(self, message):
        self.changes.append(message)

    def user_activity(self):
        self.activity += 1

    def unlock(self, master_password):
        self.unlocks += 1
        return self.app.auth_manager.authenticate(master_password)


class FakeApp:
    def __init__(self, db):
        self.db = db
        self.encryption = EncryptionEngine()
        self.auth_manager = AuthenticationManager(db, self.encryption)
        self.password_manager = PasswordManager(db, self.encryption)
        self.generator = PasswordGenerator()


@pytest.fixture
def app():
    db = DatabaseManager(":memory:")
    db.connect()
    db.create_tables()
    fake = FakeApp(db)
    ok, message = fake.auth_manager.create_account(MASTER)
    assert ok, message
    ok, message = fake.auth_manager.authenticate(MASTER)
    assert ok, message
    yield fake
    db.disconnect()


@pytest.fixture
def ui(app):
    recording = RecordingUI()
    recording.app = app
    return recording


@pytest.fixture
def service(app, ui):
    return BridgeService(app, ui)


def paired_client(service, ui):
    client = Client(service.handle)
    code = client.pair_start()
    browser, shown_code, answer = ui.questions[-1]
    assert browser == "Firefox"
    assert shown_code == code
    assert client.pair_poll() == "pending"
    answer(True)
    assert client.pair_poll() == "approved"
    assert client.hello() == "ready"
    return client


def add_entry(app, title, url, username="alice", password="Secret-123"):
    user_id = app.auth_manager.get_current_user_id()
    return app.password_manager.add_password(user_id, title, username, password, url=url)


# ------------------------------------------------------------------ pairing and sessions

def test_locked_vault_answers_only_locked(app, service):
    app.auth_manager.logout()
    reply = service.handle({"type": "hello", "client_id": str(uuid.uuid4()), "nonce": b64e(os.urandom(16))})
    assert reply["state"] == "locked"
    assert "session" not in reply
    assert service.handle({"type": "pair_request", "client_id": str(uuid.uuid4()),
                           "pub": b64e(protocol.public_bytes(protocol.generate_keypair()))})["code"] == "locked"


def test_unknown_client_is_unpaired(service):
    client = Client(service.handle)
    assert client.hello() == "unpaired"


def test_pairing_and_session(app, service, ui):
    client = paired_client(service, ui)
    assert client.call("ping") == {"ok": True}
    # The pairing key is stored encrypted, not in plain text
    row = app.db.fetch_one("SELECT encrypted_key FROM browser_clients")
    assert client.pairing_key not in row["encrypted_key"]
    # A new session works with the stored key
    assert client.hello() == "ready"
    assert client.call("ping") == {"ok": True}


def test_denied_pairing_stores_nothing(app, service, ui):
    client = Client(service.handle)
    client.pair_start()
    ui.questions[-1][2](False)
    assert client.pair_poll() == "rejected"
    assert client.pair_poll() == "expired"
    assert client.hello() == "unpaired"


def test_only_one_pairing_question_at_a_time(service, ui):
    Client(service.handle).pair_start()
    reply = service.handle({"type": "pair_request", "client_id": str(uuid.uuid4()),
                            "pub": b64e(protocol.public_bytes(protocol.generate_keypair()))})
    assert reply == {"type": "error", "code": "busy"}
    assert len(ui.questions) == 1


def test_approval_after_lock_is_ignored(app, service, ui):
    client = Client(service.handle)
    client.pair_start()
    app.auth_manager.logout()
    service.clear_sessions()
    ui.questions[-1][2](True)
    assert client.pair_poll() == "expired"
    assert service.store.list(app.auth_manager.get_current_user_id() or 1) == []


def test_replayed_message_is_rejected(service, ui):
    client = paired_client(service, ui)
    client.seq += 1
    message = client.cipher.seal({"action": "ping"}, client.seq)
    assert client.cipher.unseal(service.handle(dict(message)))["ok"]
    assert service.handle(dict(message)) == {"type": "error", "code": "bad_message"}


def test_tampered_message_is_rejected(service, ui):
    client = paired_client(service, ui)
    message = client.cipher.seal({"action": "ping"}, 1)
    ct = bytearray(b64d(message["ct"]))
    ct[0] ^= 1
    message["ct"] = b64e(bytes(ct))
    assert service.handle(message) == {"type": "error", "code": "bad_message"}


def test_other_client_key_cannot_use_session(service, ui):
    client = paired_client(service, ui)
    intruder = protocol.SessionCipher(client.cipher.session_id, os.urandom(32), os.urandom(16), os.urandom(16),
                                      is_client=True)
    assert service.handle(intruder.seal({"action": "ping"}, 1)) == {"type": "error", "code": "bad_message"}


def test_lock_ends_sessions(app, service, ui):
    client = paired_client(service, ui)
    app.auth_manager.logout()
    service.clear_sessions()
    assert client.call("ping") == {"type": "error", "code": "session_expired"}
    assert client.hello() == "locked"


def test_pairing_survives_master_password_change(app, service, ui):
    client = paired_client(service, ui)
    ok, message = app.auth_manager.change_master_password(MASTER, "SecondPass22@")
    assert ok, message
    assert client.hello() == "ready"
    assert client.call("ping") == {"ok": True}


def test_forgotten_client_is_unpaired(app, service, ui):
    client = paired_client(service, ui)
    service.store.remove_all(app.auth_manager.get_current_user_id())
    service.clear_sessions()
    assert client.hello() == "unpaired"


def test_show_app_needs_no_session(service, ui):
    assert service.handle({"type": "show_app"}) == {"type": "ok"}
    assert ui.shown == 1


def test_garbage_is_rejected(service):
    assert service.handle({"type": "nope"})["code"] == "unknown_type"
    assert service.handle({"type": "hello", "client_id": 5})["state"] == "unpaired"
    assert service.handle({"type": "enc", "session": "x", "seq": 1})["code"] == "session_expired"
    assert service.handle({"type": "pair_request", "client_id": "not-a-uuid", "pub": "AA=="})["code"] == "bad_message"


# ------------------------------------------------------------------ actions

def test_get_logins_returns_only_matching_sites(app, service, ui):
    add_entry(app, "Example", "https://example.com", "alice")
    add_entry(app, "Example 2", "https://login.example.com", "bob")
    add_entry(app, "Evil", "https://example.com.evil.test", "mallory")
    add_entry(app, "Other", "https://other.org", "carol")
    client = paired_client(service, ui)

    reply = client.call("get_logins", url="https://login.example.com/signin?x=1")
    assert reply["site"] == "login.example.com"
    assert sorted(l["username"] for l in reply["logins"]) == ["alice", "bob"]
    assert all("password" not in l for l in reply["logins"])

    assert client.call("get_logins", url="https://example.com/")["logins"][0]["username"] == "alice"
    assert client.call("get_logins", url="https://unknown.test/")["logins"] == []


def test_get_login_checks_the_site(app, service, ui):
    entry_id = add_entry(app, "Example", "https://example.com", "alice", "Pw-example-1")
    client = paired_client(service, ui)

    reply = client.call("get_login", id=entry_id, url="https://example.com/login")
    assert reply == {"id": entry_id, "username": "alice", "password": "Pw-example-1"}
    assert ui.activity == 1

    # The same entry requested from another site is refused
    assert client.call("get_login", id=entry_id, url="https://evil.test/") == {"error": "not_found"}


def test_check_save_and_update_login(app, service, ui):
    client = paired_client(service, ui)
    url = "https://shop.example.com/account/login"

    assert client.call("check_login", url=url, username="alice", password="Pw-1-aaaa") == \
        {"state": "new", "site": "shop.example.com"}

    saved = client.call("save_login", url=url, username="alice", password="Pw-1-aaaa")
    entry = app.password_manager.get_password(saved["id"], app.auth_manager.get_current_user_id())
    assert (entry.title, entry.url, entry.username, entry.password) == \
        ("shop.example.com", "https://shop.example.com", "alice", "Pw-1-aaaa")
    assert ui.changes

    assert client.call("check_login", url=url, username="alice", password="Pw-1-aaaa") == {"state": "same"}
    changed = client.call("check_login", url=url, username="alice", password="Pw-2-bbbb")
    assert changed == {"state": "changed", "id": saved["id"]}

    client.call("update_login", id=saved["id"], url=url, password="Pw-2-bbbb")
    entry = app.password_manager.get_password(saved["id"], app.auth_manager.get_current_user_id())
    assert entry.password == "Pw-2-bbbb"

    # An entry can't be updated from a page of another site
    assert client.call("update_login", id=saved["id"], url="https://evil.test/", password="x") == \
        {"error": "not_found"}


def test_save_login_refuses_non_web_pages(service, ui):
    client = paired_client(service, ui)
    assert client.call("save_login", url="file:///etc/passwd", password="x") == {"error": "bad_url"}
    assert client.call("save_login", url="https://example.com", password="") == {"error": "missing_password"}


def test_generate_password(service, ui):
    client = paired_client(service, ui)
    password = client.call("generate_password")["password"]
    assert len(password) == 20
    assert client.call("generate_password", length=32)["password"] != password


def test_unknown_action(service, ui):
    client = paired_client(service, ui)
    assert client.call("export_everything") == {"error": "unknown_action"}


# ------------------------------------------------------------------ socket server and native host

@pytest.fixture
def endpoint_name():
    # Set for every test in conftest.py, so no test touches the real program's socket
    return os.environ["SECUREVAULT_BRIDGE_ENDPOINT"]


def run_host(qtbot, messages, endpoint):
    """Run the native host like Firefox does; returns its replies"""
    stdin = b"".join(_native_frame(m) for m in messages)
    env = dict(os.environ, SECUREVAULT_BRIDGE_ENDPOINT=endpoint)
    process = subprocess.Popen([sys.executable, "-u", HOST_SCRIPT], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, env=env)
    process.stdin.write(stdin)
    process.stdin.close()
    # The server runs in this thread's event loop, so keep it turning while the host works
    qtbot.waitUntil(lambda: process.poll() is not None, timeout=15000)
    output = process.stdout.read()
    replies = []
    while output:
        (length,) = struct.unpack("<I", output[:4])
        replies.append(json.loads(output[4:4 + length]))
        output = output[4 + length:]
    return replies


def _native_frame(message):
    body = json.dumps(message).encode("utf-8")
    return struct.pack("<I", len(body)) + body


def test_native_host_without_program(qtbot, endpoint_name):
    assert run_host(qtbot, [{"type": "hello"}], endpoint_name) == [{"type": "error", "code": "app_not_running"}]


def test_native_host_relays_to_server(qtbot, app, service, ui, endpoint_name):
    from integration.server import BridgeServer

    server = BridgeServer(service)
    assert server.start(endpoint_name)
    try:
        client = Client(lambda m: run_host(qtbot, [m], endpoint_name)[0])
        client.pair_start()
        ui.questions[-1][2](True)
        assert client.pair_poll() == "approved"
        assert client.hello() == "ready"
        add_entry(app, "Example", "https://example.com", "alice")
        assert client.call("get_logins", url="https://example.com")["logins"][0]["username"] == "alice"

        # Several messages through one host process (connectNative keeps it running)
        replies = run_host(qtbot, [{"type": "show_app"}, {"type": "show_app"}], endpoint_name)
        assert replies == [{"type": "ok"}, {"type": "ok"}]
    finally:
        server.stop()


def test_second_server_does_not_steal_the_endpoint(qtbot, service, endpoint_name):
    from integration.server import BridgeServer

    first = BridgeServer(service)
    assert first.start(endpoint_name)
    second = BridgeServer(service)
    try:
        assert not second.start(endpoint_name)
        assert first.is_listening()
    finally:
        second.stop()
        first.stop()


def test_host_and_program_agree_on_the_endpoint(monkeypatch, tmp_path):
    import importlib.util
    from integration.endpoint import default_endpoint, ENDPOINT_ENV

    monkeypatch.delenv(ENDPOINT_ENV, raising=False)
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    spec = importlib.util.spec_from_file_location("securevault_host", HOST_SCRIPT)
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)

    program = default_endpoint()
    if sys.platform == "win32":
        program = "\\\\.\\pipe\\" + program
    assert host.endpoint() == program


# ------------------------------------------------------------------ unlocking from the browser

def test_unlock_from_browser(app, service, ui):
    client = paired_client(service, ui)
    app.auth_manager.logout()
    service.clear_sessions()
    assert client.hello() == "locked"

    reply = client.unlock("wrong password")
    assert reply["type"] == "unlock_result" and reply["ok"] is False
    assert "attempts remaining" in reply["message"]
    assert not app.auth_manager.is_logged_in()

    assert client.unlock(MASTER) == {"type": "unlock_result", "ok": True}
    assert app.auth_manager.is_logged_in()
    assert client.hello() == "ready"


def test_unlock_offered_only_to_paired_browsers(app, service, ui):
    paired_client(service, ui)
    app.auth_manager.logout()
    stranger = {"type": "hello", "client_id": str(uuid.uuid4()), "nonce": b64e(os.urandom(16))}
    assert "unlock" not in service.handle(stranger)
    assert "unlock" not in service.handle({"type": "hello", "client_id": None})


def test_unlock_needs_the_unlock_key(app, service, ui):
    client = paired_client(service, ui)
    app.auth_manager.logout()
    client.unlock_key = os.urandom(32)
    assert client.unlock(MASTER) == {"type": "error", "code": "bad_message"}
    assert not app.auth_manager.is_logged_in()
    assert ui.unlocks == 0


def test_unlock_challenge_is_single_use(app, service, ui):
    client = paired_client(service, ui)
    app.auth_manager.logout()
    sent = []
    original = client.send
    client.send = lambda m: (sent.append(m), original(m))[1]
    assert client.unlock(MASTER)["ok"]
    app.auth_manager.logout()
    assert service.handle(sent[-1]) == {"type": "error", "code": "unlock_expired"}
    assert not app.auth_manager.is_logged_in()


def test_unlock_attempts_count_towards_lockout(app, service, ui):
    client = paired_client(service, ui)
    app.auth_manager.logout()
    for _ in range(app.auth_manager.MAX_FAILED_ATTEMPTS):
        client.unlock("wrong password")
    reply = client.unlock(MASTER)
    assert reply["ok"] is False and "locked" in reply["message"].lower()
    assert not app.auth_manager.is_logged_in()


def test_unlock_key_column_added_to_old_table(app, service):
    app.db.execute_query("DROP TABLE IF EXISTS browser_clients")
    app.db.execute_query("""CREATE TABLE browser_clients (client_id TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
                            browser TEXT NOT NULL DEFAULT '', encrypted_key BLOB NOT NULL,
                            created_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, last_used TIMESTAMP)""")
    assert service.store.get_unlock_key("x") is None
    columns = {row["name"] for row in app.db.fetch_all("PRAGMA table_info(browser_clients)")}
    assert "unlock_key" in columns
