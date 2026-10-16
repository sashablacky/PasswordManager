"""
What the program answers to the browser extension (no sockets, no widgets).

BridgeService.handle() takes one decoded message and returns the reply. The
transport (integration.server) and the user interface (the pairing question,
notifications) are plugged in from outside, so this module can be tested on
its own.

Without a session only these requests are answered: whether the vault is
locked, a pairing request (only while it is unlocked, and only with the user's
consent in the program), "bring the program to the front", and unlocking with
the master password (only from a paired browser, encrypted, and with the same
limit on failed attempts as the login window). Everything that
touches entries needs an encrypted session of a paired browser, and a reply
never contains more than the entries of the site the browser is on.
"""

import logging
import os
import secrets
import time
import uuid
from typing import Callable, Dict, Optional, Tuple

from integration import protocol
from integration.protocol import ProtocolError, b64d, b64e
from integration.store import BrowserClientStore

logger = logging.getLogger(__name__)

# How long an unanswered pairing request and an idle session stay valid
PAIRING_TIMEOUT_SECONDS = 180
SESSION_IDLE_SECONDS = 8 * 3600
MAX_SESSIONS = 32
UNLOCK_CHALLENGE_SECONDS = 300
MAX_UNLOCK_CHALLENGES = 8

MAX_FIELD_LENGTH = 4096
GENERATED_LENGTH = 20


class BridgeUI:
    """What the service asks of the user interface; the defaults do nothing"""

    def ask_pairing(self, browser: str, code: str, on_answer: Callable[[bool], None]) -> None:
        """Ask whether the browser may connect; call on_answer(True/False) later"""
        on_answer(False)

    def show_app(self) -> None:
        pass

    def unlock(self, master_password: str) -> Tuple[bool, str]:
        """Unlock the vault with the master password typed into the extension"""
        return False, "Unlocking from the browser is not available"

    def entries_changed(self, message: str) -> None:
        pass

    def user_activity(self) -> None:
        """An explicit action in the browser (fill, save): counts as activity for auto-lock"""


class _Pairing:
    def __init__(self, client_id: str, browser: str, secret: bytes):
        self.client_id = client_id
        self.browser = browser
        self.secret = secret
        self.state = "pending"  # pending, approved, rejected
        self.pairing_key: Optional[bytes] = None
        self.unlock_key: Optional[bytes] = None
        self.created = time.monotonic()


class _UnlockChallenge:
    def __init__(self, client_id: str):
        self.client_id = client_id
        self.private_key = protocol.generate_keypair()
        self.nonce = os.urandom(protocol.NONCE_SIZE)
        self.created = time.monotonic()


class _Session:
    def __init__(self, client_id: str, cipher: protocol.SessionCipher):
        self.client_id = client_id
        self.cipher = cipher
        self.last_used = time.monotonic()


class BridgeService:

    def __init__(self, app, ui: Optional[BridgeUI] = None):
        """app: object with auth_manager, password_manager, generator, db, encryption"""
        self.app = app
        self.ui = ui or BridgeUI()
        self.store = BrowserClientStore(app.db, app.encryption)
        self._sessions: Dict[str, _Session] = {}
        self._pairings: Dict[str, _Pairing] = {}
        self._unlocks: Dict[str, _UnlockChallenge] = {}

    # ------------------------------------------------------------ state

    def _user_id(self) -> Optional[int]:
        if not self.app.auth_manager.is_logged_in():
            return None
        return self.app.auth_manager.get_current_user_id()

    def clear_sessions(self) -> None:
        """Forget every session and pending pairing (the vault was locked)"""
        self._sessions.clear()
        self._pairings.clear()
        self._unlocks.clear()

    def forget_client(self, client_id: str) -> None:
        for sid in [sid for sid, s in self._sessions.items() if s.client_id == client_id]:
            del self._sessions[sid]

    def _expire(self) -> None:
        now = time.monotonic()
        for sid in [sid for sid, s in self._sessions.items() if now - s.last_used > SESSION_IDLE_SECONDS]:
            del self._sessions[sid]
        for pid in [pid for pid, p in self._pairings.items() if now - p.created > PAIRING_TIMEOUT_SECONDS]:
            del self._pairings[pid]
        for uid in [uid for uid, u in self._unlocks.items() if now - u.created > UNLOCK_CHALLENGE_SECONDS]:
            del self._unlocks[uid]

    # ------------------------------------------------------------ entry point

    def handle(self, message: dict) -> dict:
        try:
            self._expire()
            kind = message.get("type")
            if kind == "hello":
                return self._hello(message)
            if kind == "enc":
                return self._encrypted(message)
            if kind == "pair_request":
                return self._pair_request(message)
            if kind == "pair_status":
                return self._pair_status(message)
            if kind == "unlock":
                return self._unlock(message)
            if kind == "show_app":
                self.ui.show_app()
                return {"type": "ok"}
            return _error("unknown_type")
        except ProtocolError as e:
            logger.warning(f"Browser bridge: rejected message ({e})")
            return _error("bad_message")
        except Exception:
            logger.exception("Browser bridge: request failed")
            return _error("internal")

    # ------------------------------------------------------------ unauthenticated

    def _hello(self, message: dict) -> dict:
        reply = {"type": "hello", "app": protocol.APP_ID, "version": protocol.PROTOCOL_VERSION}
        user_id = self._user_id()
        client_id = message.get("client_id")
        if user_id is None:
            reply["state"] = "locked"
            challenge = self._new_unlock_challenge(client_id)
            if challenge:
                reply["unlock"] = challenge
            return reply

        pairing_key = self.store.get_key(user_id, client_id) if client_id else None
        if pairing_key is None:
            reply["state"] = "unpaired"
            return reply

        client_nonce = b64d(message.get("nonce"), protocol.NONCE_SIZE)
        server_nonce = os.urandom(protocol.NONCE_SIZE)
        session_id = secrets.token_urlsafe(16)
        cipher = protocol.SessionCipher(session_id, pairing_key, client_nonce, server_nonce)

        if len(self._sessions) >= MAX_SESSIONS:
            oldest = min(self._sessions, key=lambda sid: self._sessions[sid].last_used)
            del self._sessions[oldest]
        self._sessions[session_id] = _Session(client_id, cipher)
        self.store.touch(client_id)

        reply.update(state="ready", session=session_id, nonce=b64e(server_nonce))
        return reply

    def _new_unlock_challenge(self, client_id) -> Optional[dict]:
        """A fresh key for sending the master password, offered only to paired browsers"""
        if self.store.get_unlock_key(client_id) is None:
            return None
        if len(self._unlocks) >= MAX_UNLOCK_CHALLENGES:
            oldest = min(self._unlocks, key=lambda uid: self._unlocks[uid].created)
            del self._unlocks[oldest]
        challenge_id = secrets.token_urlsafe(16)
        challenge = _UnlockChallenge(client_id)
        self._unlocks[challenge_id] = challenge
        return {"id": challenge_id, "pub": b64e(protocol.public_bytes(challenge.private_key)),
                "nonce": b64e(challenge.nonce)}

    def _unlock(self, message: dict) -> dict:
        challenge_id = message.get("id")
        challenge = self._unlocks.pop(challenge_id, None) if isinstance(challenge_id, str) else None
        client_id = message.get("client_id")
        if challenge is None or challenge.client_id != client_id:
            return _error("unlock_expired")
        unlock_key = self.store.get_unlock_key(client_id)
        if unlock_key is None:
            return _error("unpaired")
        secret = protocol.shared_secret(challenge.private_key, b64d(message.get("pub"), 65))
        password = protocol.open_unlock(unlock_key, secret, challenge.nonce, client_id, challenge_id,
                                        message.get("iv"), message.get("ct"))
        if self._user_id() is not None:
            return {"type": "unlock_result", "ok": True}
        ok, text = self.ui.unlock(password)
        reply = {"type": "unlock_result", "ok": bool(ok)}
        if not ok:
            reply["message"] = text
        return reply

    def _pair_request(self, message: dict) -> dict:
        user_id = self._user_id()
        if user_id is None:
            return _error("locked")
        if any(p.state == "pending" for p in self._pairings.values()):
            # One question at a time: a flood of requests must not bury the user in dialogs
            return _error("busy")

        client_id = message.get("client_id")
        try:
            client_id = str(uuid.UUID(str(client_id)))
        except ValueError:
            raise ProtocolError("client_id must be a UUID")
        browser = str(message.get("browser") or "Browser")[:40]
        peer_public = b64d(message.get("pub"), 65)

        private_key = protocol.generate_keypair()
        secret = protocol.shared_secret(private_key, peer_public)
        pairing_id = secrets.token_urlsafe(16)
        pairing = _Pairing(client_id, browser, secret)
        self._pairings[pairing_id] = pairing

        def on_answer(allowed: bool, pid=pairing_id, uid=user_id):
            current = self._pairings.get(pid)
            if current is None or current.state != "pending":
                return
            if allowed and self._user_id() == uid:
                current.pairing_key = os.urandom(protocol.KEY_SIZE)
                current.unlock_key = os.urandom(protocol.KEY_SIZE)
                self.store.add(uid, current.client_id, current.browser, current.pairing_key, current.unlock_key)
                self.forget_client(current.client_id)
                current.state = "approved"
                logger.warning(f"Browser paired: {current.browser}")
            else:
                current.state = "rejected"

        self.ui.ask_pairing(browser, protocol.pairing_code(secret), on_answer)
        return {"type": "pair_pending", "pairing": pairing_id, "pub": b64e(protocol.public_bytes(private_key))}

    def _pair_status(self, message: dict) -> dict:
        pairing_id = message.get("pairing")
        pairing = self._pairings.get(pairing_id) if isinstance(pairing_id, str) else None
        if pairing is None:
            return {"type": "pair_status", "state": "expired"}
        if pairing.state == "pending":
            return {"type": "pair_status", "state": "pending"}
        # The answer is handed out once
        del self._pairings[pairing_id]
        if pairing.state == "rejected":
            return {"type": "pair_status", "state": "rejected"}
        # The extension gets both keys at once: the pairing key, then the unlock key
        iv, ct = protocol.wrap_pairing_key(pairing.secret, pairing.client_id,
                                           pairing.pairing_key + pairing.unlock_key)
        return {"type": "pair_status", "state": "approved", "iv": iv, "ct": ct}

    # ------------------------------------------------------------ encrypted

    def _encrypted(self, message: dict) -> dict:
        session_id = message.get("session")
        session = self._sessions.get(session_id) if isinstance(session_id, str) else None
        user_id = self._user_id()
        if session is None or user_id is None:
            return _error("session_expired")

        request = session.cipher.unseal(message)
        session.last_used = time.monotonic()
        seq = message["seq"]

        action = request.get("action")
        handler = self.ACTIONS.get(action)
        if handler is None:
            result = {"error": "unknown_action"}
        else:
            try:
                result = handler(self, user_id, request)
            except ProtocolError:
                raise
            except _RequestError as e:
                result = {"error": str(e)}
        return session.cipher.seal(result, seq)

    # ------------------------------------------------------------ actions

    def _entries_for(self, user_id: int, url: str):
        return [p for p in self.app.password_manager.get_all_passwords(user_id)
                if protocol.url_matches(p.url, url)]

    def _find_entry(self, user_id: int, request: dict):
        url = _text(request, "url")
        entry_id = request.get("id")
        for entry in self._entries_for(user_id, url):
            if entry.password_id == entry_id:
                return entry, url
        raise _RequestError("not_found")

    def _get_logins(self, user_id: int, request: dict) -> dict:
        url = _text(request, "url")
        entries = self._entries_for(user_id, url)
        entries.sort(key=lambda p: (not p.is_favorite, p.title.lower()))
        return {"site": protocol.site_host(url),
                "logins": [{"id": p.password_id, "title": p.title, "username": p.username} for p in entries]}

    def _get_login(self, user_id: int, request: dict) -> dict:
        entry, _ = self._find_entry(user_id, request)
        self.app.password_manager.update_last_used(entry.password_id, user_id)
        self.ui.user_activity()
        return {"id": entry.password_id, "username": entry.username, "password": entry.password}

    def _check_login(self, user_id: int, request: dict) -> dict:
        url = _text(request, "url")
        username = _text(request, "username", required=False)
        password = _text(request, "password")
        same_user = [p for p in self._entries_for(user_id, url) if p.username == username]
        if any(p.password == password for p in same_user):
            return {"state": "same"}
        if same_user:
            return {"state": "changed", "id": same_user[0].password_id}
        return {"state": "new", "site": protocol.site_host(url)}

    def _save_login(self, user_id: int, request: dict) -> dict:
        url = _text(request, "url")
        site = protocol.site_host(url)
        if not site or not protocol.url_matches(protocol.page_origin(url), url):
            raise _RequestError("bad_url")
        username = _text(request, "username", required=False)
        password = _text(request, "password")
        title = _text(request, "title", required=False) or site
        entry_id = self.app.password_manager.add_password(
            user_id, title, username, password, url=protocol.page_origin(url))
        self.ui.user_activity()
        self.ui.entries_changed(f"Saved login for {site} from the browser")
        return {"id": entry_id}

    def _update_login(self, user_id: int, request: dict) -> dict:
        entry, url = self._find_entry(user_id, request)
        password = _text(request, "password")
        self.app.password_manager.update_password(entry.password_id, user_id, password=password)
        self.ui.user_activity()
        self.ui.entries_changed(f"Updated password for {protocol.site_host(url)} from the browser")
        return {"id": entry.password_id}

    def _generate(self, user_id: int, request: dict) -> dict:
        from security.generator import GeneratorOptions
        length = request.get("length")
        if not isinstance(length, int) or isinstance(length, bool):
            length = GENERATED_LENGTH
        self.ui.user_activity()
        return {"password": self.app.generator.generate(GeneratorOptions(length=length))}

    def _ping(self, user_id: int, request: dict) -> dict:
        return {"ok": True}

    ACTIONS = {
        "ping": _ping,
        "get_logins": _get_logins,
        "get_login": _get_login,
        "check_login": _check_login,
        "save_login": _save_login,
        "update_login": _update_login,
        "generate_password": _generate,
    }


class _RequestError(Exception):
    """A request the program refuses; sent back to the extension as {"error": ...}"""


def _error(code: str) -> dict:
    return {"type": "error", "code": code}


def _text(request: dict, key: str, required: bool = True) -> str:
    value = request.get(key, "")
    if value is None:
        value = ""
    if not isinstance(value, str) or len(value) > MAX_FIELD_LENGTH:
        raise _RequestError(f"bad_{key}")
    if required and not value:
        raise _RequestError(f"missing_{key}")
    return value
