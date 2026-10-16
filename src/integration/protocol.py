"""
Wire format and cryptography of the browser bridge (no Qt, no database).

The browser extension and the program talk through a small relay (the native
messaging host in Firefox, the Swift handler in Safari). The relay only passes
messages along, so everything that matters is protected end to end here:

* Pairing: the extension sends a fresh P-256 public key, the program answers
  with its own; both derive the same secret (ECDH). A six-digit code derived
  from it is shown in the browser and in the program, the user allows the
  connection in the program, and the program sends a random 32-byte pairing
  key to the extension, encrypted with the shared secret.
* Sessions: each session starts with two random nonces; the pairing key and
  the nonces give one AES-256-GCM key per direction (HKDF-SHA256). Every
  message carries a sequence number that must grow, so an old message can't
  be replayed.

The same constructions are implemented with WebCrypto in
browser-extension/extension/crypto.js; both sides must stay in sync.
"""

import base64
import ipaddress
import json
import os
import struct
from typing import Optional, Tuple
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL_VERSION = 1
APP_ID = "SecureVault"

# Name of the native messaging host registered for Firefox
HOST_NAME = "com.securevault.bridge"

KEY_SIZE = 32
NONCE_SIZE = 16
IV_SIZE = 12

# A frame is a 4-byte little-endian length followed by UTF-8 JSON, the same as
# native messaging itself. Requests are small; this only stops a broken client
# from making the program allocate a huge buffer.
MAX_FRAME = 1024 * 1024

INFO_PAIR_CODE = b"securevault-pair-code"
INFO_PAIR_WRAP = b"securevault-pair-wrap"
INFO_SESSION_C2S = b"securevault-session-c2s"
INFO_SESSION_S2C = b"securevault-session-s2c"


class ProtocolError(Exception):
    """A message that is malformed, fails authentication or arrives out of order"""


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text, expected_len: Optional[int] = None) -> bytes:
    if not isinstance(text, str):
        raise ProtocolError("expected base64 text")
    try:
        data = base64.b64decode(text, validate=True)
    except ValueError:
        raise ProtocolError("invalid base64")
    if expected_len is not None and len(data) != expected_len:
        raise ProtocolError("wrong length")
    return data


def hkdf(ikm: bytes, info: bytes, salt: bytes = b"") -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=salt or None, info=info).derive(ikm)


# ------------------------------------------------------------------ framing

def encode_frame(message: dict) -> bytes:
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_FRAME:
        raise ProtocolError("message too large")
    return struct.pack("<I", len(body)) + body


def decode_frames(buffer: bytearray):
    """Pop every complete frame from buffer; returns the decoded messages"""
    messages = []
    while len(buffer) >= 4:
        (length,) = struct.unpack("<I", bytes(buffer[:4]))
        if length > MAX_FRAME:
            raise ProtocolError("frame too large")
        if len(buffer) < 4 + length:
            break
        body = bytes(buffer[4:4 + length])
        del buffer[:4 + length]
        try:
            message = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ProtocolError("invalid JSON")
        if not isinstance(message, dict):
            raise ProtocolError("message must be an object")
        messages.append(message)
    return messages


# ------------------------------------------------------------------ pairing

def generate_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def public_bytes(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def shared_secret(private_key: ec.EllipticCurvePrivateKey, peer_public: bytes) -> bytes:
    try:
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public)
    except ValueError:
        raise ProtocolError("invalid public key")
    return private_key.exchange(ec.ECDH(), peer)


def pairing_code(secret: bytes) -> str:
    """Six digits both sides show, so the user can see they talk to each other"""
    number = struct.unpack(">I", hkdf(secret, INFO_PAIR_CODE)[:4])[0] % 1_000_000
    return f"{number:06d}"


def _pair_aad(client_id: str) -> bytes:
    return f"securevault-pair|{client_id}".encode("utf-8")


def wrap_pairing_key(secret: bytes, client_id: str, pairing_key: bytes) -> Tuple[str, str]:
    iv = os.urandom(IV_SIZE)
    ct = AESGCM(hkdf(secret, INFO_PAIR_WRAP)).encrypt(iv, pairing_key, _pair_aad(client_id))
    return b64e(iv), b64e(ct)


def unwrap_pairing_key(secret: bytes, client_id: str, iv: str, ct: str) -> bytes:
    try:
        return AESGCM(hkdf(secret, INFO_PAIR_WRAP)).decrypt(b64d(iv, IV_SIZE), b64d(ct), _pair_aad(client_id))
    except ProtocolError:
        raise
    except Exception:
        raise ProtocolError("pairing key does not decrypt")


# ------------------------------------------------------------------ sessions

class SessionCipher:
    """Encrypts one side of a session; the client uses it with is_client=True"""

    def __init__(self, session_id: str, pairing_key: bytes, client_nonce: bytes, server_nonce: bytes,
                 is_client: bool = False):
        salt = client_nonce + server_nonce
        c2s = AESGCM(hkdf(pairing_key, INFO_SESSION_C2S, salt))
        s2c = AESGCM(hkdf(pairing_key, INFO_SESSION_S2C, salt))
        self.session_id = session_id
        self._send, self._recv = (c2s, s2c) if is_client else (s2c, c2s)
        self._send_dir, self._recv_dir = ("c2s", "s2c") if is_client else ("s2c", "c2s")
        self.last_recv_seq = 0

    def _aad(self, direction: str, seq: int) -> bytes:
        return f"{direction}|{self.session_id}|{seq}".encode("utf-8")

    def seal(self, payload: dict, seq: int) -> dict:
        iv = os.urandom(IV_SIZE)
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ct = self._send.encrypt(iv, body, self._aad(self._send_dir, seq))
        return {"type": "enc", "session": self.session_id, "seq": seq, "iv": b64e(iv), "ct": b64e(ct)}

    def unseal(self, message: dict, enforce_order: bool = True) -> dict:
        seq = message.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq <= 0:
            raise ProtocolError("invalid sequence number")
        if enforce_order and seq <= self.last_recv_seq:
            raise ProtocolError("replayed or out-of-order message")
        try:
            body = self._recv.decrypt(b64d(message.get("iv"), IV_SIZE), b64d(message.get("ct")),
                                      self._aad(self._recv_dir, seq))
        except ProtocolError:
            raise
        except Exception:
            raise ProtocolError("message does not decrypt")
        if enforce_order:
            self.last_recv_seq = seq
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ProtocolError("invalid payload")
        if not isinstance(payload, dict):
            raise ProtocolError("payload must be an object")
        return payload


# ------------------------------------------------------------------ site matching

def _split(url: str):
    """(scheme or '', host) of a URL; a bare 'example.com' has no scheme"""
    url = (url or "").strip()
    if not url:
        return "", ""
    if "://" not in url:
        url = "//" + url
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
    except ValueError:
        return "", ""
    host = host.rstrip(".").lower()
    if host.startswith("www."):
        host = host[4:]
    return parts.scheme.lower(), host


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def site_host(url: str) -> str:
    """Host shown to the user and used as the title of a saved login"""
    return _split(url)[1]


def page_origin(url: str) -> str:
    """'https://example.com' of a page; stored as the URL of a login saved from it"""
    scheme, host = _split(url)
    return f"{scheme}://{host}" if scheme and host else host


def url_matches(entry_url: str, page_url: str) -> bool:
    """Whether a saved entry belongs to the page the browser is on

    The host must be the same, or the page must be on a subdomain of the
    saved host (a login saved for google.com is offered on accounts.google.com).
    Hosts are compared label by label, so bank.com.evil.example never matches
    bank.com. An entry saved for https is not offered on a plain http page.
    """
    page_scheme, page_host = _split(page_url)
    entry_scheme, entry_host = _split(entry_url)
    if page_scheme not in ("http", "https") or not page_host or not entry_host:
        return False
    if entry_scheme == "https" and page_scheme != "https":
        return False
    if entry_scheme and entry_scheme not in ("http", "https"):
        return False
    if page_host == entry_host:
        return True
    if _is_ip(page_host) or _is_ip(entry_host) or "." not in entry_host:
        return False
    return page_host.endswith("." + entry_host)
