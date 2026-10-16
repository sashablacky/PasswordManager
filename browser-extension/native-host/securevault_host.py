"""
Native messaging host of SecureVault for Firefox.

Firefox starts this script when the extension sends a message, writes the
message to its stdin and reads the reply from its stdout (4-byte length +
JSON). The script only passes messages on to the running SecureVault program
through a local socket and passes the replies back. It understands nothing of
the content: the extension and the program encrypt it end to end.

Standard library only, so it runs with any Python 3.8+.
"""

import getpass
import json
import os
import re
import socket
import struct
import sys

# Must match src/integration/endpoint.py
ENDPOINT_ENV = "SECUREVAULT_BRIDGE_ENDPOINT"
PIPE_PREFIX = "SecureVaultBridge-"
APP_DIR_NAME = "SecureVault"
SOCKET_NAME = "bridge.sock"
MAX_FRAME = 1024 * 1024


def endpoint():
    override = os.environ.get(ENDPOINT_ENV)
    if override:
        name = override
    elif sys.platform == "win32":
        try:
            user = getpass.getuser()
        except Exception:
            user = "user"
        name = PIPE_PREFIX + (re.sub(r"[^A-Za-z0-9_.-]", "_", user) or "user")
    elif sys.platform == "darwin":
        name = os.path.expanduser(os.path.join("~/Library/Application Support", APP_DIR_NAME, SOCKET_NAME))
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
        name = os.path.join(base, APP_DIR_NAME, SOCKET_NAME)
    if sys.platform == "win32" and not name.startswith("\\\\.\\pipe\\"):
        name = "\\\\.\\pipe\\" + name
    return name


def read_exact(stream, size):
    data = b""
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def read_frame(stream):
    header = read_exact(stream, 4)
    if header is None:
        return None
    (length,) = struct.unpack("<I", header)
    if length > MAX_FRAME:
        raise ValueError("frame too large")
    return read_exact(stream, length)


def write_frame(stream, body):
    stream.write(struct.pack("<I", len(body)) + body)
    stream.flush()


class Connection:
    """The local socket of the program (a named pipe on Windows)"""

    def __init__(self, name):
        if sys.platform == "win32":
            self._pipe = open(name, "r+b", buffering=0)
            self._sock = None
        else:
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.connect(name)
            self._pipe = self._sock.makefile("rwb", buffering=0)

    def request(self, body):
        # One request, one reply: never reading and writing the pipe at the same time
        write_frame(self._pipe, body)
        reply = read_frame(self._pipe)
        if reply is None:
            raise ConnectionError("the program closed the connection")
        return reply

    def close(self):
        try:
            self._pipe.close()
        finally:
            if self._sock is not None:
                self._sock.close()


def error(code):
    return json.dumps({"type": "error", "code": code}).encode("utf-8")


def main():
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    connection = None
    try:
        while True:
            body = read_frame(stdin)
            if body is None:
                break
            reply = None
            for attempt in range(2):
                try:
                    if connection is None:
                        connection = Connection(endpoint())
                    reply = connection.request(body)
                    break
                except (OSError, ConnectionError):
                    # Not running, or restarted since the last message: connect again once
                    if connection is not None:
                        connection.close()
                        connection = None
            write_frame(stdout, reply if reply is not None else error("app_not_running"))
    except ValueError:
        write_frame(stdout, error("bad_message"))
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    main()
