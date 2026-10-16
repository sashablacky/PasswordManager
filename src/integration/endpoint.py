"""
Where the program listens for the browser bridge.

Windows: a named pipe of the current user. macOS and Linux: a Unix socket in
the program's data folder. On macOS the program also listens inside the App
Group folder of the Safari extension (…/Group Containers/<team>.securevault.bridge),
the only place its sandboxed handler may connect to.

browser-extension/native-host/securevault_host.py computes the same names
without importing this module; keep the two in sync.
"""

import getpass
import glob
import os
import re
import sys
from typing import List

# Set this environment variable to listen somewhere else (used by the tests)
ENDPOINT_ENV = "SECUREVAULT_BRIDGE_ENDPOINT"

PIPE_PREFIX = "SecureVaultBridge-"
SOCKET_NAME = "bridge.sock"
SAFARI_GROUP_SUFFIX = ".securevault.bridge"


def _user_tag() -> str:
    try:
        user = getpass.getuser()
    except Exception:
        user = "user"
    return re.sub(r"[^A-Za-z0-9_.-]", "_", user) or "user"


def default_endpoint() -> str:
    override = os.environ.get(ENDPOINT_ENV)
    if override:
        return override
    if sys.platform == "win32":
        return PIPE_PREFIX + _user_tag()
    from app_paths import get_data_dir
    return os.path.join(get_data_dir(), SOCKET_NAME)


SAFARI_APP_NAME = "SecureVault for Safari.app"


def safari_extension_installed() -> bool:
    """The Safari extension's container app is in Applications (docs/safari-install.md).

    Without it there is nothing to listen for, so the program does not look
    into ~/Library/Group Containers at all.
    """
    if sys.platform != "darwin":
        return False
    folders = ("/Applications", os.path.expanduser("~/Applications"))
    return any(os.path.isdir(os.path.join(folder, SAFARI_APP_NAME)) for folder in folders)


def safari_endpoints() -> List[str]:
    """Sockets for the Safari extension, one per App Group folder that exists"""
    if sys.platform != "darwin" or os.environ.get(ENDPOINT_ENV):
        return []
    pattern = os.path.expanduser(f"~/Library/Group Containers/*{SAFARI_GROUP_SUFFIX}")
    return [os.path.join(folder, SOCKET_NAME) for folder in sorted(glob.glob(pattern)) if os.path.isdir(folder)]
