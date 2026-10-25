"""
Check the Firefox native messaging host registered by the Windows installer.

    python .github/scripts/check_native_host.py <install folder>            after installing
    python .github/scripts/check_native_host.py <install folder> --removed  after uninstalling

Installed: the registry key points to a manifest that names securevault_host.exe
in the install folder and our extension, and the host answers a "hello" like
Firefox would send it (the program is not running, so with "app_not_running").
Removed: the key and the manifest are gone.
"""

import json
import os
import struct
import subprocess
import sys
import winreg

HOST_NAME = "com.securevault.bridge"
EXTENSION_ID = "securevault-bridge@sashablacky"
KEY = rf"Software\Mozilla\NativeMessagingHosts\{HOST_NAME}"


def fail(message: str) -> None:
    print(f"::error title=Firefox host::{message}")
    sys.exit(1)


def registered_manifest() -> str | None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY) as key:
            return winreg.QueryValueEx(key, "")[0]
    except FileNotFoundError:
        return None


def ask_host(host: str) -> dict:
    body = json.dumps({"type": "hello", "client_id": None, "nonce": "AAAAAAAAAAAAAAAAAAAAAA=="}).encode()
    result = subprocess.run([host, os.path.join(os.path.dirname(host), HOST_NAME + ".json"), EXTENSION_ID],
                            input=struct.pack("<I", len(body)) + body, capture_output=True, timeout=30)
    out = result.stdout
    if len(out) < 4 or len(out) != 4 + struct.unpack("<I", out[:4])[0]:
        fail(f"bad reply from the host (exit {result.returncode}): {out!r} {result.stderr[-500:]!r}")
    return json.loads(out[4:])


def main() -> None:
    folder = os.path.normcase(os.path.abspath(sys.argv[1]))
    manifest_path = registered_manifest()

    if "--removed" in sys.argv[2:]:
        if manifest_path is not None:
            fail(f"the uninstaller left the registry key ({manifest_path})")
        if os.path.exists(os.path.join(folder, HOST_NAME + ".json")):
            fail("the uninstaller left the manifest")
        print("Firefox host registration removed")
        return

    if manifest_path is None:
        fail(f"no registry key HKCU\\{KEY}")
    with open(manifest_path, "rb") as f:
        manifest = json.loads(f.read().decode("ascii"))
    host = manifest.get("path", "")
    if os.path.normcase(os.path.dirname(host)) != folder or os.path.basename(host) != "securevault_host.exe":
        fail(f"the manifest names {host!r}, not securevault_host.exe in {folder}")
    if not os.path.isfile(host):
        fail(f"{host} was not installed")
    if manifest.get("name") != HOST_NAME or manifest.get("type") != "stdio" \
            or manifest.get("allowed_extensions") != [EXTENSION_ID]:
        fail(f"unexpected manifest: {manifest}")
    reply = ask_host(host)
    if reply != {"type": "error", "code": "app_not_running"}:
        fail(f"unexpected reply from the host: {reply}")
    print(f"Firefox host registered: {manifest_path} -> {host}, answers {reply}")


if __name__ == "__main__":
    main()
