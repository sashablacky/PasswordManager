"""
Register the SecureVault native messaging host with Firefox (Windows, macOS, Linux).

    python browser-extension/install_firefox.py            install for the current user
    python browser-extension/install_firefox.py --remove   undo it

It copies native-host/securevault_host.py into the SecureVault data folder,
writes a small launcher that runs it with this Python, writes the host
manifest and tells Firefox where it is (a registry key on Windows, a file in
the Mozilla folder on macOS and Linux). No administrator rights are needed.
"""

import json
import os
import shutil
import stat
import sys

HOST_NAME = "com.securevault.bridge"
EXTENSION_ID = "securevault-bridge@sashablacky"
APP_DIR_NAME = "SecureVault"

HERE = os.path.dirname(os.path.abspath(__file__))
HOST_SOURCE = os.path.join(HERE, "native-host", "securevault_host.py")


def data_dir():
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(base, APP_DIR_NAME, "browser-host")


def mozilla_manifest_dir():
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/Mozilla/NativeMessagingHosts")
    return os.path.expanduser("~/.mozilla/native-messaging-hosts")


def python_for_host():
    """A console Python: pythonw.exe has no stdin/stdout for Firefox to talk to"""
    exe = sys.executable
    if sys.platform == "win32" and os.path.basename(exe).lower() == "pythonw.exe":
        exe = os.path.join(os.path.dirname(exe), "python.exe")
    return exe


def write_launcher(folder, host_script):
    python = python_for_host()
    if sys.platform == "win32":
        path = os.path.join(folder, "securevault_host.bat")
        with open(path, "w", encoding="utf-8", newline="\r\n") as f:
            f.write("@echo off\n")
            f.write(f'"{python}" -u "{host_script}" %*\n')
    else:
        path = os.path.join(folder, "securevault_host.sh")
        with open(path, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\n")
            f.write(f'exec "{python}" -u "{host_script}" "$@"\n')
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def install():
    folder = data_dir()
    os.makedirs(folder, exist_ok=True)
    host_script = os.path.join(folder, "securevault_host.py")
    shutil.copy2(HOST_SOURCE, host_script)
    launcher = write_launcher(folder, host_script)

    manifest = {
        "name": HOST_NAME,
        "description": "SecureVault password manager",
        "path": launcher,
        "type": "stdio",
        "allowed_extensions": [EXTENSION_ID],
    }

    if sys.platform == "win32":
        manifest_path = os.path.join(folder, HOST_NAME + ".json")
        _write_json(manifest_path, manifest)
        import winreg
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Mozilla\NativeMessagingHosts\{HOST_NAME}")
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, manifest_path)
        winreg.CloseKey(key)
    else:
        os.makedirs(mozilla_manifest_dir(), exist_ok=True)
        manifest_path = os.path.join(mozilla_manifest_dir(), HOST_NAME + ".json")
        _write_json(manifest_path, manifest)

    print("SecureVault is now connected to Firefox.")
    print(f"  host:     {launcher}")
    print(f"  manifest: {manifest_path}")
    print("Restart Firefox if it is open, then click the SecureVault icon in the toolbar.")


def remove():
    if sys.platform == "win32":
        import winreg
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, rf"Software\Mozilla\NativeMessagingHosts\{HOST_NAME}")
        except FileNotFoundError:
            pass
    else:
        manifest_path = os.path.join(mozilla_manifest_dir(), HOST_NAME + ".json")
        if os.path.exists(manifest_path):
            os.remove(manifest_path)
    shutil.rmtree(data_dir(), ignore_errors=True)
    print("SecureVault is no longer connected to Firefox.")


def _write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


if __name__ == "__main__":
    if "--remove" in sys.argv[1:]:
        remove()
    else:
        install()
