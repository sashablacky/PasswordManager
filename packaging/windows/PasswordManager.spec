# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec for the Windows build: "dist/Password Manager/Password Manager.exe"
# (one folder, no console window), and next to it securevault_host.exe, the
# native messaging host of the Firefox extension (browser-extension/native-host),
# which the installer registers with Firefox. The GitHub Actions workflow
# .github/workflows/build-windows.yml packs it into an installer (installer.iss)
# and a portable .zip. Build by hand from the project folder:
#     pip install -r requirements.txt -r packaging/windows/requirements-build.txt
#     pyinstaller --noconfirm --clean packaging/windows/PasswordManager.spec

import os
import re

from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo, StringFileInfo, StringStruct, StringTable, VarFileInfo, VarStruct, VSVersionInfo)

ROOT = os.path.abspath(os.path.join(SPECPATH, "..", ".."))
SRC = os.path.join(ROOT, "src")

with open(os.path.join(SRC, "version.py"), encoding="utf-8") as f:
    VERSION = re.search(r'__version__ = "([^"]+)"', f.read()).group(1)

APP_NAME = "Password Manager"
numbers = tuple(int(n) for n in (VERSION.split(".") + ["0", "0", "0"])[:4])

# Shown in the .exe's Properties -> Details
version_info = VSVersionInfo(
    ffi=FixedFileInfo(filevers=numbers, prodvers=numbers),
    kids=[
        StringFileInfo([StringTable("040904B0", [
            StringStruct("CompanyName", "SecureVault"),
            StringStruct("FileDescription", "Password Manager"),
            StringStruct("FileVersion", VERSION),
            StringStruct("InternalName", APP_NAME),
            StringStruct("LegalCopyright", "© 2025 SecureVault"),
            StringStruct("OriginalFilename", f"{APP_NAME}.exe"),
            StringStruct("ProductName", "Password Manager"),
            StringStruct("ProductVersion", VERSION),
        ])]),
        VarFileInfo([VarStruct("Translation", [0x0409, 1200])]),
    ],
)
VERSION_FILE = os.path.join(workpath, "version_info.txt")
os.makedirs(workpath, exist_ok=True)
with open(VERSION_FILE, "w", encoding="utf-8") as f:
    f.write(str(version_info))

a = Analysis(
    [os.path.join(SRC, "main.py")],
    pathex=[SRC],
    binaries=[],
    datas=[],
    hiddenimports=["darkdetect"],
    hookspath=[],
    runtime_hooks=[],
    # Development tools from requirements.txt that the app never imports;
    # numpy/scipy only serve the Fluent acrylic blur, which the app does not use
    # (qfluentwidgets imports it inside try/except)
    excludes=["tkinter", "pytest", "pytestqt", "pylint", "black", "mypy", "IPython",
              "numpy", "scipy"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=APP_NAME,
    debug=False,
    strip=False,
    upx=False,
    console=False,      # windowed: no console window
    icon=os.path.join(SPECPATH, "SecureVault.ico"),
    version=VERSION_FILE,
)

# Firefox starts this with the extension's messages on stdin, so it is a
# console program (Firefox gives it no window). Standard library only.
host = Analysis(
    [os.path.join(ROOT, "browser-extension", "native-host", "securevault_host.py")],
    excludes=["tkinter", "PyQt5", "numpy", "scipy", "pytest", "unittest", "pydoc", "email", "http",
              "xml", "sqlite3", "ssl", "asyncio"],
    noarchive=False,
)

host_exe = EXE(
    PYZ(host.pure),
    host.scripts,
    [],
    exclude_binaries=True,
    name="securevault_host",
    debug=False,
    strip=False,
    upx=False,
    console=True,
    icon=os.path.join(SPECPATH, "SecureVault.ico"),
    version=VERSION_FILE,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    host_exe,
    host.binaries,
    host.datas,
    strip=False,
    upx=False,
    name=APP_NAME,
)
