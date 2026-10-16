# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec for the macOS app bundle: "dist/Password Manager.app".
# Build it with packaging/macos/build_macos.sh (on a Mac) or the GitHub
# Actions workflow .github/workflows/build-macos.yml. The Windows build is
# separate and does not use this file.

import os
import re

ROOT = os.path.abspath(os.path.join(SPECPATH, "..", ".."))
SRC = os.path.join(ROOT, "src")

with open(os.path.join(SRC, "version.py"), encoding="utf-8") as f:
    VERSION = re.search(r'__version__ = "([^"]+)"', f.read()).group(1)

APP_NAME = "Password Manager"
BUNDLE_ID = "io.github.sashablacky.securevault"

a = Analysis(
    [os.path.join(SRC, "main.py")],
    pathex=[SRC],
    binaries=[],
    datas=[],
    # PyObjC modules used by the Fluent window frame and the concealed clipboard;
    # some are imported inside functions, so name them explicitly
    hiddenimports=["objc", "Cocoa", "AppKit", "Foundation", "Quartz", "darkdetect"],
    hookspath=[],
    runtime_hooks=[],
    # Development tools from requirements.txt that the app never imports
    excludes=["tkinter", "pytest", "pytestqt", "pylint", "black", "mypy", "IPython"],
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
    upx=False,          # UPX breaks code signatures on macOS
    console=False,      # windowed: no Terminal window
    argv_emulation=False,
    target_arch=None,   # the architecture of the Python that builds it (arm64 or x86_64)
    codesign_identity=os.environ.get("MACOS_CODESIGN_IDENTITY") or None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name=APP_NAME,
)

app = BUNDLE(
    coll,
    name=f"{APP_NAME}.app",
    icon=os.path.join(SPECPATH, "SecureVault.icns"),
    bundle_identifier=BUNDLE_ID,
    version=VERSION,
    info_plist={
        "CFBundleName": APP_NAME,
        "CFBundleDisplayName": APP_NAME,
        "CFBundleShortVersionString": VERSION,
        "CFBundleVersion": VERSION,
        "CFBundleDevelopmentRegion": "en",
        "LSApplicationCategoryType": "public.app-category.utilities",
        "LSMinimumSystemVersion": "11.0",
        "NSHighResolutionCapable": True,
        "NSRequiresAquaSystemAppearance": False,
        "NSPrincipalClass": "NSApplication",
        "NSHumanReadableCopyright": "© 2025 SecureVault",
    },
)
