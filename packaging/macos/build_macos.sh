#!/usr/bin/env bash
#
# Build "Password Manager.app" and a .dmg on a Mac.
#
#   1. Install Python 3.12 from python.org (or `brew install python@3.12`).
#   2. In Terminal, from the project folder:
#          ./packaging/macos/build_macos.sh
#   3. The result:
#          dist/Password Manager.app
#          dist/PasswordManager-<version>-macOS-<AppleSilicon|Intel>.dmg
#
# The script makes a virtual environment in .venv-macos, installs the
# requirements and PyInstaller, runs the tests, builds the bundle, signs it
# ad hoc and packs it into a .dmg.
#
# Options:
#   --skip-install   use the current Python as is (CI installs the packages itself)
#   --skip-tests     do not run the test suite
#
# Signing: without an Apple Developer ID the app is signed "ad hoc" (codesign -s -).
# Apple Silicon Macs refuse to run code with no signature at all, and an ad hoc
# signature is enough for that, but Gatekeeper still treats the app as coming
# from an unidentified developer: the first time it has to be opened with
# right click (Control-click) -> Open, or on macOS 15 and later via
# System Settings -> Privacy & Security -> "Open Anyway".
# To sign and notarize with a Developer ID, see "Signing and notarization" in README.md.

set -euo pipefail

SKIP_INSTALL=0
SKIP_TESTS=0
for arg in "$@"; do
    case "$arg" in
        --skip-install) SKIP_INSTALL=1 ;;
        --skip-tests) SKIP_TESTS=1 ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

if [[ "$(uname)" != "Darwin" ]]; then
    echo "This script builds the macOS app and must run on a Mac." >&2
    exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"

APP_NAME="Password Manager"
VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' src/version.py)"
ARCH="$(uname -m)"
# File names say which Mac they are for in words people know
if [[ "$ARCH" == "arm64" ]]; then MAC_KIND="AppleSilicon"; else MAC_KIND="Intel"; fi

if [[ $SKIP_INSTALL -eq 0 ]]; then
    PYTHON="${PYTHON:-python3.12}"
    if ! command -v "$PYTHON" >/dev/null; then
        echo "$PYTHON not found. Install Python 3.12 from https://www.python.org/downloads/macos/" >&2
        exit 1
    fi
    "$PYTHON" -m venv .venv-macos
    # shellcheck disable=SC1091
    source .venv-macos/bin/activate
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
    python -m pip install -r packaging/macos/requirements-build.txt
fi

if [[ $SKIP_TESTS -eq 0 ]]; then
    # The Fluent window frame talks to the native Cocoa window, so the tests use
    # the real window system on a Mac rather than QT_QPA_PLATFORM=offscreen
    python -m pytest -q tests
fi

rm -rf build "dist/$APP_NAME" "dist/$APP_NAME.app"
python -m PyInstaller --noconfirm --clean packaging/macos/PasswordManager.spec

APP="dist/$APP_NAME.app"

# One consistent signature over the whole bundle: ad hoc by default, or the
# Developer ID in MACOS_CODESIGN_IDENTITY with the hardened runtime that
# notarization requires (see "Signing and notarization" in README.md)
if [[ -z "${MACOS_CODESIGN_IDENTITY:-}" ]]; then
    codesign --force --deep --sign - "$APP"
else
    codesign --force --deep --options runtime --timestamp --sign "$MACOS_CODESIGN_IDENTITY" "$APP"
fi
codesign --verify --deep --strict "$APP"

# .dmg with the app, a link to /Applications and the first-start notes
DMG="dist/PasswordManager-$VERSION-macOS-$MAC_KIND.dmg"
NOTES_DIR="$(mktemp -d)"
NOTES="$NOTES_DIR/Как открыть в первый раз.rtf"
# Step-by-step first start in large type
python packaging/macos/make_first_launch_rtf.py "$NOTES"
rm -f "$DMG"

# Preferred: dmgbuild, which lays out the window (background arrow "drag onto
# Applications", icon positions). If it fails, a plain .dmg with the same files.
DMGBUILD_LOG="$NOTES_DIR/dmgbuild.log"
if python -m dmgbuild -s packaging/macos/dmg_settings.py \
        -D app="$APP" -D notes="$NOTES" -D background=packaging/macos/dmg-background.png \
        "$APP_NAME" "$DMG" > "$DMGBUILD_LOG" 2>&1; then
    cat "$DMGBUILD_LOG"
    echo "dmg laid out with dmgbuild"
else
    cat "$DMGBUILD_LOG"
    echo "dmgbuild failed, making a plain .dmg" >&2
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        # Show why in the run's annotations (the raw log needs admin rights)
        tail -n 25 "$DMGBUILD_LOG" | python -c "import sys; t = sys.stdin.read().replace('%', '%25').replace('\r', '').replace('\n', '%0A'); print('::warning title=dmgbuild failed::' + t)"
    fi
    rm -f "$DMG"
    STAGING="$(mktemp -d)"
    # ditto keeps symlinks, permissions and extended attributes, so the signature stays valid
    ditto "$APP" "$STAGING/$APP_NAME.app"
    ln -s /Applications "$STAGING/Applications"
    cp "$NOTES" "$STAGING/"
    # hdiutil now and then fails with "Resource busy" (known on CI Macs): retry
    for attempt in 1 2 3; do
        if hdiutil create -volname "$APP_NAME" -srcfolder "$STAGING" -ov -format UDZO "$DMG"; then
            break
        fi
        if [[ $attempt -eq 3 ]]; then
            echo "hdiutil failed three times" >&2
            exit 1
        fi
        echo "hdiutil failed, retrying in 10 s..." >&2
        sleep 10
    done
    rm -rf "$STAGING"
fi
rm -rf "$NOTES_DIR"

echo
echo "Built: $APP"
echo "       $DMG"
