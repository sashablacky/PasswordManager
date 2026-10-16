"""
Differences between Windows and macOS (and Linux) in one place.

sys.platform is read on every call rather than once at import time, so the
tests can switch it with monkeypatch and check the macOS branches on Windows.
"""

import os
import sys
import logging

logger = logging.getLogger(__name__)


def is_windows() -> bool:
    return sys.platform == "win32"


def is_mac() -> bool:
    return sys.platform == "darwin"


# ---------------------------------------------------------------- file permissions

def restrict_file(path: str) -> None:
    """Make a file readable and writable by its owner only (0600).

    Files are created world-readable (0644) on macOS and Linux; the vault,
    backups and CSV exports must not be. Windows keeps per-user ACLs on the
    profile folder and os.chmod there only toggles the read-only flag, so
    nothing is changed on Windows.
    """
    if is_windows():
        return
    try:
        os.chmod(path, 0o600)
    except OSError as e:
        logger.warning(f"Could not restrict permissions of {path}: {e}")


def restrict_dir(path: str) -> None:
    """Make a folder accessible by its owner only (0700); no-op on Windows"""
    if is_windows():
        return
    try:
        os.chmod(path, 0o700)
    except OSError as e:
        logger.warning(f"Could not restrict permissions of {path}: {e}")


# ---------------------------------------------------------------- file dialogs

def default_save_path(file_name: str) -> str:
    """Suggested location for a file the user saves (export, backup).

    On Windows the bare name is kept, as before (the dialog opens in the
    current folder). An app started from Finder runs with "/" as its current
    folder, which is not writable, so on macOS and Linux the file is suggested
    in the Documents folder.
    """
    if is_windows():
        return file_name
    folder = ""
    try:
        from PyQt5.QtCore import QStandardPaths
        folder = QStandardPaths.writableLocation(QStandardPaths.DocumentsLocation)
    except Exception:  # Qt not available, e.g. in a plain script
        pass
    if not folder or not os.path.isdir(folder):
        folder = os.path.expanduser("~")
    return os.path.join(folder, file_name)


# ---------------------------------------------------------------- keyboard shortcuts

# Qt maps "Ctrl" in a QKeySequence to the Command key on macOS, so the same
# key strings work on both systems; only the labels shown to the user differ.
_MAC_MODIFIERS = {"Meta": "⌃", "Alt": "⌥", "Shift": "⇧", "Ctrl": "⌘"}
_MAC_KEYS = {"Backspace": "⌫", "Delete": "⌦", "Return": "↩", "Enter": "↩", "Esc": "⎋", "Tab": "⇥"}


def shortcut_label(keys: str) -> str:
    """Label of a shortcut as the user sees it: 'Ctrl+F' on Windows, '⌘F' on macOS"""
    if not is_mac():
        return keys
    parts = keys.split("+")
    modifiers, key = parts[:-1], parts[-1]
    # macOS lists modifiers in a fixed order: Control, Option, Shift, Command
    ordered = [m for m in _MAC_MODIFIERS if m in modifiers]
    return "".join(_MAC_MODIFIERS[m] for m in ordered) + _MAC_KEYS.get(key, key)


def shortcut_keys() -> dict:
    """Keyboard shortcuts of the main window: action name -> list of key sequences.

    The Windows set is unchanged. macOS adds the usual Mac keys: Cmd+R to
    refresh (function keys need Fn on a Mac keyboard) and Cmd+Backspace to
    delete (the Mac "delete" key is Backspace; Delete needs Fn).
    """
    keys = {
        "add": ["Ctrl+N"],
        "search": ["Ctrl+F"],
        "generator": ["Ctrl+G"],
        "lock": ["Ctrl+L"],
        "quit": ["Ctrl+Q"],
        "refresh": ["F5"],
        "delete": ["Delete"],
    }
    if is_mac():
        keys["refresh"].append("Ctrl+R")
        keys["delete"].append("Ctrl+Backspace")
    return keys


# ---------------------------------------------------------------- fonts

def ui_font_families(display: bool = False) -> list:
    """Preferred interface font families, best first"""
    if is_mac():
        # San Francisco when installed under its public name, otherwise Helvetica Neue,
        # which every macOS has. "Segoe UI" does not exist on a Mac.
        return ["SF Pro Display" if display else "SF Pro Text", "Helvetica Neue", "Helvetica"]
    if is_windows():
        variable = "Segoe UI Variable Display" if display else "Segoe UI Variable Text"
        return [variable, "Segoe UI", "Sans Serif"]
    return ["Noto Sans", "DejaVu Sans", "Sans Serif"]


def mono_font_families() -> list:
    if is_mac():
        return ["SF Mono", "Menlo", "Monaco", "Courier New"]
    if is_windows():
        return ["Cascadia Mono", "Consolas", "Courier New"]
    return ["DejaVu Sans Mono", "Liberation Mono", "Monospace"]
