import logging

from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QApplication

from platform_utils import is_mac

logger = logging.getLogger(__name__)

# Markers from nspasteboard.org: clipboard managers on macOS (Alfred, Raycast,
# Maccy, Paste, ...) do not keep items marked as concealed or transient
MAC_CONCEALED_TYPES = ("org.nspasteboard.ConcealedType", "org.nspasteboard.TransientType")

# How long a copied secret stays on the clipboard
CLEAR_AFTER_MS = 30 * 1000
CLIPBOARD_CLEAR_SECONDS = CLEAR_AFTER_MS // 1000

_last_secret = None
_quit_hook_installed = False


def copy_secret(text: str, clear_after_ms: int = CLEAR_AFTER_MS) -> None:
    """Copy a secret to the clipboard and clear it after a timeout or on app exit.

    The clipboard is only cleared if it still holds this secret, so anything
    the user copied afterwards is left alone.
    """
    global _last_secret, _quit_hook_installed

    _set_clipboard_text(text)
    _last_secret = text

    QTimer.singleShot(clear_after_ms, lambda: _clear_if_unchanged(text))

    # Qt keeps clipboard contents after the app exits, so clear on quit too
    if not _quit_hook_installed:
        QApplication.instance().aboutToQuit.connect(_clear_on_quit)
        _quit_hook_installed = True


def _set_clipboard_text(text: str) -> None:
    # Only with the native Cocoa backend: with another Qt platform (e.g. offscreen
    # in tests) Qt keeps its own clipboard and would not see the macOS pasteboard
    if is_mac() and QApplication.platformName() == "cocoa" and _set_mac_concealed_text(text):
        return
    QApplication.clipboard().setText(text)


def _set_mac_concealed_text(text: str) -> bool:
    """Put text on the macOS pasteboard marked as a secret; False if that is not possible.

    Uses AppKit from PyObjC, which is installed on macOS as a dependency of the
    Fluent window frame. Qt can only write its own private pasteboard types, so
    it cannot add these markers itself.
    """
    try:
        from AppKit import NSPasteboard, NSPasteboardTypeString
    except ImportError:
        return False
    try:
        pasteboard = NSPasteboard.generalPasteboard()
        pasteboard.declareTypes_owner_([NSPasteboardTypeString, *MAC_CONCEALED_TYPES], None)
        if not pasteboard.setString_forType_(text, NSPasteboardTypeString):
            return False
        for marker in MAC_CONCEALED_TYPES:
            pasteboard.setString_forType_("", marker)
        return True
    except Exception as e:  # fall back to the plain Qt clipboard
        logger.warning(f"Could not mark the copied password as concealed: {e}")
        return False


def _clear_if_unchanged(text: str) -> None:
    global _last_secret
    clipboard = QApplication.clipboard()
    if clipboard.text() == text:
        clipboard.clear()
    if _last_secret == text:
        _last_secret = None


def clear_secret_now() -> None:
    """Clear a copied secret right away (on exit and when the vault is locked)"""
    if _last_secret is not None:
        _clear_if_unchanged(_last_secret)


_clear_on_quit = clear_secret_now
