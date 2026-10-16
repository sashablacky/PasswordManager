from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QApplication

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

    clipboard = QApplication.clipboard()
    clipboard.setText(text)
    _last_secret = text

    QTimer.singleShot(clear_after_ms, lambda: _clear_if_unchanged(text))

    # Qt keeps clipboard contents after the app exits, so clear on quit too
    if not _quit_hook_installed:
        QApplication.instance().aboutToQuit.connect(_clear_on_quit)
        _quit_hook_installed = True


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
