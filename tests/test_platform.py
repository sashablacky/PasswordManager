"""
Platform branches (Windows / macOS / Linux), checked on any system by
switching sys.platform with monkeypatch.
"""

import os
import sys

import pytest

import app_paths
import app_settings
import platform_utils


@pytest.fixture
def fake_home(monkeypatch, tmp_path):
    """os.path.expanduser('~') returns a temporary folder on every system"""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    return str(home)


@pytest.fixture
def chmod_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(os, "chmod", lambda path, mode: calls.append((str(path), mode)))
    return calls


# ---------------------------------------------------------------- data folder

def test_data_dir_on_windows_uses_appdata(monkeypatch, tmp_path, fake_home):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
    assert app_paths.get_data_dir() == os.path.join(str(tmp_path / "Roaming"), "SecureVault")
    assert os.path.isdir(app_paths.get_data_dir())


def test_data_dir_on_windows_without_appdata_falls_back_to_home(monkeypatch, fake_home):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delenv("APPDATA", raising=False)
    assert app_paths.get_data_dir() == os.path.join(fake_home, "SecureVault")


def test_data_dir_on_mac_is_application_support(monkeypatch, tmp_path, fake_home, chmod_calls):
    monkeypatch.setattr(sys, "platform", "darwin")
    # %APPDATA% must be ignored on a Mac even if it happens to be set
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))

    path = app_paths.get_data_dir()

    assert path == os.path.join(fake_home, "Library", "Application Support", "SecureVault")
    assert os.path.isdir(path)
    # Only the owner may open the folder
    assert (path, 0o700) in chmod_calls


def test_data_dir_on_linux_follows_xdg(monkeypatch, tmp_path, fake_home):
    monkeypatch.setattr(sys, "platform", "linux")
    assert app_paths.get_data_dir() == os.path.join(fake_home, ".local", "share", "SecureVault")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert app_paths.get_data_dir() == os.path.join(str(tmp_path / "xdg"), "SecureVault")


def test_vault_log_and_settings_live_in_the_mac_data_dir(monkeypatch, fake_home, chmod_calls):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.delenv(app_paths.DB_PATH_ENV, raising=False)
    monkeypatch.delenv(app_settings.SETTINGS_PATH_ENV, raising=False)
    monkeypatch.setattr(app_paths, "_program_dir", lambda: os.path.join(fake_home, "nowhere"))
    monkeypatch.chdir(fake_home)

    data_dir = os.path.join(fake_home, "Library", "Application Support", "SecureVault")
    assert app_paths.get_db_path() == os.path.join(data_dir, "password_vault.db")
    assert app_paths.get_log_path() == os.path.join(data_dir, "error.log")
    assert app_settings.get_settings_path() == os.path.join(data_dir, "settings.json")


def test_data_dir_on_windows_is_not_chmodded(monkeypatch, tmp_path, fake_home, chmod_calls):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", str(tmp_path))
    app_paths.get_data_dir()
    assert chmod_calls == []


# ---------------------------------------------------------------- file permissions

def test_restrict_file_is_owner_only_on_mac_and_linux(monkeypatch, chmod_calls):
    for name in ("darwin", "linux"):
        monkeypatch.setattr(sys, "platform", name)
        platform_utils.restrict_file("/some/vault.db")
    assert chmod_calls == [("/some/vault.db", 0o600), ("/some/vault.db", 0o600)]


def test_restrict_file_does_nothing_on_windows(monkeypatch, chmod_calls):
    monkeypatch.setattr(sys, "platform", "win32")
    platform_utils.restrict_file(r"C:\vault.db")
    platform_utils.restrict_dir(r"C:\SecureVault")
    assert chmod_calls == []


def test_restrict_file_errors_are_not_fatal(monkeypatch):
    def fail(path, mode):
        raise PermissionError("read-only file system")
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(os, "chmod", fail)
    platform_utils.restrict_file("/some/vault.db")  # logs a warning, does not raise


def test_vault_and_backup_are_owner_only_on_mac(monkeypatch, tmp_path, chmod_calls):
    from database.db_manager import DatabaseManager

    monkeypatch.setattr(sys, "platform", "darwin")
    vault = str(tmp_path / "vault.db")
    backup = str(tmp_path / "backup.db")

    db = DatabaseManager(vault)
    db.connect()
    try:
        db.create_tables()
        db.backup_to(backup)
    finally:
        db.disconnect()

    assert (vault, 0o600) in chmod_calls
    assert (backup, 0o600) in chmod_calls


def test_vault_permissions_untouched_on_windows(monkeypatch, tmp_path, chmod_calls):
    from database.db_manager import DatabaseManager

    monkeypatch.setattr(sys, "platform", "win32")
    db = DatabaseManager(str(tmp_path / "vault.db"))
    db.connect()
    db.backup_to(str(tmp_path / "backup.db"))
    db.disconnect()
    assert chmod_calls == []


# ---------------------------------------------------------------- save dialogs

def test_save_path_on_windows_is_unchanged(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert platform_utils.default_save_path("backup.db") == "backup.db"


def test_save_path_on_mac_is_in_documents(monkeypatch, tmp_path):
    from PyQt5.QtCore import QStandardPaths

    documents = tmp_path / "Documents"
    documents.mkdir()
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(QStandardPaths, "writableLocation", lambda location: str(documents))
    assert platform_utils.default_save_path("export.csv") == os.path.join(str(documents), "export.csv")


def test_save_path_on_mac_falls_back_to_home(monkeypatch, fake_home):
    from PyQt5.QtCore import QStandardPaths

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(QStandardPaths, "writableLocation", lambda location: "")
    assert platform_utils.default_save_path("export.csv") == os.path.join(fake_home, "export.csv")


# ---------------------------------------------------------------- shortcuts

def test_shortcut_labels(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert platform_utils.shortcut_label("Ctrl+F") == "Ctrl+F"
    assert platform_utils.shortcut_label("Ctrl+Shift+N") == "Ctrl+Shift+N"

    monkeypatch.setattr(sys, "platform", "darwin")
    assert platform_utils.shortcut_label("Ctrl+F") == "⌘F"
    # Mac order is Control, Option, Shift, Command whatever order they were written in
    assert platform_utils.shortcut_label("Ctrl+Shift+N") == "⇧⌘N"
    assert platform_utils.shortcut_label("Ctrl+Backspace") == "⌘⌫"
    assert platform_utils.shortcut_label("F5") == "F5"


def test_windows_shortcuts_are_unchanged(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert platform_utils.shortcut_keys() == {
        "add": ["Ctrl+N"], "search": ["Ctrl+F"], "generator": ["Ctrl+G"],
        "lock": ["Ctrl+L"], "quit": ["Ctrl+Q"], "refresh": ["F5"], "delete": ["Delete"],
    }


def test_mac_adds_cmd_r_and_cmd_backspace(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    keys = platform_utils.shortcut_keys()
    assert keys["refresh"] == ["F5", "Ctrl+R"]
    assert keys["delete"] == ["Delete", "Ctrl+Backspace"]
    assert keys["search"] == ["Ctrl+F"]  # Qt turns Ctrl into Command on macOS


def test_shortcut_keys_returns_a_fresh_dict(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    platform_utils.shortcut_keys()["refresh"].append("X")
    assert "X" not in platform_utils.shortcut_keys()["refresh"]


# ---------------------------------------------------------------- fonts

def test_font_families_per_platform(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert platform_utils.ui_font_families()[:2] == ["Segoe UI Variable Text", "Segoe UI"]
    assert platform_utils.ui_font_families(display=True)[0] == "Segoe UI Variable Display"
    assert platform_utils.mono_font_families()[0] == "Cascadia Mono"

    monkeypatch.setattr(sys, "platform", "darwin")
    assert "Segoe UI" not in platform_utils.ui_font_families()
    assert "Helvetica Neue" in platform_utils.ui_font_families()
    assert "Menlo" in platform_utils.mono_font_families()


def test_windows_ui_font_is_still_segoe(qapp, monkeypatch):
    from PyQt5.QtGui import QFontDatabase
    from ui import theme

    monkeypatch.setattr(sys, "platform", "win32")
    font = theme.ui_font(14)
    installed = set(QFontDatabase().families())
    if "Segoe UI" in installed or "Segoe UI Variable Text" in installed:
        assert font.family().startswith("Segoe UI")
    assert font.pixelSize() == 14


def test_mac_fonts_are_given_to_fluent_widgets(qapp, monkeypatch):
    from qfluentwidgets import qconfig
    from ui import theme

    saved = qconfig.get(qconfig.fontFamilies)
    try:
        monkeypatch.setattr(sys, "platform", "win32")
        theme.apply_platform_fonts()
        assert qconfig.get(qconfig.fontFamilies) == saved  # Windows keeps the Fluent defaults

        monkeypatch.setattr(sys, "platform", "darwin")
        theme.apply_platform_fonts()
        families = qconfig.get(qconfig.fontFamilies)
        assert "Segoe UI" not in families
        assert families[-1] == "PingFang SC"
    finally:
        qconfig.set(qconfig.fontFamilies, saved, save=False)


# ---------------------------------------------------------------- clipboard

@pytest.fixture
def cocoa(monkeypatch):
    """Pretend to run on macOS with Qt's native Cocoa backend"""
    from PyQt5.QtWidgets import QApplication
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(QApplication, "platformName", staticmethod(lambda: "cocoa"))


def test_mac_clipboard_marks_secret_as_concealed(qapp, cocoa, monkeypatch):
    from ui import clipboard

    written = []
    monkeypatch.setattr(clipboard, "_set_mac_concealed_text", lambda text: written.append(text) or True)
    qapp.clipboard().setText("something else")

    clipboard._set_clipboard_text("s3cret")

    assert written == ["s3cret"]
    assert qapp.clipboard().text() == "something else"  # the Qt route was not used
    qapp.clipboard().clear()


def test_mac_clipboard_falls_back_to_qt(qapp, cocoa, monkeypatch):
    from ui import clipboard

    # e.g. PyObjC missing or the pasteboard refused the data
    monkeypatch.setattr(clipboard, "_set_mac_concealed_text", lambda text: False)
    clipboard._set_clipboard_text("s3cret")
    assert qapp.clipboard().text() == "s3cret"
    qapp.clipboard().clear()


@pytest.mark.skipif(sys.platform == "darwin", reason="AppKit is available on a Mac")
def test_appkit_route_reports_failure_without_appkit():
    from ui import clipboard
    assert clipboard._set_mac_concealed_text("s3cret") is False


def test_mac_clipboard_needs_the_cocoa_backend(qapp, monkeypatch):
    from ui import clipboard

    # On macOS with QT_QPA_PLATFORM=offscreen, Qt's own clipboard must be used
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(clipboard, "_set_mac_concealed_text",
                        lambda text: pytest.fail("pasteboard used without Cocoa"))
    if qapp.platformName() == "cocoa":
        pytest.skip("running on the real Cocoa backend")
    clipboard._set_clipboard_text("s3cret")
    assert qapp.clipboard().text() == "s3cret"
    qapp.clipboard().clear()


def test_windows_clipboard_does_not_try_appkit(qapp, monkeypatch):
    from ui import clipboard

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(clipboard, "_set_mac_concealed_text",
                        lambda text: pytest.fail("AppKit route used on Windows"))
    clipboard._set_clipboard_text("s3cret")
    assert qapp.clipboard().text() == "s3cret"
    qapp.clipboard().clear()


@pytest.mark.skipif(sys.platform != "darwin", reason="needs a real Mac")
def test_real_mac_pasteboard_holds_concealed_secret(qapp):
    if qapp.platformName() != "cocoa":
        pytest.skip("needs the native Cocoa backend")
    from AppKit import NSPasteboard
    from ui import clipboard

    clipboard._set_clipboard_text("s3cret")
    types = list(NSPasteboard.generalPasteboard().types())
    assert "org.nspasteboard.ConcealedType" in types
    # Qt reads the same pasteboard, so the auto-clear comparison works
    assert qapp.clipboard().text() == "s3cret"
    clipboard._clear_if_unchanged("s3cret")
    assert qapp.clipboard().text() == ""


# ---------------------------------------------------------------- app icon

def test_app_icon_scales_for_the_mac_bundle(qapp):
    from ui import theme

    small = theme.app_icon_pixmap(64)
    big = theme.app_icon_pixmap(1024)
    assert (small.width(), big.width()) == (64, 1024)
    # The tile is drawn edge to edge, so the centre is opaque at every size
    assert big.toImage().pixelColor(512, 100).alpha() == 255
    assert not theme.app_icon().isNull()


# ---------------------------------------------------------------- start-up errors

def _raise_import_error():
    try:
        raise ImportError("dlopen(_ffi.abi3.so): built for macOS 15.0")
    except ImportError:
        return sys.exc_info()


def test_startup_error_is_written_to_the_log(monkeypatch, tmp_path):
    import main

    log = tmp_path / "error.log"
    alerts = []
    monkeypatch.setattr(main, "get_log_path", lambda: str(log))
    monkeypatch.setattr(main, "_mac_alert", lambda title, text: alerts.append(text))
    monkeypatch.setattr(sys, "__excepthook__", lambda *a: None)
    monkeypatch.setattr(sys, "platform", "win32")

    main.report_startup_error(*_raise_import_error())

    text = log.read_text(encoding="utf-8")
    assert "could not start" in text and "built for macOS 15.0" in text and "Traceback" in text
    assert alerts == []  # the Windows/source run has a console


def test_startup_error_shows_an_alert_in_the_packaged_mac_app(monkeypatch, tmp_path):
    import main

    log = tmp_path / "error.log"
    calls = []
    monkeypatch.setattr(main, "get_log_path", lambda: str(log))
    monkeypatch.setattr(sys, "__excepthook__", lambda *a: None)
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(main.subprocess, "run", lambda args, **kw: calls.append(args))

    main.report_startup_error(*_raise_import_error())

    assert len(calls) == 1
    args = calls[0]
    assert args[0] == "osascript"
    # Title and text go in as arguments, so quotes in the message cannot break the script
    assert args[-2] == "Password Manager could not start"
    assert "ImportError" in args[-1] and str(log) in args[-1]
    assert log.exists()


def test_importing_main_does_not_replace_the_excepthook():
    import importlib
    import main

    before = sys.excepthook
    importlib.reload(main)
    assert sys.excepthook is before  # only the running program installs its hook


# ---------------------------------------------------------------- browser bridge on macOS

def test_safari_scan_only_with_the_safari_app_installed(monkeypatch, fake_home, tmp_path):
    from integration import endpoint

    monkeypatch.setattr(sys, "platform", "darwin")
    real_isdir = os.path.isdir
    installed = []
    monkeypatch.setattr(os.path, "isdir",
                        lambda p: p in installed or (not p.startswith("/Applications") and real_isdir(p)))
    assert endpoint.safari_extension_installed() is False

    installed.append(os.path.join("/Applications", "SecureVault for Safari.app"))
    assert endpoint.safari_extension_installed() is True

    monkeypatch.setattr(sys, "platform", "win32")
    assert endpoint.safari_extension_installed() is False


def test_safari_scan_errors_do_not_escape(qapp, monkeypatch):
    from integration import server

    def broken():
        raise PermissionError("Operation not permitted: Group Containers")
    monkeypatch.setattr(server, "safari_endpoints", broken)
    bridge = server.BridgeServer.__new__(server.BridgeServer)
    bridge._servers = {}
    bridge._listen_safari()  # logs a warning, does not raise
