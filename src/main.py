import sys
import logging
import os
import shutil
import subprocess
import traceback
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Only the standard library and app_paths so far, so that a failure in any
# import below (Qt, cryptography, Argon2...) is still written to the log
from app_paths import get_log_path


def _system_alert(title: str, message: str) -> None:
    """An error window without Qt, for the packaged app (it has no console)"""
    try:
        if sys.platform == "darwin":
            # Title and text as arguments, so quotes in the message cannot break the script
            subprocess.run(
                ["osascript",
                 "-e", "on run argv",
                 "-e", "display alert (item 1 of argv) message (item 2 of argv) as critical",
                 "-e", "end run",
                 title, message],
                timeout=600, check=False)
        elif sys.platform == "win32":
            import ctypes
            mb_iconerror = 0x10
            ctypes.windll.user32.MessageBoxW(None, message, title, mb_iconerror)
    except Exception:
        pass


def _show_startup_alert(exc_type, exc_value, log_path) -> None:
    """Only in the packaged app: run from the sources, the console shows the error"""
    if getattr(sys, "frozen", False):
        _system_alert("Password Manager could not start",
                      f"{exc_type.__name__}: {exc_value}\n\nDetails were written to:\n{log_path}")


def report_startup_error(exc_type, exc_value, exc_tb):
    """Write an error that happened before the Qt window could show it to the
    log, and in the packaged app also show it in a system alert"""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        return
    text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    log_path = "error.log"
    try:
        log_path = get_log_path()
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} - startup - CRITICAL - "
                    f"Password Manager could not start:\n{text}\n")
    except Exception:
        pass
    sys.__excepthook__(exc_type, exc_value, exc_tb)
    _show_startup_alert(exc_type, exc_value, log_path)


_fault_log = None
if __name__ == "__main__":  # the program itself, not the tests importing this module
    sys.excepthook = report_startup_error
    # A crash in native code (Qt, PyObjC) leaves no Python traceback: let
    # faulthandler write the stack of every thread into the same log
    try:
        import faulthandler
        _fault_log = open(get_log_path(), "a", encoding="utf-8")
        faulthandler.enable(_fault_log)
    except Exception:
        pass

from PyQt5.QtWidgets import QApplication, QMessageBox, QDialog
from PyQt5.QtCore import Qt, QObject, QEvent, QTimer

from app_paths import get_db_path
from platform_utils import is_mac, restrict_file
from version import __version__
from database.db_manager import DatabaseManager
from security.encryption import EncryptionEngine
from managers.auth_manager import AuthenticationManager
from managers.password_manager import PasswordManager
from security.generator import PasswordGenerator
from ui.login_widget import LoginWidget
from ui.clipboard import clear_secret_now
from ui import theme
import app_settings

# Lock the vault after this many minutes without mouse or keyboard activity
# (the default; the user can pick one of the choices in Settings)
AUTO_LOCK_MINUTES = 5
AUTO_LOCK_CHOICES = app_settings.AUTO_LOCK_CHOICES


def setup_logging():
    # force=True: modules imported above may already have touched the root logger,
    # and without it the file handler below would be silently ignored
    logging.basicConfig(
        filename=get_log_path(),
        level=logging.WARNING,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        force=True
    )
    if os.path.exists(get_log_path()):
        restrict_file(get_log_path())


def handle_exception(exc_type, exc_value, exc_tb):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        return

    logging.critical("Uncaught exception:", exc_info=(exc_type, exc_value, exc_tb))
    traceback.print_exception(exc_type, exc_value, exc_tb)

    # The packaged app has no console, so make the error visible to the user
    if QApplication.instance() is not None:
        QMessageBox.critical(
            None, "Unexpected Error",
            f"An unexpected error occurred:\n{exc_value}\n\nDetails were written to:\n{get_log_path()}"
        )
    else:
        _show_startup_alert(exc_type, exc_value, get_log_path())


# Activity monitor to track user interaction
class ActivityMonitor(QObject):
    def __init__(self, reset_callback):
        super().__init__()
        self.reset_callback = reset_callback

    def eventFilter(self, obj, event):
        if event.type() in (
            QEvent.MouseMove,
            QEvent.MouseButtonPress,
            QEvent.KeyPress,
            QEvent.Wheel
        ):
            self.reset_callback()
        return super().eventFilter(obj, event)


class PasswordManagerApp:

    auto_lock_minutes = AUTO_LOCK_MINUTES

    def __init__(self):
        # Colour theme saved in the settings file (applies to every window)
        theme.init_theme()

        self.db_path = get_db_path()

        # Connect to database before the managers use it
        self.db = DatabaseManager(self.db_path)
        self.db.connect()
        self.db.create_tables()

        # Initialize components
        self.encryption = EncryptionEngine()
        self.auth_manager = AuthenticationManager(self.db, self.encryption)
        self.password_manager = PasswordManager(self.db, self.encryption)
        self.generator = PasswordGenerator()

        # UI components
        self.login_widget = None
        self.main_window = None

        # Auto-lock timer
        self.auto_lock_minutes = self._saved_auto_lock_minutes()
        self.auto_lock_timer = None
        self.setup_auto_lock()

        # Lets the browser extension fill in and save passwords (see integration/)
        self.bridge = None
        if app_settings.load_settings().get("browser_integration"):
            self.start_bridge()

        print("Password Manager initialized")
        print(f"Database: {self.db_path}")

    def setup_auto_lock(self):
        self.auto_lock_timer = QTimer()
        self.auto_lock_timer.setSingleShot(True)
        self.auto_lock_timer.timeout.connect(self.auto_lock)

    @staticmethod
    def _saved_auto_lock_minutes() -> int:
        minutes = app_settings.load_settings().get("auto_lock_minutes")
        return minutes if minutes in AUTO_LOCK_CHOICES else AUTO_LOCK_MINUTES

    def set_auto_lock_minutes(self, minutes: int):
        if minutes not in AUTO_LOCK_CHOICES:
            return
        self.auto_lock_minutes = minutes
        app_settings.save_settings(auto_lock_minutes=minutes)
        self.reset_auto_lock()

    def reset_auto_lock(self):
        if self.auto_lock_timer and self.auth_manager.is_logged_in():
            self.auto_lock_timer.start(self.auto_lock_minutes * 60 * 1000)

    def auto_lock(self):
        if not self.auth_manager.is_logged_in():
            return

        print(f"Inactivity detected ({self.auto_lock_minutes} min). Locking vault.")
        self.lock_vault()

    def lock_vault(self):
        """Clear the key from memory and return to the login screen"""
        if self.auto_lock_timer:
            self.auto_lock_timer.stop()

        # Close any dialogs that are still open on top of the main window
        for widget in QApplication.topLevelWidgets():
            if isinstance(widget, QDialog) and widget.isVisible():
                widget.reject()

        self.auth_manager.logout()
        if self.bridge:
            self.bridge.service.clear_sessions()

        # A password copied a moment ago must not stay readable on the clipboard
        clear_secret_now()

        # Show the login screen first so the app does not quit when the main window closes
        self.show_login()

        if self.main_window:
            self.main_window.close_without_prompt()
            self.main_window = None

    def start(self):
        self.show_login()

    def start_bridge(self):
        if self.bridge:
            return
        try:
            from integration.server import create_bridge
            self.bridge = create_bridge(self)
            self.bridge.start()
        except Exception as e:
            # The program works without the browser extension
            logging.error(f"Browser bridge could not start: {e}")
            self.bridge = None

    def stop_bridge(self):
        if self.bridge:
            self.bridge.stop()
            self.bridge = None

    def set_browser_integration(self, enabled: bool):
        app_settings.save_settings(browser_integration=bool(enabled))
        if enabled:
            self.start_bridge()
        else:
            self.stop_bridge()

    def show_login(self):
        if self.login_widget:
            self.login_widget.close()
        self.login_widget = LoginWidget(self.auth_manager)
        self.login_widget.login_successful.connect(self.on_login_success)
        self.login_widget.show()

    def on_login_success(self):
        print(f"User logged in: {self.auth_manager.get_current_user_id()}")

        if self.login_widget:
            self.login_widget.close()
            self.login_widget = None

        self.show_main_window()

    def unlock_from_browser(self, master_password: str):
        """Master password typed into the browser extension; returns (ok, message)"""
        if self.auth_manager.is_logged_in():
            return True, "Already unlocked"
        ok, message = self.auth_manager.authenticate(master_password)
        if ok:
            if self.login_widget:
                self.login_widget.close()
                self.login_widget = None
            # Opened minimized, so the window doesn't jump in front of the browser
            self.show_main_window(minimized=True)
        return ok, message

    def show_main_window(self, minimized=False):
        from ui.main_window import MainWindow

        self.main_window = MainWindow(self)
        if minimized:
            self.main_window.showMinimized()
        else:
            self.main_window.show()

        # Start inactivity tracking AFTER login
        self.reset_auto_lock()

    def reopen_database(self):
        """Reconnect after the database file was replaced (e.g. restored from backup)"""
        self.db.disconnect()
        self.db.connect()
        self.db.create_tables()

    def restore_database(self, backup_path: str) -> str:
        """Replace the vault with backup_path; returns where the previous vault was saved"""
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base, ext = os.path.splitext(self.db_path)
        saved_copy = f"{base}_before_restore_{stamp}{ext or '.db'}"
        self.db.backup_to(saved_copy)

        self.db.disconnect()
        try:
            shutil.copy2(backup_path, self.db_path)
            restrict_file(self.db_path)
        finally:
            # Reconnect either way: to the restored vault, or to the old one if the copy failed
            self.reopen_database()
        return saved_copy

    def shutdown(self):
        if self.auto_lock_timer:
            self.auto_lock_timer.stop()
        self.stop_bridge()

        if self.db and self.db.connection:
            self.auth_manager.logout()
            self.db.disconnect()

        print("Password Manager shut down")


def main():
    setup_logging()
    sys.excepthook = handle_exception

    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)

    app.setApplicationName("Password Manager")
    app.setOrganizationName("SecureVault")
    app.setApplicationVersion(__version__)
    app.setStyle('Fusion')
    if is_mac():
        # Dock icon when started from the sources (the .app bundle has its own .icns)
        app.setWindowIcon(theme.app_icon())

    try:
        password_manager_app = PasswordManagerApp()

        #global activity tracker
        activity_monitor = ActivityMonitor(password_manager_app.reset_auto_lock)
        app.installEventFilter(activity_monitor)

        password_manager_app.start()

        exit_code = app.exec_()

        password_manager_app.shutdown()
        sys.exit(exit_code)

    except Exception as e:
        logging.exception("Fatal error during startup")
        QMessageBox.critical(None, "Fatal Error", f"Application error:\n{str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
