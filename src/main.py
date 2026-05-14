import sys
import logging
import os
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import Qt, QObject, QEvent, QTimer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database.db_manager import DatabaseManager
from security.encryption import EncryptionEngine
from managers.auth_manager import AuthenticationManager
from managers.password_manager import PasswordManager
from security.generator import PasswordGenerator
from ui.login_widget import LoginWidget

logging.basicConfig(
    filename="error.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def handle_exception(exc_type, exc_value, exc_tb):
    logging.critical("Uncaught exception:", exc_info=(exc_type, exc_value, exc_tb))

sys.excepthook = handle_exception


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

    def __init__(self):
        self.db_path = 'password_vault.db'

        # Initialize components
        self.db = DatabaseManager(self.db_path)
        self.encryption = EncryptionEngine()
        self.auth_manager = AuthenticationManager(self.db, self.encryption)
        self.password_manager = PasswordManager(self.db, self.encryption)
        self.generator = PasswordGenerator()

        # UI components
        self.login_widget = None
        self.main_window = None

        # Connect to database
        self.db.connect()
        self.db.create_tables()

        # Auto-close timer (30 seconds inactivity)
        self.auto_lock_timer = None
        self.setup_auto_lock()

        print("Password Manager initialized")
        print(f"Database: {self.db_path}")

    def setup_auto_lock(self):
        self.auto_lock_timer = QTimer()
        self.auto_lock_timer.setSingleShot(True)
        self.auto_lock_timer.timeout.connect(self.auto_lock)

    def reset_auto_lock(self):
        if self.auto_lock_timer:
            self.auto_lock_timer.stop()
            self.auto_lock_timer.start(30 * 1000)  # 30 seconds

    def auto_lock(self):
        if not self.auth_manager.is_logged_in():
            return

        print("Inactivity detected (30s). Closing application.")
        self.shutdown()
        QApplication.quit()  # CLOSE APP

    def start(self):
        self.show_login()

    def show_login(self):
        self.login_widget = LoginWidget(self.auth_manager)
        self.login_widget.login_successful.connect(self.on_login_success)
        self.login_widget.show()

    def on_login_success(self):
        print(f"User logged in: {self.auth_manager.get_current_user_id()}")

        if self.login_widget:
            self.login_widget.close()

        self.show_main_window()

    def show_main_window(self):
        from ui.main_window import MainWindow

        self.main_window = MainWindow(self)
        self.main_window.show()

        # Start inactivity tracking AFTER login
        self.reset_auto_lock()

    def shutdown(self):
        self.auth_manager.logout()

        if self.db:
            self.db.disconnect()

        print("Password Manager shut down")


def main():
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)

    app.setApplicationName("Password Manager")
    app.setOrganizationName("SecureVault")
    app.setApplicationVersion("1.0.0")
    app.setStyle('Fusion')

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
        QMessageBox.critical(None, "Fatal Error", f"Application error:\n{str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()