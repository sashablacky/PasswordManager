from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QMessageBox, QCheckBox,
                             QInputDialog, QDialog, QDialogButtonBox, QFormLayout)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont

from database.db_manager import DatabaseManager
from security.encryption import EncryptionEngine
from security.generator import PasswordGenerator
from managers.auth_manager import AuthenticationManager


class LoginWidget(QWidget):
    """Login and account creation widget"""

    login_successful = pyqtSignal()
    account_created = pyqtSignal()

    def __init__(self, auth_manager):
        super().__init__()
        self.auth_manager = auth_manager
        self.generator = PasswordGenerator()
        self.setup_ui()
        self.check_account_exists()

    def setup_ui(self):
        """Set up the user interface"""
        self.setWindowTitle("Password Manager - Login")
        self.setFixedSize(1000, 1000)
        self.setStyleSheet("""
            QWidget {
                background-color: #f5f7fa;
            }
            QLineEdit {
                padding: 10px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 14px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #667eea;
            }
            QPushButton {
                padding: 12px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: bold;
            }
            QLabel {
                color: #2c3e50;
            }
        """)

        # Main layout
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(40, 40, 40, 40)

        # Logo/Title
        title_label = QLabel("🔐 Password Manager")
        title_font = QFont()
        title_font.setPointSize(28)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #667eea; margin-bottom: 10px;")
        layout.addWidget(title_label)

        # Subtitle
        subtitle_label = QLabel("Secure • Local • Private")
        subtitle_font = QFont()
        subtitle_font.setPointSize(12)
        subtitle_label.setFont(subtitle_font)
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setStyleSheet("color: #7f8c8d; margin-bottom: 30px;")
        layout.addWidget(subtitle_label)

        # Master password label
        password_label = QLabel("Master Password:")
        password_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(password_label)

        # Password input
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setMaxLength(128)
        self.password_input.setPlaceholderText("Enter your master password")
        self.password_input.setMinimumHeight(45)
        self.password_input.returnPressed.connect(self.on_login_clicked)
        layout.addWidget(self.password_input)

        # Show/Hide password checkbox
        self.show_password_checkbox = QCheckBox("Show password")
        self.show_password_checkbox.setStyleSheet("font-size: 12px; color: #7f8c8d;")
        self.show_password_checkbox.stateChanged.connect(self.toggle_password_visibility)
        layout.addWidget(self.show_password_checkbox)

        # Password strength indicator (for account creation)
        self.strength_label = QLabel("")
        self.strength_label.setAlignment(Qt.AlignCenter)
        self.strength_label.setStyleSheet("font-size: 12px; padding: 8px; border-radius: 5px;")
        self.strength_label.hide()
        layout.addWidget(self.strength_label)

        layout.addSpacing(10)

        # Login button
        self.login_button = QPushButton("Login")
        self.login_button.setMinimumHeight(45)
        self.login_button.setCursor(Qt.PointingHandCursor)
        self.login_button.setStyleSheet("""
            QPushButton {
                background-color: #667eea;
                color: white;
                border: none;
            }
            QPushButton:hover {
                background-color: #5568d3;
            }
            QPushButton:pressed {
                background-color: #4c5fc7;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
        """)
        self.login_button.clicked.connect(self.on_login_clicked)
        layout.addWidget(self.login_button)

        # Create account button
        self.create_account_button = QPushButton("Create New Account")
        self.create_account_button.setMinimumHeight(45)
        self.create_account_button.setCursor(Qt.PointingHandCursor)
        self.create_account_button.setStyleSheet("""
            QPushButton {
                background-color: white;
                color: #667eea;
                border: 2px solid #667eea;
            }
            QPushButton:hover {
                background-color: #f0f3ff;
            }
        """)
        self.create_account_button.clicked.connect(self.on_create_account_clicked)
        layout.addWidget(self.create_account_button)

        # Generate password button (for account creation)
        self.generate_btn = QPushButton("🎲 Generate Strong Password")
        self.generate_btn.setMinimumHeight(35)
        self.generate_btn.setCursor(Qt.PointingHandCursor)
        self.generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #f8f9fa;
                color: #2c3e50;
                border: 1px solid #ddd;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #e9ecef;
            }
        """)
        self.generate_btn.clicked.connect(self.generate_password)
        self.generate_btn.hide()  # Hide initially
        layout.addWidget(self.generate_btn)

        # Info label
        self.info_label = QLabel("⚠️ Remember your master password!\nIt cannot be recovered if forgotten.")
        self.info_label.setAlignment(Qt.AlignCenter)
        self.info_label.setStyleSheet("""
            color: #e74c3c;
            font-size: 11px;
            padding: 12px;
            background-color: #fee;
            border-radius: 8px;
            margin-top: 20px;
        """)
        self.info_label.setWordWrap(True)
        layout.addWidget(self.info_label)

        layout.addStretch()

        self.setLayout(layout)

        # Set focus to password input
        self.password_input.setFocus()

    def check_account_exists(self):
        """Check if an account exists and update UI accordingly"""
        from database.db_manager import DatabaseManager
        db = DatabaseManager('password_vault.db')
        db.connect()
        user = db.fetch_one("SELECT user_id FROM users LIMIT 1")
        db.disconnect()

        if user:
            # Account exists - show login mode
            self.create_account_button.setText("Create New Account (Current Account Will Be Overwritten)")
            self.info_label.show()
            self.generate_btn.hide()
        else:
            # No account - show account creation mode
            self.login_button.setEnabled(False)
            self.password_input.textChanged.connect(self.on_password_changed)
            self.info_label.setText("🔐 Create your master password.\nMake it strong and memorable!")
            self.info_label.setStyleSheet("""
                color: #667eea;
                font-size: 11px;
                padding: 12px;
                background-color: #e3f2fd;
                border-radius: 8px;
                margin-top: 20px;
            """)
            self.generate_btn.show()

    def on_password_changed(self, text):
        """Handle password changes for strength checking"""
        if text:
            self.check_password_strength(text)
            self.login_button.setEnabled(True)
        else:
            self.strength_label.hide()
            self.login_button.setEnabled(False)

    def on_login_clicked(self):
        """Handle login button click"""
        password = self.password_input.text()

        if not password:
            self.show_error("Please enter your master password")
            return

        # Attempt login
        success, message = self.auth_manager.authenticate(password)

        if success:
            self.login_successful.emit()
        else:
            self.show_error(message)
            self.password_input.clear()
            self.password_input.setFocus()

    def on_create_account_clicked(self):
        """Handle create account button click"""
        # Check if account exists and warn user
        from database.db_manager import DatabaseManager
        db = DatabaseManager('password_vault.db')
        db.connect()
        user = db.fetch_one("SELECT user_id FROM users LIMIT 1")
        db.disconnect()

        if user:
            # Account exists - warn user
            reply = QMessageBox.warning(
                self,
                "Account Already Exists",
                "An account already exists. Creating a new account will overwrite the existing one.\n\n"
                "This will permanently delete all saved passwords!\n\n"
                "Are you ABSOLUTELY sure you want to continue?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return

        password = self.password_input.text()

        if not password:
            self.show_error("Please enter a master password")
            return

        # Confirm password
        confirm_password, ok = self.show_confirm_password_dialog()
        if not ok:
            return

        if password != confirm_password:
            self.show_error("Passwords do not match")
            return

        # Attempt account creation
        success, message = self.auth_manager.create_account(password)

        if success:
            QMessageBox.information(self, "Success",
                                    "Account created successfully!\nYou can now login.")
            self.account_created.emit()

            # Auto-login
            self.auth_manager.authenticate(password)
            self.login_successful.emit()
        else:
            self.show_error(message)

    def generate_password(self):
        """Generate a strong password and show it"""
        password = self.generator.generate()
        self.password_input.setText(password)
        self.check_password_strength(password)

        # Show the password briefly
        self.password_input.setEchoMode(QLineEdit.Normal)
        QMessageBox.information(
            self,
            "Password Generated",
            f"Generated password:\n\n{password}\n\n"
            f"Strength: {self.generator.calculate_strength_score(password)}/100\n\n"
            "Please save this password securely!"
        )

    def show_confirm_password_dialog(self):
        """Show dialog to confirm password"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Confirm Password")
        dialog.setFixedSize(400, 200)

        layout = QVBoxLayout()
        layout.setSpacing(15)

        label = QLabel("Please re-enter your master password:")
        label.setStyleSheet("font-size: 12px;")
        layout.addWidget(label)

        password_input = QLineEdit()
        password_input.setEchoMode(QLineEdit.Password)
        password_input.setPlaceholderText("Re-enter password")
        layout.addWidget(password_input)

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        dialog.setLayout(layout)

        result = dialog.exec_()
        return password_input.text(), result == QDialog.Accepted

    def check_password_strength(self, password):
        """Check and display password strength"""
        strength = self.generator.calculate_strength_score(password)
        entropy = self.generator.calculate_entropy(password)
        crack_info = self.generator.estimate_crack_time(password)

        if strength < 30:
            self.strength_label.setText(f"⚠️ Very Weak - {crack_info['time_string']}")
            self.strength_label.setStyleSheet("""
                background-color: #e74c3c;
                color: white;
                font-weight: bold;
                border-radius: 5px;
                padding: 8px;
            """)
        elif strength < 50:
            self.strength_label.setText(f"⚠️ Weak - {crack_info['time_string']}")
            self.strength_label.setStyleSheet("""
                background-color: #e67e22;
                color: white;
                font-weight: bold;
                border-radius: 5px;
                padding: 8px;
            """)
        elif strength < 75:
            self.strength_label.setText(f"✓ Medium - {crack_info['time_string']}")
            self.strength_label.setStyleSheet("""
                background-color: #f39c12;
                color: white;
                font-weight: bold;
                border-radius: 5px;
                padding: 8px;
            """)
        else:
            self.strength_label.setText(f"✓ Strong - {crack_info['time_string']}")
            self.strength_label.setStyleSheet("""
                background-color: #27ae60;
                color: white;
                font-weight: bold;
                border-radius: 5px;
                padding: 8px;
            """)

        self.strength_label.show()

    def toggle_password_visibility(self, state):
        """Toggle password visibility"""
        if state == Qt.Checked:
            self.password_input.setEchoMode(QLineEdit.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.Password)

    def show_error(self, message):
        """Show error message"""
        QMessageBox.critical(self, "Error", message)

    def clear_form(self):
        """Clear the form"""
        self.password_input.clear()
        self.show_password_checkbox.setChecked(False)
        self.strength_label.hide()


# Test the login widget
if __name__ == '__main__':
    import sys
    from PyQt5.QtWidgets import QApplication
    from database.db_manager import DatabaseManager
    from security.encryption import EncryptionEngine
    from managers.auth_manager import AuthenticationManager

    app = QApplication(sys.argv)

    # Setup
    db = DatabaseManager('password_vault.db')
    db.connect()
    db.create_tables()

    encryption = EncryptionEngine()
    auth = AuthenticationManager(db, encryption)

    # Create and show login widget
    login_widget = LoginWidget(auth)


    def on_login_success():
        print("✓ Login successful!")
        QMessageBox.information(login_widget, "Success", "Login successful!")


    def on_account_created():
        print("✓ Account created!")


    login_widget.login_successful.connect(on_login_success)
    login_widget.account_created.connect(on_account_created)

    login_widget.show()

    sys.exit(app.exec_())