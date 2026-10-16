from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QMessageBox, QDialog)
from PyQt5.QtCore import Qt, pyqtSignal, QRectF
from PyQt5.QtGui import QFont, QPainter, QColor

from qfluentwidgets import FluentWidget, TransparentPushButton, PushButton
from security.generator import PasswordGenerator
from ui import theme
from ui.icons import AppIcon


class LogoTile(theme.ThemedWidget):
    """Accent-coloured tile with a lock, shown at the top of the login card"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(56, 56)

    def paintEvent(self, e):
        p = theme.current()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(p.accent))
        painter.drawRoundedRect(QRectF(self.rect()), 14, 14)
        AppIcon.LOCK.render(painter, QRectF(14, 14, 28, 28), fill=p.on_accent)


class Note(theme.WellFrame):
    """Small boxed hint with a warning icon"""

    def __init__(self, text, parent=None):
        super().__init__(parent, radius=8, alpha=0.35)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(10)
        self.icon = IconLabel(AppIcon.WARNING, "warn", 16)
        layout.addWidget(self.icon, 0, Qt.AlignTop)
        self.text_label = theme.label(text, role="muted", size=12)
        self.text_label.setWordWrap(True)
        layout.addWidget(self.text_label, 1)

    def setText(self, text):
        self.text_label.setText(text)

    def set_icon(self, icon, role):
        self.icon.icon, self.icon.role = icon, role
        self.icon.update()


class IconLabel(theme.ThemedWidget):
    def __init__(self, icon, role=None, size=16, parent=None):
        super().__init__(parent)
        self.icon, self.role = icon, role
        self.setFixedSize(size, size)

    def paintEvent(self, e):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        color = theme.current().color(self.role) if self.role else QColor(theme.current().text)
        self.icon.render(painter, QRectF(self.rect()), fill=color.name())


class LoginWidget(FluentWidget):
    """Login and account creation window"""

    login_successful = pyqtSignal()
    account_created = pyqtSignal()

    def __init__(self, auth_manager):
        super().__init__()
        self.auth_manager = auth_manager
        self.generator = PasswordGenerator()
        self.account_exists = False
        self.setup_ui()
        self.check_account_exists()
        theme.signals.changed.connect(self._on_theme_changed)

    def _on_theme_changed(self, key):
        try:
            self.update()
        except RuntimeError:
            pass

    def setup_ui(self):
        """Set up the user interface"""
        self.setWindowTitle("Password Manager")
        self.setWindowIcon(theme.app_icon())
        # Fits small laptop screens (1366x768); the user can still enlarge it
        self.setMinimumSize(460, 600)
        self.resize(520, 680)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, self.titleBar.height() + 8, 24, 24)
        outer.addStretch(1)

        card = theme.GlassCard(radius=12)
        card.setMaximumWidth(420)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(34, 34, 34, 28)
        layout.setSpacing(14)

        layout.addWidget(LogoTile(), 0, Qt.AlignLeft)

        self.title_label = theme.label("Unlock your vault", size=26, weight=QFont.DemiBold, display=True)
        layout.addWidget(self.title_label)
        subtitle = theme.label("Secure · Local · Private", role="muted", size=13)
        layout.addWidget(subtitle)
        layout.addSpacing(4)

        # Master password
        self.password_input = theme.reveal_line_edit()
        self.password_input.setPlaceholderText("Master password")
        self.password_input.setMinimumHeight(40)
        self.password_input.returnPressed.connect(self.on_return_pressed)
        layout.addWidget(self.password_input)

        # Strength of a new master password (account creation only)
        self.strength_bar = theme.StrengthBar()
        self.strength_label = theme.label("", role="muted", size=12)
        self.strength_bar.hide()
        self.strength_label.hide()
        layout.addWidget(self.strength_bar)
        layout.addWidget(self.strength_label)

        # Unlock (login mode) or create (first start) - only one of them is shown
        self.login_button = theme.primary_button("Unlock")
        self.login_button.setMinimumHeight(40)
        self.login_button.clicked.connect(self.on_login_clicked)
        layout.addWidget(self.login_button)

        self.create_account_button = theme.primary_button("Create vault")
        self.create_account_button.setMinimumHeight(40)
        self.create_account_button.clicked.connect(self.on_create_account_clicked)
        layout.addWidget(self.create_account_button)

        links = QHBoxLayout()
        links.setSpacing(4)
        # Login mode: start over with a new vault (deletes the old one after a warning)
        self.reset_button = TransparentPushButton("Reset vault…")
        self.reset_button.setToolTip("Delete this vault and create a new one")
        self.reset_button.clicked.connect(self.on_create_account_clicked)
        links.addWidget(self.reset_button)
        links.addStretch(1)
        # Account creation: generate a strong master password
        self.generate_btn = TransparentPushButton(AppIcon.DICE, "Generate a strong password")
        self.generate_btn.clicked.connect(self.generate_password)
        links.addWidget(self.generate_btn)
        layout.addLayout(links)

        self.info_label = Note("The master password cannot be recovered. "
                               "If you forget it, the vault stays locked for good.")
        layout.addWidget(self.info_label)

        outer.addWidget(card, 0, Qt.AlignHCenter)
        outer.addStretch(1)

        # Set focus to password input
        self.password_input.setFocus()

    def paintEvent(self, e):
        painter = QPainter(self)
        theme.paint_backdrop(painter, self.rect(), opacity=0.6 if self.isMicaEffectEnabled() else 1.0)

    def check_account_exists(self):
        """Check if an account exists and update UI accordingly"""
        self.account_exists = self.auth_manager.account_exists()

        if self.account_exists:
            # Account exists - show login mode
            self.title_label.setText("Unlock your vault")
            self.create_account_button.hide()
            self.reset_button.show()
            self.generate_btn.hide()
        else:
            # No account - show account creation mode
            self.title_label.setText("Create your vault")
            self.login_button.hide()
            self.reset_button.hide()
            self.password_input.textChanged.connect(self.on_password_changed)
            self.info_label.setText(
                "Choose a master password: at least 12 characters mixing letters, numbers "
                "and symbols, or a passphrase of 16+ characters (e.g. four random words). "
                "It cannot be recovered if forgotten."
            )
            self.generate_btn.show()

    def on_password_changed(self, text):
        """Handle password changes for strength checking"""
        if text:
            self.check_password_strength(text)
        else:
            self.strength_bar.hide()
            self.strength_label.hide()

    def on_return_pressed(self):
        """Enter logs in when an account exists, otherwise creates one"""
        if self.account_exists:
            self.on_login_clicked()
        else:
            self.on_create_account_clicked()

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
        """Handle create account / reset vault"""
        overwrite = False
        if self.auth_manager.account_exists():
            # Account exists - warn user
            reply = QMessageBox.warning(
                self,
                "Account Already Exists",
                "An account already exists. Creating a new account will delete the existing "
                "account and ALL saved passwords.\n\n"
                "A backup copy of the current vault file will be saved next to it first.\n\n"
                "Are you ABSOLUTELY sure you want to continue?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return
            overwrite = True

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
        success, message = self.auth_manager.create_account(password, overwrite=overwrite)

        if success:
            self.account_created.emit()

            # Auto-login
            logged_in, login_message = self.auth_manager.authenticate(password)
            if logged_in:
                QMessageBox.information(self, "Success", "Account created successfully!")
                self.login_successful.emit()
            else:
                self.show_error(f"Account was created, but logging in failed:\n{login_message}")
        else:
            self.show_error(message)

    def generate_password(self):
        """Generate a strong password and show it"""
        password = self.generator.generate()
        self.password_input.setText(password)
        self.check_password_strength(password)

        # Show the password so the user can write it down
        self.password_input.setPasswordVisible(True)
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
        dialog.setFixedSize(400, 190)

        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        layout.addWidget(theme.label("Please re-enter your master password:", size=13))

        password_input = theme.reveal_line_edit()
        password_input.setPlaceholderText("Re-enter password")
        password_input.returnPressed.connect(dialog.accept)
        layout.addWidget(password_input)
        layout.addStretch(1)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        ok_button = theme.primary_button("OK")
        ok_button.clicked.connect(dialog.accept)
        cancel_button = PushButton("Cancel")
        cancel_button.clicked.connect(dialog.reject)
        buttons.addWidget(ok_button)
        buttons.addWidget(cancel_button)
        layout.addLayout(buttons)

        password_input.setFocus()
        result = dialog.exec_()
        return password_input.text(), result == QDialog.Accepted

    def check_password_strength(self, password):
        """Check and display password strength"""
        strength = self.generator.calculate_strength_score(password)
        crack_info = self.generator.estimate_crack_time(password)

        self.strength_bar.set_score(strength)
        self.strength_label.setText(f"{theme.strength_text(strength)} · cracked in {crack_info['time_string']}")
        self.strength_label.setProperty("role", theme.strength_role(strength))
        self.strength_label.style().unpolish(self.strength_label)
        self.strength_label.style().polish(self.strength_label)
        self.strength_bar.show()
        self.strength_label.show()

    def toggle_password_visibility(self, state):
        """Show or hide the master password"""
        self.password_input.setPasswordVisible(state == Qt.Checked or state is True)

    def show_error(self, message):
        """Show error message"""
        QMessageBox.critical(self, "Error", message)

    def clear_form(self):
        """Clear the form"""
        self.password_input.clear()
        self.password_input.setPasswordVisible(False)
        self.strength_bar.hide()
        self.strength_label.hide()
