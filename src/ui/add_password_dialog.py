from urllib.parse import urlparse

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QMessageBox, QWidget
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QPainter

from qfluentwidgets import LineEdit, ComboBox, TextEdit, CheckBox, PushButton, FluentIcon
from security.generator import PasswordGenerator, GeneratorOptions
from ui import theme
from ui.clipboard import copy_secret
from ui.icons import AppIcon
from ui.layout_utils import set_scrollable_layout, resize_to_fit_screen


class AddPasswordDialog(QDialog):
    """Dialog for adding or editing a password entry"""

    password_added = pyqtSignal(int)
    password_updated = pyqtSignal(int)

    def __init__(self, password_manager, user_id, categories=None, password_data=None, parent=None):
        super().__init__(parent)

        self.password_manager = password_manager
        self.user_id = user_id
        self.categories = categories or []
        self.password_data = password_data
        self.generator = PasswordGenerator()
        self.is_edit = password_data is not None

        self.setup_ui()
        self.load_categories()

        if self.is_edit:
            self.load_password_data()

    # -------------------------
    # UI
    # -------------------------
    def setup_ui(self):
        self.setWindowTitle("Add Password" if not self.is_edit else "Edit Password")
        self.setWindowIcon(theme.app_icon())
        # Fits small laptop screens (1366x768); the user can still enlarge it
        self.setMinimumSize(520, 600)
        resize_to_fit_screen(self, 560, 720)

        layout = QVBoxLayout()
        layout.setSpacing(6)
        layout.setContentsMargins(30, 26, 30, 10)

        header = QHBoxLayout()
        header.setSpacing(14)
        self.avatar = theme.Avatar("", size=44, radius=11)
        header.addWidget(self.avatar)
        title_label = theme.label("New password" if not self.is_edit else "Edit password",
                                  size=22, weight=QFont.DemiBold, display=True)
        header.addWidget(title_label, 1)
        layout.addLayout(header)
        layout.addSpacing(12)

        # Title (filled in from the URL if left empty)
        layout.addWidget(self._field_label("Title"))
        self.title_input = LineEdit()
        self.title_input.setPlaceholderText("e.g. My Bank (taken from the URL if empty)")
        self.title_input.textChanged.connect(self.update_avatar)
        layout.addWidget(self.title_input)

        # Username
        layout.addWidget(self._field_label("Username / email"))
        self.username_input = LineEdit()
        self.username_input.setPlaceholderText("Optional (not needed for PIN codes or Wi-Fi)")
        layout.addWidget(self.username_input)

        # Password
        layout.addWidget(self._field_label("Password *"))
        pw_layout = QHBoxLayout()
        pw_layout.setSpacing(8)
        self.password_input = theme.reveal_line_edit()
        self.password_input.setPlaceholderText("Enter password")
        pw_layout.addWidget(self.password_input, 1)

        generate_btn = PushButton(AppIcon.DICE, "Generate")
        generate_btn.clicked.connect(self.generate_password)
        pw_layout.addWidget(generate_btn)
        layout.addLayout(pw_layout)

        # Strength
        strength_row = QHBoxLayout()
        strength_row.setSpacing(10)
        self.strength_bar = theme.StrengthBar()
        strength_row.addWidget(self.strength_bar, 1)
        self.strength_label = theme.label("", role="muted", size=12)
        strength_row.addWidget(self.strength_label)
        self.strength_widgets = (self.strength_bar, self.strength_label)
        layout.addSpacing(2)
        layout.addLayout(strength_row)

        # URL
        layout.addWidget(self._field_label("Website"))
        self.url_input = LineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        self.url_input.textChanged.connect(self.update_avatar)
        layout.addWidget(self.url_input)

        # Category
        layout.addWidget(self._field_label("Category"))
        self.category_combo = ComboBox()
        self.category_combo.addItem("None", userData=None)
        layout.addWidget(self.category_combo)

        # Notes
        layout.addWidget(self._field_label("Notes"))
        self.notes_input = TextEdit()
        self.notes_input.setFixedHeight(80)
        layout.addWidget(self.notes_input)

        # Favorite
        layout.addSpacing(6)
        self.favorite_cb = CheckBox("Add to favorites")
        layout.addWidget(self.favorite_cb)

        layout.addStretch()

        # Buttons
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.save_button = theme.primary_button("Save", FluentIcon.SAVE)
        self.save_button.clicked.connect(self.save_password)
        buttons.addWidget(self.save_button)
        cancel_button = PushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        buttons.addWidget(cancel_button)
        footer = QWidget()
        footer.setLayout(buttons)
        buttons.setContentsMargins(0, 0, 0, 0)

        # Scrollable form with the buttons always visible (fits small screens)
        set_scrollable_layout(self, layout, footer)

        self.password_input.textChanged.connect(self.update_strength)
        self.update_strength()

    def paintEvent(self, e):
        painter = QPainter(self)
        theme.paint_backdrop(painter, self.rect())

    @staticmethod
    def _field_label(text):
        widget = theme.label(text, role="muted", size=13)
        widget.setContentsMargins(0, 8, 0, 0)
        return widget

    # -------------------------
    # Helpers
    # -------------------------
    def extract_title_from_url(self, url: str) -> str:
        """Generate title from URL domain"""
        if not url:
            return "Unknown"

        if not url.startswith("http"):
            url = "https://" + url

        try:
            domain = urlparse(url).netloc
            domain = domain.replace("www.", "")
            name = domain.split(".")[0]
            return name.capitalize() if name else "Unknown"
        except Exception:
            return "Unknown"

    def update_avatar(self):
        url = self.url_input.text().strip()
        title = self.title_input.text().strip() or (self.extract_title_from_url(url) if url else "")
        self.avatar.set_title(title or "?")

    # -------------------------
    # Data
    # -------------------------
    def load_categories(self):
        for c in self.categories:
            self.category_combo.addItem(
                c['name'],
                icon=theme.dot_icon(theme.category_color(c.get('color'))),
                userData=c['category_id']
            )

    def load_password_data(self):
        self.title_input.setText(getattr(self.password_data, 'title', ''))
        self.username_input.setText(getattr(self.password_data, 'username', ''))
        self.password_input.setText(getattr(self.password_data, 'password', ''))
        self.url_input.setText(getattr(self.password_data, 'url', ''))
        self.notes_input.setPlainText(getattr(self.password_data, 'notes', ''))
        self.favorite_cb.setChecked(getattr(self.password_data, 'is_favorite', False))

        if self.password_data.category_id:
            idx = self.category_combo.findData(self.password_data.category_id)
            if idx >= 0:
                self.category_combo.setCurrentIndex(idx)

        self.update_strength()

    # -------------------------
    # Password tools
    # -------------------------
    def generate_password(self):
        options = GeneratorOptions(
            length=16,
            use_uppercase=True,
            use_lowercase=True,
            use_digits=True,
            use_symbols=True
        )

        password = self.generator.generate(options)
        self.password_input.setText(password)
        self.update_strength()

        reply = QMessageBox.question(
            self,
            "Generated",
            "Copy password to clipboard?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            copy_secret(password)

    def toggle_password_visibility(self, state):
        self.password_input.setPasswordVisible(state == Qt.Checked or state is True)

    def update_strength(self):
        """Update password strength indicator (same style as the generator)"""
        password = self.password_input.text()

        if not password:
            self.strength_bar.set_score(0)
            self.strength_label.setText("Strength")
            self.strength_label.setProperty("role", "faint")
        else:
            strength = self.generator.calculate_strength_score(password)
            crack_info = self.generator.estimate_crack_time(password)
            self.strength_bar.set_score(strength)
            self.strength_label.setText(
                f"{theme.strength_text(strength)} ({strength}/100) · {crack_info['time_string']}"
            )
            self.strength_label.setProperty("role", theme.strength_role(strength))

        self.strength_label.style().unpolish(self.strength_label)
        self.strength_label.style().polish(self.strength_label)

    # -------------------------
    # Save
    # -------------------------
    def save_password(self):
        username = self.username_input.text().strip()
        # Not stripped: leading/trailing spaces are part of the password
        password = self.password_input.text()
        url = self.url_input.text().strip()

        if not password:
            QMessageBox.warning(self, "Error", "Password is required")
            return

        # Title typed by the user, otherwise taken from the URL, otherwise the username.
        # The username is optional (PIN codes, Wi-Fi passwords), but then a title is needed.
        title = self.title_input.text().strip() or (self.extract_title_from_url(url) if url else username)
        if not title:
            QMessageBox.warning(self, "Error", "Enter a title, a URL or a username")
            return

        notes = self.notes_input.toPlainText().strip()
        category_id = self.category_combo.currentData()
        is_fav = self.favorite_cb.isChecked()

        try:
            if self.is_edit:
                success = self.password_manager.update_password(
                    password_id=self.password_data.password_id,
                    user_id=self.user_id,
                    title=title,
                    username=username,
                    password=password,
                    url=url,
                    notes=notes,
                    category_id=category_id
                )

                if success:
                    if is_fav != self.password_data.is_favorite:
                        self.password_manager.toggle_favorite(
                            self.password_data.password_id,
                            self.user_id
                        )

                    self.password_updated.emit(self.password_data.password_id)
                    self.accept()

            else:
                pid = self.password_manager.add_password(
                    user_id=self.user_id,
                    title=title,
                    username=username,
                    password=password,
                    url=url,
                    notes=notes,
                    category_id=category_id
                )

                if is_fav:
                    self.password_manager.toggle_favorite(pid, self.user_id)

                self.password_added.emit(pid)
                self.accept()

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
