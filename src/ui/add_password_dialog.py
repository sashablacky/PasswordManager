import re
from urllib.parse import urlparse

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QComboBox, QTextEdit,
    QDialogButtonBox, QMessageBox, QCheckBox
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont

from security.generator import PasswordGenerator, GeneratorOptions


class AddPasswordDialog(QDialog):
    """Dialog for adding or editing a password entry"""

    password_added = pyqtSignal(int)
    password_updated = pyqtSignal(int)

    def __init__(self, password_manager, user_id, categories=None, password_data=None):
        super().__init__()

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
        self.setFixedSize(1000, 950)

        self.setStyleSheet("""
            QDialog { background-color: #f5f7fa; }
            QLineEdit, QTextEdit, QComboBox {
                padding: 10px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 14px;
                background-color: white;
            }
            QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
                border-color: #667eea;
            }
            QLabel {
                color: #2c3e50;
                font-weight: bold;
                font-size: 12px;
            }
        """)

        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(30, 30, 30, 30)

        # Title label only (NO input field anymore)
        title_label = QLabel("🔐 Add New Password" if not self.is_edit else "🔐 Edit Password")
        font = QFont()
        font.setPointSize(20)
        font.setBold(True)
        title_label.setFont(font)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #667eea; margin-bottom: 20px;")
        layout.addWidget(title_label)

        form = QVBoxLayout()
        form.setSpacing(10)

        # Username
        form.addWidget(QLabel("Username/Email *"))
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username or email")
        form.addWidget(self.username_input)

        # Password
        form.addWidget(QLabel("Password *"))
        pw_layout = QHBoxLayout()

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter password")
        pw_layout.addWidget(self.password_input)

        generate_btn = QPushButton("🎲 Generate")
        generate_btn.setFixedWidth(110)
        generate_btn.clicked.connect(self.generate_password)
        generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px;
            }
            QPushButton:hover { background-color: #2980b9; }
        """)
        pw_layout.addWidget(generate_btn)

        form.addLayout(pw_layout)

        # Show password
        self.show_password_cb = QCheckBox("Show password")
        self.show_password_cb.stateChanged.connect(self.toggle_password_visibility)
        form.addWidget(self.show_password_cb)

        # Strength
        self.strength_label = QLabel("")
        self.strength_label.setAlignment(Qt.AlignCenter)
        form.addWidget(self.strength_label)

        # URL
        form.addWidget(QLabel("URL"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        form.addWidget(self.url_input)

        # Category
        form.addWidget(QLabel("Category"))
        self.category_combo = QComboBox()
        self.category_combo.addItem("None", None)
        form.addWidget(self.category_combo)

        # Notes
        form.addWidget(QLabel("Notes"))
        self.notes_input = QTextEdit()
        self.notes_input.setMaximumHeight(100)
        form.addWidget(self.notes_input)

        # Favorite
        self.favorite_cb = QCheckBox("⭐ Mark as favorite")
        form.addWidget(self.favorite_cb)

        layout.addLayout(form)
        layout.addStretch()

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save_password)
        buttons.rejected.connect(self.reject)

        layout.addWidget(buttons)
        self.setLayout(layout)

        self.password_input.textChanged.connect(self.update_strength)

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

    # -------------------------
    # Data
    # -------------------------
    def load_categories(self):
        for c in self.categories:
            self.category_combo.addItem(
                f"{c.get('icon', '📁')} {c['name']}",
                c['category_id']
            )

    def load_password_data(self):
        self.username_input.setText(getattr(self.password_data, 'username', ''))
        self.password_input.setText(getattr(self.password_data, 'password', ''))
        self.url_input.setText(getattr(self.password_data, 'url', ''))
        self.notes_input.setText(getattr(self.password_data, 'notes', ''))
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
            from PyQt5.QtWidgets import QApplication
            QApplication.clipboard().setText(password)

    def toggle_password_visibility(self, state):
        if state == Qt.Checked:
            self.password_input.setEchoMode(QLineEdit.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.Password)

    def update_strength(self):
        """Update password strength indicator (same style as generator dialog)"""
        password = self.password_input.text()

        if not password:
            self.strength_label.setText("")
            self.strength_label.hide()
            return

        strength = self.generator.calculate_strength_score(password)
        crack_info = self.generator.estimate_crack_time(password)

        if strength < 30:
            color = "#e74c3c"
            text = "Very Weak"
        elif strength < 50:
            color = "#e67e22"
            text = "Weak"
        elif strength < 75:
            color = "#f39c12"
            text = "Medium"
        else:
            color = "#27ae60"
            text = "Strong"

        self.strength_label.setText(
            f"Strength: {text} ({strength}/100) - {crack_info['time_string']}"
        )

        self.strength_label.setStyleSheet(f"""
            background-color: {color};
            color: white;
            font-weight: bold;
            border-radius: 5px;
            padding: 8px;
        """)

        self.strength_label.show()

    # -------------------------
    # Save
    # -------------------------
    def save_password(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        url = self.url_input.text().strip()

        if not username:
            QMessageBox.warning(self, "Error", "Username is required")
            return

        if not password:
            QMessageBox.warning(self, "Error", "Password is required")
            return

        # AUTO TITLE FROM URL
        title = self.extract_title_from_url(url)

        notes = self.notes_input.toPlainText().strip()
        category_id = self.category_combo.currentData()
        is_fav = self.favorite_cb.isChecked()

        try:
            if self.is_edit:
                success = self.password_manager.update_password(
                    password_id=self.password_data.password_id,
                    user_id=self.user_id,
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
                    title=title,   # <-- AUTO GENERATED
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