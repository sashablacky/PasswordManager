"""
Password Generator Dialog
"""

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QSpinBox, QCheckBox,
                             QGroupBox, QSlider, QMessageBox, QApplication)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

from security.generator import PasswordGenerator, GeneratorOptions


class PasswordGeneratorDialog(QDialog):
    """Dialog for generating strong passwords"""

    def __init__(self, generator=None):
        """
        Initialize dialog

        Args:
            generator: PasswordGenerator instance (optional)
        """
        super().__init__()
        self.generator = generator or PasswordGenerator()
        self.current_password = ""
        self.setup_ui()
        self.generate_password()

    def setup_ui(self):
        """Setup the user interface"""
        self.setWindowTitle("Password Generator")
        self.setFixedSize(1000, 1000)
        self.setStyleSheet("""
            QDialog {
                background-color: #f5f7fa;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QLineEdit, QSpinBox {
                padding: 8px;
                border: 2px solid #e0e0e0;
                border-radius: 5px;
                font-size: 14px;
            }
            QLineEdit:focus, QSpinBox:focus {
                border-color: #667eea;
            }
            QCheckBox {
                font-size: 12px;
            }
            QSlider::groove:horizontal {
                height: 8px;
                background: #e0e0e0;
                border-radius: 4px;
            }
            QSlider::handle:horizontal {
                background: #667eea;
                width: 18px;
                margin: -5px 0;
                border-radius: 9px;
            }
            QPushButton {
                padding: 10px 20px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: bold;
            }
        """)

        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)

        # Title
        title_label = QLabel("🎲 Password Generator")
        title_font = QFont()
        title_font.setPointSize(20)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #667eea; margin-bottom: 10px;")
        layout.addWidget(title_label)

        # Generated password display
        password_group = QGroupBox("Generated Password")
        password_layout = QVBoxLayout()

        self.password_display = QLineEdit()
        self.password_display.setReadOnly(True)
        self.password_display.setStyleSheet("""
            QLineEdit {
                font-family: monospace;
                font-size: 18px;
                padding: 15px;
                background-color: white;
                border: 2px solid #667eea;
            }
        """)
        password_layout.addWidget(self.password_display)

        # Strength indicator
        self.strength_label = QLabel()
        self.strength_label.setAlignment(Qt.AlignCenter)
        self.strength_label.setStyleSheet("padding: 8px; border-radius: 5px;")
        password_layout.addWidget(self.strength_label)

        # Action buttons for password
        action_layout = QHBoxLayout()

        copy_btn = QPushButton("📋 Copy")
        copy_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        copy_btn.clicked.connect(self.copy_to_clipboard)
        action_layout.addWidget(copy_btn)

        regenerate_btn = QPushButton("🔄 Regenerate")
        regenerate_btn.setStyleSheet("""
            QPushButton {
                background-color: #667eea;
                color: white;
            }
            QPushButton:hover {
                background-color: #5568d3;
            }
        """)
        regenerate_btn.clicked.connect(self.generate_password)
        action_layout.addWidget(regenerate_btn)

        password_layout.addLayout(action_layout)
        password_group.setLayout(password_layout)
        layout.addWidget(password_group)

        # Options group
        options_group = QGroupBox("Generation Options")
        options_layout = QVBoxLayout()
        options_layout.setSpacing(15)

        # Length control
        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel("Password Length:"))

        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 128)
        self.length_spin.setValue(16)
        self.length_spin.valueChanged.connect(self.generate_password)
        length_layout.addWidget(self.length_spin)

        self.length_slider = QSlider(Qt.Horizontal)
        self.length_slider.setRange(8, 128)
        self.length_slider.setValue(16)
        self.length_slider.valueChanged.connect(self.length_spin.setValue)
        length_layout.addWidget(self.length_slider)

        options_layout.addLayout(length_layout)

        # Character types
        char_types_group = QGroupBox("Character Types")
        char_types_layout = QVBoxLayout()

        self.uppercase_cb = QCheckBox("Include Uppercase Letters (A-Z)")
        self.uppercase_cb.setChecked(True)
        self.uppercase_cb.stateChanged.connect(self.generate_password)
        char_types_layout.addWidget(self.uppercase_cb)

        self.lowercase_cb = QCheckBox("Include Lowercase Letters (a-z)")
        self.lowercase_cb.setChecked(True)
        self.lowercase_cb.stateChanged.connect(self.generate_password)
        char_types_layout.addWidget(self.lowercase_cb)

        self.digits_cb = QCheckBox("Include Numbers (0-9)")
        self.digits_cb.setChecked(True)
        self.digits_cb.stateChanged.connect(self.generate_password)
        char_types_layout.addWidget(self.digits_cb)

        self.symbols_cb = QCheckBox("Include Symbols (!@#$%...)")
        self.symbols_cb.setChecked(True)
        self.symbols_cb.stateChanged.connect(self.generate_password)
        char_types_layout.addWidget(self.symbols_cb)

        char_types_group.setLayout(char_types_layout)
        options_layout.addWidget(char_types_group)

        # Advanced options
        advanced_group = QGroupBox("Advanced Options")
        advanced_layout = QVBoxLayout()

        self.exclude_ambiguous_cb = QCheckBox("Exclude Ambiguous Characters (0, O, l, 1, I)")
        self.exclude_ambiguous_cb.stateChanged.connect(self.generate_password)
        advanced_layout.addWidget(self.exclude_ambiguous_cb)

        self.exclude_similar_cb = QCheckBox("Exclude Similar Characters (il1Lo0O)")
        self.exclude_similar_cb.stateChanged.connect(self.generate_password)
        advanced_layout.addWidget(self.exclude_similar_cb)

        advanced_group.setLayout(advanced_layout)
        options_layout.addWidget(advanced_group)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        # Passphrase option
        passphrase_group = QGroupBox("Passphrase (Memorable)")
        passphrase_layout = QVBoxLayout()

        generate_passphrase_btn = QPushButton("Generate Passphrase")
        generate_passphrase_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
            }
            QPushButton:hover {
                background-color: #229954;
            }
        """)
        generate_passphrase_btn.clicked.connect(self.generate_passphrase)
        passphrase_layout.addWidget(generate_passphrase_btn)

        self.passphrase_display = QLineEdit()
        self.passphrase_display.setReadOnly(True)
        self.passphrase_display.setStyleSheet("font-family: monospace;")
        passphrase_layout.addWidget(self.passphrase_display)

        passphrase_group.setLayout(passphrase_layout)
        layout.addWidget(passphrase_group)

        # Close button
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignCenter)

        self.setLayout(layout)

    def generate_password(self):
        """Generate a new password based on current options"""
        # Ensure at least one character type is selected
        if not any([
            self.uppercase_cb.isChecked(),
            self.lowercase_cb.isChecked(),
            self.digits_cb.isChecked(),
            self.symbols_cb.isChecked()
        ]):
            QMessageBox.warning(self, "Warning", "Select at least one character type")
            return

        options = GeneratorOptions(
            length=self.length_spin.value(),
            use_uppercase=self.uppercase_cb.isChecked(),
            use_lowercase=self.lowercase_cb.isChecked(),
            use_digits=self.digits_cb.isChecked(),
            use_symbols=self.symbols_cb.isChecked(),
            exclude_ambiguous=self.exclude_ambiguous_cb.isChecked(),
            exclude_similar=self.exclude_similar_cb.isChecked()
        )

        self.current_password = self.generator.generate(options)
        self.password_display.setText(self.current_password)

        # Update strength indicator
        self.update_strength()

    def generate_passphrase(self):
        """Generate a memorable passphrase"""
        passphrase = self.generator.generate_passphrase(
            word_count=4,
            separator="-",
            capitalize=True,
            add_number=True
        )
        self.passphrase_display.setText(passphrase)

    def update_strength(self):
        """Update password strength indicator"""
        if not self.current_password:
            return

        strength = self.generator.calculate_strength_score(self.current_password)
        crack_info = self.generator.estimate_crack_time(self.current_password)

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

    def copy_to_clipboard(self):
        """Copy current password to clipboard"""
        if self.current_password:
            clipboard = QApplication.clipboard()
            clipboard.setText(self.current_password)
            QMessageBox.information(self, "Copied", "Password copied to clipboard!")


if __name__ == '__main__':
    import sys
    from PyQt5.QtWidgets import QApplication

    app = QApplication(sys.argv)
    dialog = PasswordGeneratorDialog()
    dialog.exec_()