"""
Password generator: a page of the main window (GeneratorPage) and the same page
in a stand-alone dialog (PasswordGeneratorDialog).
"""

import html

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QWidget,
                             QMessageBox, QStackedWidget, QBoxLayout)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QPainter

from qfluentwidgets import (SegmentedWidget, Slider, SpinBox, SwitchButton, PushButton,
                            ComboBox, InfoBar, InfoBarPosition, FluentIcon)
from security.generator import PasswordGenerator, GeneratorOptions
from ui import theme
from ui.clipboard import copy_secret, CLIPBOARD_CLEAR_SECONDS
from ui.layout_utils import set_scrollable_layout

SEPARATORS = [("Hyphen  -", "-"), ("Dot  .", "."), ("Underscore  _", "_"), ("Space", " ")]


def _switch():
    switch = SwitchButton()
    switch.setOnText("")
    switch.setOffText("")
    return switch


class ToggleRow(QWidget):
    """One option of the generator: name, small example of the characters, switch"""

    def __init__(self, text, sample, switch, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 8, 0, 8)
        names = QVBoxLayout()
        names.setSpacing(0)
        names.addWidget(theme.label(text, size=14))
        if sample:
            names.addWidget(theme.label(sample, role="faint", size=12, mono=True))
        layout.addLayout(names, 1)
        layout.addWidget(switch, 0, Qt.AlignVCenter)

    def paintEvent(self, e):
        # hairline above every row, as in the mock-up
        painter = QPainter(self)
        painter.setPen(theme.current().glass_line)
        painter.drawLine(0, 0, self.width(), 0)


class GeneratorPage(QWidget):
    """Generates passwords and passphrases; vertical=True stacks the cards (dialog)"""

    save_requested = pyqtSignal(str)  # "Save as new entry" with the generated password

    def __init__(self, generator=None, parent=None, vertical=False, can_save=False):
        super().__init__(parent)
        self.setObjectName("generatorPage")
        self.generator = generator or PasswordGenerator()
        self.current_password = ""
        self.copied = False  # True once the user copied a password to the clipboard
        self.mode = "password"
        self.vertical = vertical
        self.can_save = can_save
        self.setup_ui()
        self.generate_password()
        theme.signals.changed.connect(self._on_theme_changed)

    def setup_ui(self):
        layout = QVBoxLayout(self)
        margins = (0, 0, 0, 0) if self.vertical else (6, 6, 18, 18)
        layout.setContentsMargins(*margins)
        layout.setSpacing(14)

        if not self.vertical:
            layout.addWidget(theme.title_label("Password generator"))

        body = QBoxLayout(QBoxLayout.TopToBottom if self.vertical else QBoxLayout.LeftToRight)
        body.setSpacing(14)
        layout.addLayout(body, 1)

        # ---- output card
        out = theme.GlassCard()
        out_layout = QVBoxLayout(out)
        out_layout.setContentsMargins(24, 22, 24, 22)
        out_layout.setSpacing(16)

        self.mode_switch = SegmentedWidget()
        self.mode_switch.addItem("password", "Password", lambda: self.set_mode("password"))
        self.mode_switch.addItem("passphrase", "Passphrase", lambda: self.set_mode("passphrase"))
        self.mode_switch.setCurrentItem("password")
        self.mode_switch.setFixedWidth(240)
        out_layout.addWidget(self.mode_switch, 0, Qt.AlignLeft)

        well = theme.WellFrame(radius=10, alpha=0.45)
        well_layout = QVBoxLayout(well)
        well_layout.setContentsMargins(22, 20, 22, 20)
        self.password_display = theme.label("", mono=True, size=26 if not self.vertical else 22)
        self.password_display.setWordWrap(True)
        self.password_display.setMinimumHeight(40)
        self.password_display.setTextFormat(Qt.RichText)
        well_layout.addWidget(self.password_display)
        out_layout.addWidget(well)

        strength_row = QHBoxLayout()
        strength_row.setSpacing(12)
        strength_row.addWidget(theme.label("Strength", role="muted", size=13))
        self.strength_bar = theme.StrengthBar()
        strength_row.addWidget(self.strength_bar, 1)
        self.strength_label = theme.label("", size=13, weight=QFont.DemiBold)
        strength_row.addWidget(self.strength_label)
        out_layout.addLayout(strength_row)
        self.crack_label = theme.label("", role="faint", size=12)
        out_layout.addWidget(self.crack_label)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        copy_btn = theme.primary_button("Copy", FluentIcon.COPY)
        copy_btn.clicked.connect(self.copy_to_clipboard)
        actions.addWidget(copy_btn)
        regenerate_btn = PushButton(FluentIcon.SYNC, "Regenerate")
        regenerate_btn.clicked.connect(self.regenerate)
        actions.addWidget(regenerate_btn)
        self.save_btn = PushButton(FluentIcon.ADD, "Save as new entry")
        self.save_btn.clicked.connect(lambda: self.save_requested.emit(self.current_password))
        self.save_btn.setVisible(self.can_save)
        actions.addWidget(self.save_btn)
        actions.addStretch(1)
        out_layout.addLayout(actions)
        out_layout.addStretch(1)

        hint = theme.label(
            "Nothing generated here is stored until you save it as an entry. "
            f"A copied password is cleared from the clipboard after {CLIPBOARD_CLEAR_SECONDS} seconds.",
            role="faint", size=12)
        hint.setWordWrap(True)
        out_layout.addWidget(hint)

        body.addWidget(out, 1)

        # ---- options card
        opts = theme.GlassCard()
        if not self.vertical:
            opts.setFixedWidth(370)
        opts_layout = QVBoxLayout(opts)
        opts_layout.setContentsMargins(22, 18, 22, 14)
        opts_layout.setSpacing(4)
        opts_layout.addWidget(theme.label("Options", size=15, weight=QFont.DemiBold, display=True))

        self.options_stack = QStackedWidget()
        self.options_stack.addWidget(self._password_options())
        self.options_stack.addWidget(self._passphrase_options())
        opts_layout.addWidget(self.options_stack)
        opts_layout.addStretch(1)
        body.addWidget(opts, 0)

    def _length_row(self, minimum, maximum, value, text):
        row = QHBoxLayout()
        row.setContentsMargins(0, 6, 0, 12)
        row.setSpacing(12)
        row.addWidget(theme.label(text, role="muted", size=14))
        slider = Slider(Qt.Horizontal)
        slider.setRange(minimum, maximum)
        slider.setValue(value)
        row.addWidget(slider, 1)
        spin = SpinBox()
        spin.setRange(minimum, maximum)
        spin.setValue(value)
        spin.setFixedWidth(118)
        row.addWidget(spin)
        # keep slider and number in step
        slider.valueChanged.connect(spin.setValue)
        spin.valueChanged.connect(slider.setValue)
        return row, slider, spin

    def _password_options(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(0)

        row, self.length_slider, self.length_spin = self._length_row(8, 128, 16, "Length")
        self.length_spin.valueChanged.connect(self.generate_password)
        layout.addLayout(row)

        self.uppercase_cb = _switch()
        self.lowercase_cb = _switch()
        self.digits_cb = _switch()
        self.symbols_cb = _switch()
        self.exclude_ambiguous_cb = _switch()
        self.exclude_similar_cb = _switch()
        rows = [
            ("Uppercase", "A–Z", self.uppercase_cb, True),
            ("Lowercase", "a–z", self.lowercase_cb, True),
            ("Numbers", "0–9", self.digits_cb, True),
            ("Symbols", "! @ # $ % ^ & *", self.symbols_cb, True),
            ("Exclude ambiguous", "0 O l 1 I", self.exclude_ambiguous_cb, False),
            ("Exclude similar", "i l 1 L o 0 O", self.exclude_similar_cb, False),
        ]
        for text, sample, switch, checked in rows:
            switch.setChecked(checked)
            switch.checkedChanged.connect(self.generate_password)
            layout.addWidget(ToggleRow(text, sample, switch))
        return page

    def _passphrase_options(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(0)

        row, self.words_slider, self.words_spin = self._length_row(3, 8, 4, "Words")
        self.words_spin.valueChanged.connect(self.generate_passphrase)
        layout.addLayout(row)

        sep_row = QHBoxLayout()
        sep_row.setContentsMargins(0, 8, 0, 8)
        sep_row.addWidget(theme.label("Separator", size=14), 1)
        self.separator_combo = ComboBox()
        for text, value in SEPARATORS:
            self.separator_combo.addItem(text, userData=value)
        self.separator_combo.currentIndexChanged.connect(self.generate_passphrase)
        sep_row.addWidget(self.separator_combo)
        sep_holder = QWidget()
        sep_holder.setLayout(sep_row)
        layout.addWidget(sep_holder)

        self.capitalize_cb = _switch()
        self.add_number_cb = _switch()
        for text, sample, switch in [("Capitalize words", "Orbit-Maple", self.capitalize_cb),
                                     ("Add a number", "…-River42", self.add_number_cb)]:
            switch.setChecked(True)
            switch.checkedChanged.connect(self.generate_passphrase)
            layout.addWidget(ToggleRow(text, sample, switch))
        return page

    # ---------------------------------------------------------------- logic

    def set_mode(self, mode):
        self.mode = mode
        self.mode_switch.setCurrentItem(mode)
        self.options_stack.setCurrentIndex(0 if mode == "password" else 1)
        self.regenerate()

    def regenerate(self):
        if self.mode == "password":
            self.generate_password()
        else:
            self.generate_passphrase()

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
            # Undo the click that left no character types selected
            sender = self.sender()
            if isinstance(sender, SwitchButton):
                sender.blockSignals(True)
                sender.setChecked(True)
                sender.blockSignals(False)
            return

        if self.mode != "password":
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

        self.show_password(self.generator.generate(options))

    def generate_passphrase(self):
        """Generate a memorable passphrase"""
        if self.mode != "passphrase":
            return
        passphrase = self.generator.generate_passphrase(
            word_count=self.words_spin.value(),
            separator=self.separator_combo.currentData() or "-",
            capitalize=self.capitalize_cb.isChecked(),
            add_number=self.add_number_cb.isChecked()
        )
        self.show_password(passphrase)

    def show_password(self, password):
        self.current_password = password
        self.password_display.setText(self.colorize(password))
        self.update_strength()

    @staticmethod
    def colorize(password):
        """Digits and symbols in their own colours, with break points so long passwords wrap"""
        p = theme.current()
        parts = []
        for ch in password:
            text = html.escape(ch) if ch != " " else "&nbsp;"
            if ch.isdigit():
                text = f'<span style="color:{p.warn}">{text}</span>'
            elif not ch.isalnum():
                text = f'<span style="color:{p.ok}">{text}</span>'
            parts.append(text)
        # zero-width spaces let the label wrap; the text is not selectable, Copy is the way out
        return "&#8203;".join(parts)

    def update_strength(self):
        """Update password strength indicator"""
        if not self.current_password:
            return

        strength = self.generator.calculate_strength_score(self.current_password)
        crack_info = self.generator.estimate_crack_time(self.current_password)

        self.strength_bar.set_score(strength)
        self.strength_label.setText(f"{theme.strength_text(strength)} ({strength}/100)")
        self.strength_label.setProperty("role", theme.strength_role(strength))
        self.strength_label.style().unpolish(self.strength_label)
        self.strength_label.style().polish(self.strength_label)
        self.crack_label.setText(f"Time to crack offline: {crack_info['time_string'].lower()}")

    def copy_to_clipboard(self):
        """Copy current password to clipboard"""
        if self.current_password:
            copy_secret(self.current_password)
            self.copied = True
            InfoBar.success(
                "Copied", f"The clipboard is cleared in {CLIPBOARD_CLEAR_SECONDS} seconds.",
                duration=2500, position=InfoBarPosition.TOP_RIGHT, parent=self.window()
            )

    def _on_theme_changed(self, key):
        try:
            if self.current_password:
                self.password_display.setText(self.colorize(self.current_password))
            self.update()
        except RuntimeError:
            pass


class PasswordGeneratorDialog(QDialog):
    """The generator page in its own window"""

    def __init__(self, generator=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Password Generator")
        self.setWindowIcon(theme.app_icon())
        # Fits small laptop screens (1366x768); the user can still enlarge it
        self.setMinimumSize(560, 600)
        self.resize(620, 700)

        self.page = GeneratorPage(generator, vertical=True)

        layout = QVBoxLayout()
        layout.setContentsMargins(24, 24, 24, 10)
        layout.setSpacing(14)
        layout.addWidget(theme.label("Password generator", size=22, weight=QFont.DemiBold, display=True))
        layout.addWidget(self.page)

        close_btn = PushButton("Close")
        close_btn.setMinimumWidth(100)
        close_btn.clicked.connect(self.accept)
        # Scrollable options with the Close button always visible (fits small screens)
        set_scrollable_layout(self, layout, close_btn, Qt.AlignRight)

    def paintEvent(self, e):
        theme.paint_backdrop(QPainter(self), self.rect())

    def __getattr__(self, name):
        # Expose the page's widgets and methods (current_password, copied, generate_password...)
        if name == "page":
            raise AttributeError(name)
        return getattr(self.page, name)


if __name__ == '__main__':
    import sys
    from PyQt5.QtWidgets import QApplication

    app = QApplication(sys.argv)
    theme.init_theme()
    dialog = PasswordGeneratorDialog()
    dialog.exec_()
