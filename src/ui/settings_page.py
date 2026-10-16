"""
Settings page: colour theme, vault operations that used to be in the menu bar
(master password, export/import, backup/restore), browser extension, tools and "About".
"""

from PyQt5.QtCore import Qt, QRectF, QSize, pyqtSignal
from PyQt5.QtGui import QFont, QPainter, QPen, QColor
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QAbstractButton, QButtonGroup, QFrame)

from qfluentwidgets import (SettingCardGroup, SettingCard, PushSettingCard, SwitchSettingCard, ComboBox,
                            FluentIcon, ScrollArea)
import app_settings
from ui import theme
from ui.clipboard import CLIPBOARD_CLEAR_SECONDS
from ui.icons import AppIcon


class ThemeSwatch(QAbstractButton):
    """A theme choice: four colour chips of the palette and its name"""

    def __init__(self, palette, note="", parent=None):
        super().__init__(parent)
        self.palette_ = palette
        self.note = note
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip(f"{palette.name} theme")
        self.setFixedSize(QSize(200, 64))
        theme.signals.changed.connect(self._on_theme_changed)

    def _on_theme_changed(self, key):
        try:
            self.update()
        except RuntimeError:
            pass

    def text(self):
        return self.palette_.name

    def enterEvent(self, e):
        self.update()

    def leaveEvent(self, e):
        self.update()

    def paintEvent(self, e):
        cur = theme.current()
        sw = self.palette_
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        fill = cur.color("text", 0.08) if (self.isChecked() or self.underMouse()) else cur.color("text", 0.03)
        r = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        painter.setBrush(fill)
        if self.isChecked():
            painter.setPen(QPen(QColor(cur.accent2), 2))
        else:
            painter.setPen(QPen(cur.glass_line, 1))
        painter.drawRoundedRect(r, 9, 9)

        # colour chips
        chips = QRectF(12, 14, 64, 36)
        painter.save()
        from PyQt5.QtGui import QPainterPath
        path = QPainterPath()
        path.addRoundedRect(chips, 6, 6)
        painter.setClipPath(path)
        painter.setPen(Qt.NoPen)
        for i, color in enumerate((sw.n0, sw.n1, sw.n2, sw.accent)):
            painter.setBrush(QColor(color))
            painter.drawRect(QRectF(chips.left() + i * 16, chips.top(), 16, chips.height()))
        painter.restore()

        painter.setPen(QColor(cur.text))
        painter.setFont(theme.ui_font(14, QFont.DemiBold))
        painter.drawText(QRectF(88, 12, self.width() - 96, 22), Qt.AlignLeft | Qt.AlignVCenter, sw.name)
        if self.note:
            painter.setPen(cur.muted)
            painter.setFont(theme.ui_font(12))
            painter.drawText(QRectF(88, 32, self.width() - 96, 18), Qt.AlignLeft | Qt.AlignVCenter, self.note)


class ThemeCard(theme.GlassCard):
    theme_selected = pyqtSignal(str)

    NOTES = {"midnight": "Deep blue", "slate": "Blue grey", "dusk": "Muted (default)"}

    def __init__(self, parent=None):
        super().__init__(parent, radius=8)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 18)
        layout.setSpacing(4)
        layout.addWidget(theme.label("Theme", size=14))
        layout.addWidget(theme.label("Applies right away and is remembered for the next start.",
                                     role="muted", size=12))
        row = QHBoxLayout()
        row.setContentsMargins(0, 12, 0, 0)
        row.setSpacing(12)
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        self.swatches = {}
        for key in theme.THEME_ORDER:
            swatch = ThemeSwatch(theme.THEMES[key], self.NOTES.get(key, ""))
            swatch.setChecked(key == theme.current_key())
            swatch.clicked.connect(lambda checked=False, k=key: self.theme_selected.emit(k))
            self.group.addButton(swatch)
            self.swatches[key] = swatch
            row.addWidget(swatch)
        row.addStretch(1)
        layout.addLayout(row)
        # The settings group lays its cards out by their fixed height
        self.setFixedHeight(self.sizeHint().height())

    def set_current(self, key):
        if key in self.swatches:
            self.swatches[key].setChecked(True)


class AutoLockCard(SettingCard):
    """How long the vault stays unlocked without activity"""

    minutes_changed = pyqtSignal(int)

    def __init__(self, app, parent=None):
        super().__init__(AppIcon.LOCK, "Lock automatically",
                         "After this time without activity in the program or the browser extension", parent)
        self.choices = app_settings.AUTO_LOCK_CHOICES
        self.combo = ComboBox(self)
        self.combo.addItems([f"{m} minutes" for m in self.choices])
        if app.auto_lock_minutes in self.choices:
            self.combo.setCurrentIndex(self.choices.index(app.auto_lock_minutes))
        self.combo.currentIndexChanged.connect(lambda i: self.minutes_changed.emit(self.choices[i]))
        self.hBoxLayout.addWidget(self.combo, 0, Qt.AlignRight)
        self.hBoxLayout.addSpacing(16)


class SettingsPage(ScrollArea):
    """All settings in one scrollable page"""

    def __init__(self, window, parent=None):
        super().__init__(parent)
        self.setObjectName("pageScroll")
        self.window_ = window
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        content = QWidget()
        content.setObjectName("pageScrollContent")
        self.setWidget(content)
        self.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        self.viewport().setStyleSheet("background: transparent;")

        layout = QVBoxLayout(content)
        layout.setContentsMargins(6, 6, 24, 24)
        layout.setSpacing(22)
        layout.addWidget(theme.title_label("Settings"))

        # Appearance
        appearance = SettingCardGroup("Appearance", content)
        self.theme_card = ThemeCard()
        self.theme_card.theme_selected.connect(self.window_.set_theme)
        appearance.addSettingCard(self.theme_card)
        layout.addWidget(appearance)

        # Vault
        vault = SettingCardGroup("Vault", content)
        cards = [
            (AppIcon.KEY, "Change master password",
             "Re-encrypts the vault with a new master password", "Change", window.change_master_password),
            (FluentIcon.SHARE, "Export passwords",
             "Save all entries to a CSV file (NOT encrypted)", "Export", window.export_passwords),
            (FluentIcon.DOWNLOAD, "Import passwords",
             "Add entries from a CSV file (Title, Username, Password, URL, Notes)", "Import",
             window.import_passwords),
            (FluentIcon.SAVE_COPY, "Create backup",
             "Copy the encrypted vault file to a place you choose", "Back up", window.create_backup),
            (FluentIcon.HISTORY, "Restore from backup",
             "Replace the vault with a backup (the current one is kept as a copy)", "Restore",
             window.restore_backup),
        ]
        self.auto_lock_card = AutoLockCard(window.app)
        self.auto_lock_card.minutes_changed.connect(self._on_auto_lock_changed)
        vault.addSettingCard(self.auto_lock_card)
        self.vault_cards = {}
        for icon, title, content_text, button_text, slot in cards:
            card = PushSettingCard(button_text, icon, title, content_text)
            card.clicked.connect(slot)
            vault.addSettingCard(card)
            self.vault_cards[title] = card
        layout.addWidget(vault)

        # Browser extension
        browser = SettingCardGroup("Browser extension", content)
        self.browser_switch = SwitchSettingCard(
            FluentIcon.GLOBE, "Allow browser extension",
            "Firefox and Safari can fill in and save passwords once you allow them here"
        )
        self.browser_switch.setChecked(window.app.bridge is not None)
        self.browser_switch.checkedChanged.connect(window.set_browser_integration)
        browser.addSettingCard(self.browser_switch)
        self.browsers_card = PushSettingCard("Disconnect all", FluentIcon.LINK, "Connected browsers", "")
        self.browsers_card.clicked.connect(window.forget_browsers)
        browser.addSettingCard(self.browsers_card)
        layout.addWidget(browser)
        self.update_browser_status()

        # Tools
        tools = SettingCardGroup("Tools", content)
        health = PushSettingCard("Open report", FluentIcon.PIE_SINGLE, "Password health check",
                                 "Totals by strength, average strength and the weakest entries")
        health.clicked.connect(window.show_health_check)
        tools.addSettingCard(health)
        layout.addWidget(tools)

        # About
        about = SettingCardGroup("About", content)
        self.about_card = about_card = PushSettingCard("About", FluentIcon.INFO, "Password Manager", "")
        self._update_about_text()
        about_card.clicked.connect(window.show_about)
        about.addSettingCard(about_card)
        layout.addWidget(about)

        layout.addStretch(1)

    def _update_about_text(self):
        self.about_card.setContent(
            f"Locks itself after {self.window_.app.auto_lock_minutes} minutes without activity. Copied passwords "
            f"are cleared from the clipboard after {CLIPBOARD_CLEAR_SECONDS} seconds."
        )

    def _on_auto_lock_changed(self, minutes):
        self.window_.app.set_auto_lock_minutes(minutes)
        self._update_about_text()

    def update_browser_status(self):
        count = len(self.window_.paired_browsers())
        if count:
            self.browsers_card.setContent(f"{count} connected. Disconnect them if a computer or browser "
                                          f"is no longer yours; they can connect again with your approval.")
        else:
            self.browsers_card.setContent("No browser is connected yet. Click \"Connect\" in the extension "
                                          "and allow it here.")
        self.browsers_card.button.setEnabled(bool(count))

    def showEvent(self, e):
        super().showEvent(e)
        self.update_browser_status()
