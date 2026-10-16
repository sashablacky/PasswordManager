"""
The vault page of the main window: title, search, "New password", count chips,
the entry list on the left and the details of the selected entry on the right.

The page only builds and paints widgets; loading, filtering and the actions on
entries are done by MainWindow, which owns the data.
"""

from urllib.parse import urlparse

from PyQt5.QtCore import Qt, QRectF, QSize, QUrl
from PyQt5.QtGui import QFont, QPainter, QPen, QColor, QDesktopServices, QFontMetrics
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QStyle,
                             QStackedWidget, QButtonGroup, QListWidgetItem, QAbstractItemView,
                             QSizePolicy)

from qfluentwidgets import (ListWidget, ListItemDelegate, SearchLineEdit, PushButton, ToolButton, TransparentToolButton,
                            FluentIcon, setCustomStyleSheet)
from ui import theme
from ui.icons import AppIcon
from platform_utils import shortcut_label

ENTRY_ROLE = Qt.UserRole + 1   # dict with what the list shows (never the password itself)


def format_date(value, empty="Never"):
    if not value:
        return empty
    try:
        if hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%d %H:%M")
    except Exception:
        pass
    return str(value)


class EntryDelegate(ListItemDelegate):
    """One row of the entry list: avatar, title and username, favourite star, strength pill"""

    ROW_HEIGHT = 54

    def sizeHint(self, option, index):
        return QSize(option.rect.width(), self.ROW_HEIGHT)

    def paint(self, painter, option, index):
        entry = index.data(ENTRY_ROLE) or {}
        p = theme.current()
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setRenderHint(QPainter.TextAntialiasing)

        r = QRectF(option.rect).adjusted(4, 2, -4, -2)
        if option.state & QStyle.State_Selected:
            painter.setPen(QPen(p.color("text", 0.16), 1))
            painter.setBrush(p.color("text", 0.10))
            painter.drawRoundedRect(r.adjusted(0.5, 0.5, -0.5, -0.5), 7, 7)
        elif index.row() == self.hoverRow:
            painter.setPen(Qt.NoPen)
            painter.setBrush(p.color("text", 0.05))
            painter.drawRoundedRect(r, 7, 7)

        title = entry.get("title", "")
        theme.paint_avatar(painter, QRectF(r.left() + 10, r.center().y() - 17, 34, 34), title)

        # Strength pill on the right
        score = entry.get("score", 0)
        pill_text = theme.strength_text(score)
        pill_font = theme.ui_font(11, QFont.DemiBold)
        fm = QFontMetrics(pill_font)
        pill_w = fm.horizontalAdvance(pill_text) + 16
        pill = QRectF(r.right() - 10 - pill_w, r.center().y() - 10, pill_w, 20)
        color = p.color(theme.strength_role(score))
        fill = QColor(color)
        fill.setAlphaF(0.14)
        painter.setPen(Qt.NoPen)
        painter.setBrush(fill)
        painter.drawRoundedRect(pill, 10, 10)
        painter.setPen(color)
        painter.setFont(pill_font)
        painter.drawText(pill, Qt.AlignCenter, pill_text)

        right = pill.left() - 10
        if entry.get("favorite"):
            AppIcon.STAR_FILLED.render(painter, QRectF(right - 15, r.center().y() - 7.5, 15, 15),
                                       fill=p.accent2)
            right -= 25

        # Title and username
        left = r.left() + 56
        width = max(10, right - left)
        painter.setPen(QColor(p.text))
        title_font = theme.ui_font(14, QFont.DemiBold)
        painter.setFont(title_font)
        username = entry.get("username", "")
        if username:
            title_rect = QRectF(left, r.top() + 7, width, 20)
        else:
            title_rect = QRectF(left, r.top(), width, r.height())
        painter.drawText(title_rect, Qt.AlignVCenter | Qt.AlignLeft,
                         QFontMetrics(title_font).elidedText(title, Qt.ElideRight, int(width)))
        if username:
            user_font = theme.ui_font(13)
            painter.setFont(user_font)
            painter.setPen(p.muted)
            painter.drawText(QRectF(left, r.top() + 27, width, 18), Qt.AlignVCenter | Qt.AlignLeft,
                             QFontMetrics(user_font).elidedText(username, Qt.ElideRight, int(width)))
        painter.restore()


class FieldRow(theme.WellFrame):
    """One field of the entry card: name, value and small tool buttons"""

    def __init__(self, key, mono=False, top_aligned=False, parent=None):
        super().__init__(parent, radius=8, alpha=0.32)
        self.layout_ = QHBoxLayout(self)
        self.layout_.setContentsMargins(14, 8, 8, 8)
        self.layout_.setSpacing(12)
        align = Qt.AlignTop if top_aligned else Qt.AlignVCenter
        key_label = theme.label(key, role="muted", size=13)
        key_label.setFixedWidth(84)
        if top_aligned:
            key_label.setContentsMargins(0, 4, 0, 0)
        self.layout_.addWidget(key_label, 0, align)
        self.value = theme.label("", size=14, mono=mono)
        self.value.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.value.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.value.setMinimumHeight(28)
        self.layout_.addWidget(self.value, 1, align)
        self.tools = QHBoxLayout()
        self.tools.setSpacing(2)
        self.layout_.addLayout(self.tools)

    def add_tool(self, icon, tooltip, slot):
        button = TransparentToolButton(icon)
        button.setToolTip(tooltip)
        button.setFixedSize(32, 32)
        button.clicked.connect(slot)
        self.tools.addWidget(button)
        return button


class DetailPanel(theme.GlassCard):
    """Details of the selected entry, with copy / show buttons per field"""

    MASK = "•" * 14

    def __init__(self, window, parent=None):
        super().__init__(parent)
        self.window_ = window
        self.password_id = None
        self.password_visible = False

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self.stack = QStackedWidget()
        outer.addWidget(self.stack)

        # empty state
        empty = QWidget()
        empty_layout = QVBoxLayout(empty)
        empty_layout.addStretch(1)
        self.empty_title = theme.label("No entry selected", size=18, weight=QFont.DemiBold, display=True)
        self.empty_title.setAlignment(Qt.AlignCenter)
        empty_layout.addWidget(self.empty_title)
        self.empty_text = theme.label("Pick an entry on the left to see its details.", role="muted", size=13)
        self.empty_text.setAlignment(Qt.AlignCenter)
        empty_layout.addWidget(self.empty_text)
        empty_layout.addStretch(1)
        self.stack.addWidget(empty)

        # details
        details = QWidget()
        layout = QVBoxLayout(details)
        layout.setContentsMargins(24, 22, 24, 18)
        layout.setSpacing(10)

        head = QHBoxLayout()
        head.setSpacing(14)
        self.avatar = theme.Avatar("", size=48, radius=11)
        head.addWidget(self.avatar)
        names = QVBoxLayout()
        names.setSpacing(0)
        self.title_label = theme.label("", size=22, weight=QFont.DemiBold, display=True)
        self.title_label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        names.addWidget(self.title_label)
        self.subtitle_label = theme.label("", role="muted", size=13)
        names.addWidget(self.subtitle_label)
        head.addLayout(names, 1)

        self.fav_button = TransparentToolButton(AppIcon.STAR)
        self.fav_button.setToolTip("Add to favorites")
        self.fav_button.clicked.connect(lambda: self.window_.toggle_favorite(self.password_id))
        head.addWidget(self.fav_button)
        self.edit_button = PushButton(FluentIcon.EDIT, "Edit")
        self.edit_button.clicked.connect(lambda: self.window_.edit_password(self.password_id))
        head.addWidget(self.edit_button)
        self.delete_button = ToolButton(FluentIcon.DELETE)
        self.delete_button.setToolTip("Delete")
        self.delete_button.clicked.connect(lambda: self.window_.delete_password(self.password_id))
        head.addWidget(self.delete_button)
        layout.addLayout(head)
        layout.addSpacing(6)

        self.username_row = FieldRow("Username")
        self.username_row.add_tool(FluentIcon.COPY, "Copy username",
                                   lambda: self.window_.copy_username(self.password_id))
        layout.addWidget(self.username_row)

        self.password_row = FieldRow("Password", mono=True)
        self.password_row.value.setTextInteractionFlags(Qt.NoTextInteraction)
        self.reveal_button = self.password_row.add_tool(FluentIcon.VIEW, "Show password", self.toggle_password)
        self.password_row.add_tool(FluentIcon.COPY, "Copy password",
                                   lambda: self.window_.copy_password(self.password_id))
        layout.addWidget(self.password_row)

        self.url_row = FieldRow("Website")
        self.open_button = self.url_row.add_tool(FluentIcon.LINK, "Open in browser", self.open_url)
        self.url_row.add_tool(FluentIcon.COPY, "Copy address",
                              lambda: self.window_.copy_text(self.url_row.value.text(), "Address"))
        layout.addWidget(self.url_row)

        self.strength_row = FieldRow("Strength", top_aligned=True)
        self.strength_meter = theme.StrengthMeter()
        strength_box = QVBoxLayout()
        strength_box.setContentsMargins(0, 4, 8, 6)
        strength_box.setSpacing(6)
        self.strength_row.layout_.removeWidget(self.strength_row.value)
        strength_box.addWidget(self.strength_row.value)
        strength_box.addWidget(self.strength_meter)
        self.strength_row.layout_.insertLayout(1, strength_box, 1)
        layout.addWidget(self.strength_row)

        self.notes_row = FieldRow("Notes", top_aligned=True)
        self.notes_row.value.setWordWrap(True)
        self.notes_row.value.setProperty("role", "muted")
        self.notes_row.value.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self.notes_row.value.setContentsMargins(0, 4, 0, 4)
        layout.addWidget(self.notes_row, 1)

        meta = QHBoxLayout()
        meta.setSpacing(22)
        self.created_label = theme.label("", role="faint", size=12)
        self.modified_label = theme.label("", role="faint", size=12)
        self.used_label = theme.label("", role="faint", size=12)
        for widget in (self.created_label, self.modified_label, self.used_label):
            meta.addWidget(widget)
        meta.addStretch(1)
        layout.addLayout(meta)
        self.stack.addWidget(details)

    def show_empty(self, count):
        self.password_id = None
        self.password_visible = False
        self.empty_title.setText("No entry selected" if count else "No passwords here")
        self.empty_text.setText("Pick an entry on the left to see its details." if count else
                                "Add one with “New password” or change the search.")
        self.stack.setCurrentIndex(0)

    def show_entry(self, pwd, category_name=None):
        """Fill the card from a Password object (the password itself is masked)"""
        same_entry = self.password_id == pwd.password_id
        self.password_id = pwd.password_id
        if not same_entry:
            self.password_visible = False

        self.avatar.set_title(pwd.title)
        self.title_label.setText(pwd.title)
        parts = [category_name or "No category"]
        if pwd.is_favorite:
            parts.append("in favorites")
        self.subtitle_label.setText(" · ".join(parts))
        self.fav_button.setIcon(AppIcon.STAR_FILLED if pwd.is_favorite else AppIcon.STAR)
        self.fav_button.setToolTip("Remove from favorites" if pwd.is_favorite else "Add to favorites")

        self.username_row.value.setText(pwd.username or "—")
        self.username_row.setVisible(True)
        self.set_password_text(pwd.password if self.password_visible else None)

        self.url_row.value.setText(pwd.url or "—")
        self.open_button.setEnabled(self._safe_url(pwd.url) is not None)

        kinds = sum([any(c.isupper() for c in pwd.password), any(c.islower() for c in pwd.password),
                     any(c.isdigit() for c in pwd.password), any(not c.isalnum() for c in pwd.password)])
        self.strength_row.value.setText(
            f"{theme.strength_text(pwd.strength_score)} · {len(pwd.password)} characters, "
            f"{kinds} character type{'s' if kinds != 1 else ''}"
        )
        self.strength_meter.set_score(pwd.strength_score)

        self.notes_row.value.setText(pwd.notes or "No notes")

        self.created_label.setText(f"Created {format_date(pwd.created_date, 'unknown')}")
        self.modified_label.setText(f"Modified {format_date(pwd.modified_date, 'unknown')}")
        self.used_label.setText(f"Last used {format_date(pwd.last_used_date, 'never')}")
        self.stack.setCurrentIndex(1)

    def set_password_text(self, password):
        if password is None:
            self.password_row.value.setText(self.MASK)
            self.reveal_button.setIcon(FluentIcon.VIEW)
            self.reveal_button.setToolTip("Show password")
        else:
            self.password_row.value.setText(password)
            self.reveal_button.setIcon(FluentIcon.HIDE)
            self.reveal_button.setToolTip("Hide password")

    def toggle_password(self):
        if self.password_id is None:
            return
        self.password_visible = not self.password_visible
        self.set_password_text(self.window_.reveal_password(self.password_id) if self.password_visible else None)

    @staticmethod
    def _safe_url(url):
        """Only web addresses are opened (never file: or other schemes)"""
        url = (url or "").strip()
        if not url:
            return None
        if "://" not in url:
            url = "https://" + url
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return None
        return url

    def open_url(self):
        url = self._safe_url(self.url_row.value.text())
        if url:
            QDesktopServices.openUrl(QUrl(url))


class VaultPage(QWidget):
    """Widgets of the vault page (MainWindow fills them)"""

    def __init__(self, window, parent=None):
        super().__init__(parent)
        self.setObjectName("vaultPage")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 18, 12)
        layout.setSpacing(14)

        # Title, search, new password
        top = QHBoxLayout()
        top.setSpacing(10)
        self.view_title = theme.title_label("All passwords")
        self.view_title.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        top.addWidget(self.view_title, 1)
        self.search_input = SearchLineEdit()
        self.search_input.setPlaceholderText(f"Search passwords   ({shortcut_label('Ctrl+F')})")
        self.search_input.setFixedWidth(300)
        top.addWidget(self.search_input)
        self.add_button = theme.primary_button("New password", FluentIcon.ADD)
        top.addWidget(self.add_button)
        layout.addLayout(top)

        # Count chips, which also filter by strength
        chips = QHBoxLayout()
        chips.setSpacing(8)
        self.chip_group = QButtonGroup(self)
        self.chip_group.setExclusive(True)
        self.strength_chips = {}
        for key, text, role in (("All", "total", None), ("Strong", "strong", "ok"),
                                ("Medium", "medium", "warn"), ("Weak", "weak", "bad")):
            chip = theme.Chip(text, role)
            chip.setToolTip("Show all passwords" if key == "All" else f"Show only {text} passwords")
            self.chip_group.addButton(chip)
            self.strength_chips[key] = chip
            chips.addWidget(chip)
        self.strength_chips["All"].setChecked(True)
        chips.addStretch(1)
        self.refresh_button = TransparentToolButton(FluentIcon.SYNC)
        self.refresh_button.setToolTip("Refresh")
        chips.addWidget(self.refresh_button)
        layout.addLayout(chips)

        # Entry list and details
        split = QHBoxLayout()
        split.setSpacing(14)
        list_card = theme.GlassCard()
        list_card.setMinimumWidth(320)
        list_card.setMaximumWidth(440)
        list_layout = QVBoxLayout(list_card)
        list_layout.setContentsMargins(6, 6, 6, 6)
        self.entry_list = ListWidget()
        self.entry_list.setObjectName("entryList")
        self.entry_list.setItemDelegate(EntryDelegate(self.entry_list))
        self.entry_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.entry_list.setMouseTracking(True)
        self.entry_list.setUniformItemSizes(True)
        self.entry_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.entry_list.setContextMenuPolicy(Qt.CustomContextMenu)
        transparent = "ListWidget, QListWidget { background: transparent; border: none; outline: none; }"
        setCustomStyleSheet(self.entry_list, transparent, transparent)
        list_layout.addWidget(self.entry_list)
        split.addWidget(list_card, 4)

        self.detail = DetailPanel(window)
        split.addWidget(self.detail, 6)
        layout.addLayout(split, 1)

        # Status line
        status = QHBoxLayout()
        self.status_label = theme.label("Ready", role="faint", size=12)
        self.status_label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        status.addWidget(self.status_label, 1)
        self.encryption_status = theme.label("Encrypted · AES-256-GCM", role="faint", size=12)
        status.addWidget(self.encryption_status)
        layout.addLayout(status)

    def add_entry_item(self, pwd):
        item = QListWidgetItem()
        item.setData(Qt.UserRole, pwd.password_id)
        item.setData(Qt.DisplayRole, pwd.title)
        item.setData(ENTRY_ROLE, {
            "title": pwd.title,
            "username": pwd.username,
            "score": pwd.strength_score,
            "favorite": pwd.is_favorite,
        })
        item.setSizeHint(QSize(0, EntryDelegate.ROW_HEIGHT))
        self.entry_list.addItem(item)
        return item
