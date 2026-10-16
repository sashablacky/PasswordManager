from PyQt5.QtWidgets import (QApplication, QLineEdit, QMessageBox, QShortcut)
from PyQt5.QtCore import Qt, QTimer, QRectF, QPointF
from PyQt5.QtGui import QColor, QFont, QKeySequence, QPainter

from qfluentwidgets import (FluentWindow, NavigationItemPosition, NavigationPushButton, NavigationWidget,
                            InfoBar, InfoBarPosition, RoundMenu, Action, FluentIcon, setCustomStyleSheet)
from qfluentwidgets.common.icon import drawIcon

from ui import theme
from ui.add_password_dialog import AddPasswordDialog
from ui.breach_dialog import BreachCheckPage
from ui.clipboard import copy_secret, CLIPBOARD_CLEAR_SECONDS
from ui.icons import AppIcon
from ui.layout_utils import resize_to_fit_screen
from ui.password_generator_dialog import GeneratorPage
from ui.settings_page import SettingsPage
from ui.vault_page import VaultPage
from platform_utils import default_save_path, restrict_file, shortcut_keys
from version import __version__

VIEW_TITLES = {
    "all": "All passwords",
    "favorites": "Favorites",
    "weak": "Weak passwords",
    "recent": "Recently used",
}


class NavItem(NavigationPushButton):
    """Navigation entry in the theme colours, with an optional count and colour dot"""

    def __init__(self, icon, text, selectable=True, dot=None, parent=None):
        super().__init__(icon, text, selectable, parent)
        self.dot = dot
        self.count = None
        self.count_role = None
        self.setFont(theme.ui_font(14))

    def set_count(self, count, role=None):
        self.count = count
        self.count_role = role
        self.update()

    def paintEvent(self, e):
        p = theme.current()
        painter = QPainter(self)
        painter.setRenderHints(QPainter.Antialiasing | QPainter.TextAntialiasing | QPainter.SmoothPixmapTransform)
        painter.setPen(Qt.NoPen)
        if self.isPressed:
            painter.setOpacity(0.75)

        rect = QRectF(self.rect())
        if self.isSelected:
            painter.setBrush(p.color("text", 0.08))
            painter.drawRoundedRect(rect, 6, 6)
            painter.setBrush(QColor(p.accent2))
            painter.drawRoundedRect(QRectF(0, 10, 3, self.height() - 20), 1.5, 1.5)
        elif self.isEnter:
            painter.setBrush(p.color("text", 0.05))
            painter.drawRoundedRect(rect, 6, 6)

        if self.dot:
            painter.setBrush(QColor(self.dot))
            painter.drawEllipse(QPointF(19.5, self.height() / 2), 4, 4)
        else:
            drawIcon(self._icon, painter, QRectF(11.5, (self.height() - 16) / 2, 16, 16), fill=p.text)

        if self.isCompacted:
            return

        painter.setFont(self.font())
        painter.setPen(QColor(p.text))
        right = self.width() - 12
        if self.count is not None:
            painter.setPen(p.color(self.count_role) if self.count_role else p.faint)
            painter.setFont(theme.ui_font(12))
            painter.drawText(QRectF(right - 40, 0, 40, self.height()), Qt.AlignVCenter | Qt.AlignRight,
                             str(self.count))
            right -= 44
            painter.setFont(self.font())
            painter.setPen(QColor(p.text))
        painter.drawText(QRectF(44, 0, right - 44, self.height()), Qt.AlignVCenter | Qt.AlignLeft, self.text())


class NavHeader(NavigationWidget):
    """Small upper-case caption in the navigation ("CATEGORIES")"""

    def __init__(self, text, parent=None):
        super().__init__(False, parent)
        self.text = text
        self.setFixedHeight(34)

    def setCompacted(self, isCompacted):
        self.isCompacted = isCompacted
        self.setFixedSize(40 if isCompacted else self.EXPAND_WIDTH, 34)

    def mouseReleaseEvent(self, e):
        e.ignore()

    def paintEvent(self, e):
        if self.isCompacted:
            return
        painter = QPainter(self)
        font = theme.ui_font(11)
        font.setLetterSpacing(QFont.PercentageSpacing, 108)
        painter.setFont(font)
        painter.setPen(theme.current().faint)
        painter.drawText(QRectF(12, 12, self.width() - 12, 22), Qt.AlignLeft | Qt.AlignVCenter, self.text.upper())


class MainWindow(FluentWindow):
    """Main application window"""

    def __init__(self, app_instance):
        """
        Initialize main window

        Args:
            app_instance: PasswordManagerApp instance
        """
        super().__init__()
        self.app = app_instance
        self.user_id = app_instance.auth_manager.get_current_user_id()
        self.current_category = None
        self.current_view = "all"  # all, favorites, weak, recent
        self.strength_filter = "All"  # All, Strong, Medium, Weak
        self.categories = []
        self.category_names = {}
        self.category_items = {}
        self.selected_password_id = None
        self._skip_close_prompt = False

        # The list is refreshed after every change made in the app, so no periodic
        # auto-refresh is needed (it used to reset the search results every 30 s).
        # User activity for auto-lock is tracked by the app-wide ActivityMonitor in main.py.

        self.setup_ui()
        self.load_categories()
        self.load_passwords()

        if self.app.auth_manager.upgrade_error:
            self.status_label.setText(
                "The vault could not be converted to the new storage format "
                "(an entry could not be decrypted). It keeps working in the old format."
            )

    # ---------------------------------------------------------------- layout

    def setup_ui(self):
        """Set up the user interface"""
        self.setWindowTitle("Password Manager")
        self.setWindowIcon(theme.app_icon())
        self.setMinimumSize(1000, 600)
        resize_to_fit_screen(self, 1280, 800)

        # Pages sit directly on the window backdrop
        transparent = "StackedWidget { background: transparent; border: none; }"
        setCustomStyleSheet(self.stackedWidget, transparent, transparent)

        self.vault_page = VaultPage(self)
        self.generator_page = GeneratorPage(self.app.generator, can_save=True)
        self.security_page = BreachCheckPage(self.app.password_manager, self.user_id)
        self.settings_page = SettingsPage(self)
        self.pages = {
            "vault": self.vault_page,
            "generator": self.generator_page,
            "security": self.security_page,
            "settings": self.settings_page,
        }
        for page in self.pages.values():
            self.stackedWidget.addWidget(page)

        # Shortcuts to the vault page widgets (used by the methods below and the tests)
        self.view_title = self.vault_page.view_title
        self.search_input = self.vault_page.search_input
        self.entry_list = self.vault_page.entry_list
        self.strength_chips = self.vault_page.strength_chips
        self.status_label = self.vault_page.status_label
        self.detail = self.vault_page.detail

        self.vault_page.add_button.clicked.connect(self.show_add_password_dialog)
        self.vault_page.refresh_button.clicked.connect(self.refresh_data)
        self.search_input.textChanged.connect(self.on_search)
        for key, chip in self.strength_chips.items():
            chip.clicked.connect(lambda checked=False, k=key: self.apply_filter(k))
        self.entry_list.currentItemChanged.connect(self.on_entry_selected)
        self.entry_list.itemDoubleClicked.connect(
            lambda item: self.edit_password(item.data(Qt.UserRole)))
        self.entry_list.customContextMenuRequested.connect(self.show_entry_menu)

        self.generator_page.save_requested.connect(self.save_generated_password)
        self.security_page.entries_changed.connect(self.refresh_data)
        self.security_page.statistics_changed.connect(self.on_breach_statistics)

        self.create_navigation()
        self.create_shortcuts()
        self.security_page.load_statistics()

        theme.signals.changed.connect(self.on_theme_changed)
        self.show_page("vault", "all")

    def create_navigation(self):
        nav = self.navigationInterface
        nav.setExpandWidth(250)
        nav.setCollapsible(False)
        nav.setMenuButtonVisible(False)
        nav.setReturnButtonVisible(False)
        nav.setIndicatorAnimationEnabled(False)
        # Leave room for the title bar above the first item
        nav.panel.vBoxLayout.setContentsMargins(0, self.titleBar.height(), 0, 8)

        self.nav_items = {}
        views = [
            ("all", FluentIcon.TILES, "All passwords"),
            ("favorites", AppIcon.STAR, "Favorites"),
            ("weak", AppIcon.WARNING, "Weak passwords"),
            ("recent", FluentIcon.HISTORY, "Recently used"),
        ]
        for view_id, icon, text in views:
            item = NavItem(icon, text)
            # Navigation items emit clicked(bool): without the first parameter the bool
            # would replace view_id and every entry showed all passwords
            nav.addWidget(f"view-{view_id}", item, lambda checked=False, v=view_id: self.change_view(v))
            self.nav_items[f"view-{view_id}"] = item

        nav.addWidget("header-categories", NavHeader("Categories"), position=NavigationItemPosition.SCROLL)

        nav.addSeparator(NavigationItemPosition.BOTTOM)
        bottom = [
            ("generator", AppIcon.DICE, "Generator", lambda: self.show_page("generator")),
            ("security", AppIcon.SHIELD, "Security check", lambda: self.show_page("security")),
            ("settings", FluentIcon.SETTING, "Settings", lambda: self.show_page("settings")),
        ]
        for key, icon, text, slot in bottom:
            item = NavItem(icon, text)
            nav.addWidget(key, item, slot, NavigationItemPosition.BOTTOM)
            self.nav_items[key] = item

        lock_item = NavItem(AppIcon.LOCK, "Lock vault", selectable=False)
        nav.addWidget("lock", lock_item, self.lock_vault, NavigationItemPosition.BOTTOM)
        self.nav_items["lock"] = lock_item

    def create_shortcuts(self):
        """Keyboard shortcuts of the former menu bar ("Ctrl" is the Command key on macOS)"""
        slots = {
            "add": self.show_add_password_dialog,
            "search": self.focus_search,
            "generator": self.show_generator_dialog,
            "lock": self.lock_vault,
            "quit": self.close,
            "refresh": self.refresh_data,
        }
        keys = shortcut_keys()
        self.shortcuts = []
        for action, slot in slots.items():
            for sequence in keys[action]:
                shortcut = QShortcut(QKeySequence(sequence), self)
                shortcut.activated.connect(slot)
                self.shortcuts.append(shortcut)
        for sequence in keys["delete"]:
            delete = QShortcut(QKeySequence(sequence), self.entry_list)
            delete.setContext(Qt.WidgetShortcut)
            delete.activated.connect(
                lambda: self.selected_password_id and self.delete_password(self.selected_password_id))
            self.shortcuts.append(delete)

    def paintEvent(self, e):
        painter = QPainter(self)
        theme.paint_backdrop(painter, self.rect(), opacity=0.6 if self.isMicaEffectEnabled() else 1.0)

    def show_page(self, name, nav_key=None):
        """Switch the stacked page and highlight its navigation entry"""
        self.switchTo(self.pages[name])
        nav_key = nav_key or name
        if nav_key in ("all", "favorites", "weak", "recent"):
            nav_key = f"view-{nav_key}"
        self.navigationInterface.setCurrentItem(nav_key)

    def focus_search(self):
        self.show_page("vault", self.current_nav_key())
        self.search_input.setFocus()
        self.search_input.selectAll()

    def current_nav_key(self):
        if self.current_category:
            return f"category-{self.current_category}"
        return f"view-{self.current_view}"

    def set_theme(self, key):
        """Settings page: switch the theme live and remember it"""
        theme.apply_theme(key, save=True)

    def on_theme_changed(self, key):
        try:
            self.settings_page.theme_card.set_current(key)
            self.update()
        except RuntimeError:
            pass

    # ---------------------------------------------------------------- data

    def update_statistics(self):
        """Update the count chips and the counts in the navigation"""
        try:
            stats = self.app.password_manager.get_statistics(self.user_id)
            self.strength_chips["All"].set_value(stats['total'])
            self.strength_chips["Strong"].set_value(stats['strong'])
            self.strength_chips["Medium"].set_value(stats['medium'])
            self.strength_chips["Weak"].set_value(stats['weak'])

            self.nav_items["view-all"].set_count(stats['total'])
            self.nav_items["view-favorites"].set_count(stats['favorites'] or None)
            self.nav_items["view-weak"].set_count(stats['weak'] or None, "bad" if stats['weak'] else None)

            per_category = {}
            for pwd in self.app.password_manager.get_all_passwords(self.user_id):
                per_category[pwd.category_id] = per_category.get(pwd.category_id, 0) + 1
            for category_id, item in self.category_items.items():
                item.set_count(per_category.get(category_id) or None)
        except Exception:
            for chip in self.strength_chips.values():
                chip.set_value("?")

    def on_breach_statistics(self, compromised):
        self.nav_items["security"].set_count(compromised or None, "bad")

    def load_categories(self):
        """Load categories from database into the navigation"""
        try:
            categories = self.app.db.fetch_all(
                "SELECT * FROM categories WHERE user_id = ? ORDER BY sort_order",
                (self.user_id,)
            )
        except Exception as e:
            print(f"Error loading categories: {e}")
            return

        self.categories = categories
        self.category_names = {cat['category_id']: cat['name'] for cat in categories}
        known = set()
        for cat in categories:
            key = f"category-{cat['category_id']}"
            known.add(cat['category_id'])
            item = self.category_items.get(cat['category_id'])
            if item is None:
                item = NavItem(None, cat['name'], dot=theme.category_color(cat.get('color')))
                self.navigationInterface.addWidget(
                    key, item, lambda checked=False, cid=cat['category_id']: self.on_category_selected(cid),
                    NavigationItemPosition.SCROLL)
                self.category_items[cat['category_id']] = item
            else:
                item.setText(cat['name'])
        for category_id in list(self.category_items):
            if category_id not in known:
                self.navigationInterface.removeWidget(f"category-{category_id}")
                del self.category_items[category_id]

        # Keep the selected category highlighted after a refresh
        if self.current_category not in self.category_items:
            self.current_category = None
        if self.stackedWidget.currentWidget() is self.vault_page:
            self.navigationInterface.setCurrentItem(self.current_nav_key())

    def load_passwords(self):
        """Load passwords based on current view and category"""
        try:
            # Get passwords based on view
            if self.current_view == "all":
                passwords = self.app.password_manager.get_all_passwords(self.user_id)
            elif self.current_view == "favorites":
                passwords = self.app.password_manager.get_favorites(self.user_id)
            elif self.current_view == "weak":
                passwords = self.app.password_manager.get_weak_passwords(self.user_id)
            elif self.current_view == "recent":
                all_passwords = self.app.password_manager.get_all_passwords(self.user_id)
                # Sort by last used date
                passwords = sorted(
                    [p for p in all_passwords if p.last_used_date],
                    key=lambda x: x.last_used_date,
                    reverse=True
                )[:20]  # Top 20 recent
            else:
                passwords = self.app.password_manager.get_all_passwords(self.user_id)

            # Filter by category if selected
            if self.current_category:
                passwords = [p for p in passwords if p.category_id == self.current_category]

            # Filter by search text
            query = self.search_input.text().strip().lower()
            if query:
                passwords = [
                    p for p in passwords
                    if query in p.title.lower() or query in p.username.lower()
                    or query in p.url.lower() or query in p.notes.lower()
                ]

            # Filter by strength
            if self.strength_filter == "Strong":
                passwords = [p for p in passwords if p.strength_score >= 75]
            elif self.strength_filter == "Medium":
                passwords = [p for p in passwords if 50 <= p.strength_score < 75]
            elif self.strength_filter == "Weak":
                passwords = [p for p in passwords if p.strength_score < 50]

            self.display_passwords(passwords)
            if query:
                self.status_label.setText(f"{len(passwords)} results for “{self.search_input.text().strip()}”")
            self.update_statistics()

            failures = self.app.password_manager.last_decrypt_failures
            if failures:
                self.status_label.setText(
                    f"{failures} entries could not be decrypted (wrong key or damaged data)"
                )

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load passwords:\n{str(e)}")

    def display_passwords(self, passwords):
        """Show passwords in the entry list, keeping the selected entry if it is still there"""
        keep = self.selected_password_id
        self.entry_list.blockSignals(True)
        self.entry_list.clear()
        selected_row = -1
        for row, pwd in enumerate(passwords):
            self.vault_page.add_entry_item(pwd)
            if pwd.password_id == keep:
                selected_row = row
        if selected_row < 0 and passwords:
            selected_row = 0
        self.entry_list.setCurrentRow(selected_row)
        self.entry_list.blockSignals(False)
        self.on_entry_selected(self.entry_list.currentItem())

        if not self.search_input.text().strip():
            self.status_label.setText(f"{len(passwords)} passwords")

    def entry_title(self, row):
        """Title shown in row `row` of the entry list"""
        return self.entry_list.item(row).data(Qt.DisplayRole)

    def on_entry_selected(self, item, previous=None):
        if item is None:
            self.selected_password_id = None
            self.detail.show_empty(self.entry_list.count())
            return
        self.selected_password_id = item.data(Qt.UserRole)
        try:
            pwd = self.app.password_manager.get_password(self.selected_password_id, self.user_id)
        except Exception as e:
            self.detail.show_empty(self.entry_list.count())
            self.status_label.setText(f"Could not open the entry: {e}")
            return
        self.detail.show_entry(pwd, self.category_names.get(pwd.category_id))

    def get_strength_text(self, score):
        """Get strength text from score"""
        return theme.strength_text(score)

    def get_strength_color(self, score):
        """Get color for strength score"""
        return theme.strength_color(score)

    def change_view(self, view_id):
        """Change current view (all, favorites, weak, recent)"""
        self.current_view = view_id
        self.current_category = None
        self.view_title.setText(VIEW_TITLES.get(view_id, "Passwords"))
        self.show_page("vault", view_id)
        self.load_passwords()

    def on_category_selected(self, category_id):
        """Show the entries of one category"""
        self.current_view = "all"
        self.current_category = category_id
        self.view_title.setText(self.category_names.get(category_id, "Category"))
        self.show_page("vault", f"category-{category_id}")
        self.load_passwords()

    def on_search(self, text):
        """Handle search (respects the current view, category and strength filter)"""
        self.load_passwords()

    def apply_filter(self, filter_text):
        """Apply strength filter (All, Strong, Medium, Weak)"""
        self.strength_filter = filter_text
        chip = self.strength_chips.get(filter_text)
        if chip is not None and not chip.isChecked():
            chip.setChecked(True)
        self.load_passwords()

    def refresh_data(self):
        """Refresh all data"""
        self.load_categories()
        self.load_passwords()
        if not self.app.password_manager.last_decrypt_failures:
            self.notify("Refreshed")

    def notify(self, text, msec=2500):
        """Show a short message in the status line, then the entry count again"""
        self.status_label.setText(text)
        self.run_later(msec, self._reset_status)

    def _reset_status(self):
        if not self.app.password_manager.last_decrypt_failures:
            self.status_label.setText(f"{self.entry_list.count()} passwords")

    def run_later(self, msec, callback):
        """Like QTimer.singleShot, but cancelled if this window is closed (e.g. vault locked)"""
        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(callback)
        timer.timeout.connect(timer.deleteLater)
        timer.start(msec)

    def toast(self, title, text=""):
        InfoBar.success(title, text, duration=2500, position=InfoBarPosition.TOP_RIGHT, parent=self)

    # ---------------------------------------------------------------- entry actions

    def copy_password(self, password_id):
        """Copy password to clipboard"""
        try:
            pwd = self.app.password_manager.get_password(password_id, self.user_id)

            # Copy to clipboard (cleared after 30 seconds or on exit)
            copy_secret(pwd.password)

            # Update last used
            self.app.password_manager.update_last_used(password_id, self.user_id)

            self.toast("Password copied", f"“{pwd.title}” · cleared from the clipboard in "
                                          f"{CLIPBOARD_CLEAR_SECONDS} s")
            self.status_label.setText(
                f"Password for '{pwd.title}' copied to clipboard (cleared in {CLIPBOARD_CLEAR_SECONDS} s)"
            )

            # Refresh to show updated last used
            self.run_later(500, self.load_passwords)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to copy password:\n{str(e)}")

    def copy_username(self, password_id):
        try:
            pwd = self.app.password_manager.get_password(password_id, self.user_id)
            self.copy_text(pwd.username, "Username")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to copy username:\n{str(e)}")

    def copy_text(self, text, what):
        """Copy something that is not secret (username, address)"""
        if not text or text == "—":
            return
        QApplication.clipboard().setText(text)
        self.toast(f"{what} copied")

    def reveal_password(self, password_id):
        """The password of an entry, for the "show" button of the detail card"""
        try:
            return self.app.password_manager.get_password(password_id, self.user_id).password
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read password:\n{str(e)}")
            return None

    def view_password(self, password_id):
        """Select the entry and show its details"""
        for row in range(self.entry_list.count()):
            if self.entry_list.item(row).data(Qt.UserRole) == password_id:
                self.show_page("vault", self.current_nav_key())
                self.entry_list.setCurrentRow(row)
                return

    def toggle_favorite(self, password_id):
        if password_id is None:
            return
        try:
            self.app.password_manager.toggle_favorite(password_id, self.user_id)
            self.load_passwords()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update favorite:\n{str(e)}")

    def show_entry_menu(self, pos):
        item = self.entry_list.itemAt(pos)
        if item is None:
            return
        pid = item.data(Qt.UserRole)
        menu = RoundMenu(parent=self)
        menu.addAction(Action(FluentIcon.COPY, "Copy password", triggered=lambda: self.copy_password(pid)))
        menu.addAction(Action(FluentIcon.PEOPLE, "Copy username", triggered=lambda: self.copy_username(pid)))
        menu.addSeparator()
        menu.addAction(Action(FluentIcon.EDIT, "Edit", triggered=lambda: self.edit_password(pid)))
        menu.addAction(Action(AppIcon.STAR, "Favorite on / off", triggered=lambda: self.toggle_favorite(pid)))
        menu.addAction(Action(FluentIcon.DELETE, "Delete", triggered=lambda: self.delete_password(pid)))
        menu.exec(self.entry_list.viewport().mapToGlobal(pos))

    def edit_password(self, password_id):
        """Edit password"""
        if password_id is None:
            return
        try:
            # Get password data
            pwd = self.app.password_manager.get_password(password_id, self.user_id)

            # Get categories
            categories = self.app.db.fetch_all(
                "SELECT * FROM categories WHERE user_id = ?",
                (self.user_id,)
            )

            # Show edit dialog
            dialog = AddPasswordDialog(
                self.app.password_manager,
                self.user_id,
                categories,
                pwd,
                parent=self
            )
            dialog.password_updated.connect(self.on_password_updated)
            dialog.exec_()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to edit password:\n{str(e)}")

    def delete_password(self, password_id):
        """Delete password"""
        if password_id is None:
            return
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            "Are you sure you want to delete this password?\nThis action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            try:
                self.app.password_manager.delete_password(password_id, self.user_id)
                self.refresh_data()
                self.notify("Password deleted")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete password:\n{str(e)}")

    def show_add_password_dialog(self, password=None):
        """Show add password dialog (optionally with a generated password filled in)"""
        try:
            # Get categories
            categories = self.app.db.fetch_all(
                "SELECT * FROM categories WHERE user_id = ?",
                (self.user_id,)
            )

            dialog = AddPasswordDialog(
                self.app.password_manager,
                self.user_id,
                categories,
                parent=self
            )
            if isinstance(password, str) and password:
                dialog.password_input.setText(password)
            if self.current_category:
                index = dialog.category_combo.findData(self.current_category)
                if index >= 0:
                    dialog.category_combo.setCurrentIndex(index)
            dialog.password_added.connect(self.on_password_added)
            dialog.exec_()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open dialog:\n{str(e)}")

    def save_generated_password(self, password):
        """Generator page: "Save as new entry" """
        self.show_add_password_dialog(password)

    def on_password_added(self, password_id):
        """Handle password added"""
        self.selected_password_id = password_id
        self.show_page("vault", self.current_nav_key())
        self.refresh_data()
        self.notify("Password added successfully")

    def on_password_updated(self, password_id):
        """Handle password updated"""
        self.refresh_data()
        self.notify("Password updated successfully")

    # ---------------------------------------------------------------- tools

    def show_generator_dialog(self):
        """Open the generator (now a page of this window)"""
        self.show_page("generator")

    def check_breaches(self):
        """Open the security check (now a page of this window)"""
        self.show_page("security")

    def change_master_password(self):
        """Change master password"""
        from PyQt5.QtWidgets import QInputDialog

        # Get current password
        current, ok = QInputDialog.getText(
            self,
            "Change Master Password",
            "Enter current master password:",
            QLineEdit.Password
        )
        if not ok or not current:
            return

        # Get new password
        new_password, ok = QInputDialog.getText(
            self,
            "Change Master Password",
            "Enter new master password:",
            QLineEdit.Password
        )
        if not ok or not new_password:
            return

        # Confirm new password
        confirm, ok = QInputDialog.getText(
            self,
            "Change Master Password",
            "Confirm new master password:",
            QLineEdit.Password
        )
        if not ok or new_password != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match")
            return

        # Attempt to change password
        success, message = self.app.auth_manager.change_master_password(current, new_password)

        if success:
            QMessageBox.information(self, "Success", "Master password changed successfully!")
        else:
            QMessageBox.critical(self, "Error", message)

    def set_browser_integration(self, enabled):
        self.app.set_browser_integration(enabled)
        if enabled and self.app.bridge is None:
            self.settings_page.browser_switch.setChecked(False)
            QMessageBox.warning(self, "Browser extension",
                                "The connection for the browser extension could not be started.\n"
                                "Details were written to the log file.")

    def paired_browsers(self):
        from integration.store import BrowserClientStore
        try:
            return BrowserClientStore(self.app.db, self.app.encryption).list(self.user_id)
        except Exception:
            return []

    def forget_browsers(self):
        reply = QMessageBox.question(
            self, "Disconnect browsers",
            "Disconnect all browsers from this vault?\nThey will need your approval to connect again.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return
        from integration.store import BrowserClientStore
        BrowserClientStore(self.app.db, self.app.encryption).remove_all(self.user_id)
        if self.app.bridge:
            self.app.bridge.service.clear_sessions()
        self.settings_page.update_browser_status()
        self.toast("Browsers disconnected")

    def show_health_check(self):
        """Show password health check"""
        stats = self.app.password_manager.get_statistics(self.user_id)
        weak = self.app.password_manager.get_weak_passwords(self.user_id)

        message = f"Password Health Report\n"
        message += "=" * 40 + "\n\n"
        message += f"Total Passwords: {stats['total']}\n"
        message += f"Strong: {stats['strong']}\n"
        message += f"Medium: {stats['medium']}\n"
        message += f"Weak: {stats['weak']}\n"
        message += f"Favorites: {stats['favorites']}\n"
        message += f"Average Strength: {stats['average_strength']}/100\n\n"

        if weak:
            message += "Weak Passwords:\n"
            for pwd in weak[:5]:  # Show first 5
                message += f"  • {pwd.title} ({pwd.strength_score}/100)\n"

        QMessageBox.information(self, "Password Health", message)

    # ---------------------------------------------------------------- files

    def export_passwords(self):
        """Export passwords to CSV (plain text, so it needs a warning and the master password)"""
        from PyQt5.QtWidgets import QFileDialog, QInputDialog
        import csv
        from datetime import datetime

        reply = QMessageBox.warning(
            self,
            "Export Passwords",
            "The exported CSV file is NOT encrypted: anyone who gets the file can read "
            "all your passwords.\n\n"
            "Keep it only as long as you need it, then delete it.\n\n"
            "Continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        master, ok = QInputDialog.getText(
            self, "Export Passwords", "Enter your master password to export:", QLineEdit.Password
        )
        if not ok:
            return
        if not self.app.auth_manager.verify_master_password(master):
            QMessageBox.critical(self, "Error", "Wrong master password. Nothing was exported.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Passwords",
            default_save_path(f"passwords_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"),
            "CSV Files (*.csv)"
        )

        # The vault may have been locked while the file dialog was open
        if file_path and self.app.auth_manager.is_logged_in():
            try:
                passwords = self.app.password_manager.get_all_passwords(self.user_id)

                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    # Plain-text passwords: owner-only file on macOS/Linux (no-op on Windows)
                    restrict_file(file_path)
                    writer = csv.writer(f)
                    writer.writerow(['Title', 'Username', 'Password', 'URL', 'Notes', 'Strength', 'Favorite'])

                    for pwd in passwords:
                        writer.writerow([
                            pwd.title,
                            pwd.username,
                            pwd.password,
                            pwd.url,
                            pwd.notes,
                            pwd.strength_score,
                            'Yes' if pwd.is_favorite else 'No'
                        ])

                QMessageBox.information(self, "Success", f"Exported {len(passwords)} passwords to:\n{file_path}")

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export: {str(e)}")

    def import_passwords(self):
        """Import passwords from CSV"""
        from PyQt5.QtWidgets import QFileDialog

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Passwords",
            "",
            "CSV Files (*.csv)"
        )

        if not file_path or not self.app.auth_manager.is_logged_in():
            return

        try:
            imported, skipped = self.import_csv_file(file_path)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to import: {str(e)}")
            return

        self.refresh_data()

        message = f"Imported {imported} passwords."
        if skipped:
            message += f"\n\nSkipped {len(skipped)} rows:\n" + "\n".join(skipped[:10])
            if len(skipped) > 10:
                message += f"\n... and {len(skipped) - 10} more"
            QMessageBox.warning(self, "Import Finished", message)
        else:
            QMessageBox.information(self, "Success", message)

    def import_csv_file(self, file_path):
        """Add every usable row of the CSV file; return (imported count, list of skipped-row reasons)

        A bad row used to stop the import half way, leaving the rows before it
        imported and the rest not. Now bad rows are skipped and reported.
        """
        import csv

        pm = self.app.password_manager
        imported = 0
        skipped = []

        # utf-8-sig: CSV files saved by Excel start with a byte-order mark
        with open(file_path, 'r', encoding='utf-8-sig', newline='') as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames or 'Password' not in reader.fieldnames:
                raise ValueError("The file has no 'Password' column. Expected columns: "
                                 "Title, Username, Password, URL, Notes")

            for line_number, row in enumerate(reader, start=2):
                password = row.get('Password') or ''
                url = (row.get('URL') or '').strip()
                username = (row.get('Username') or '').strip()
                title = (row.get('Title') or '').strip() or (
                    pm._extract_title_from_url(url) if url else username)

                if not password:
                    skipped.append(f"line {line_number}: no password")
                    continue
                if not title:
                    skipped.append(f"line {line_number}: no title, URL or username")
                    continue

                try:
                    pm.add_password(
                        user_id=self.user_id,
                        title=title,
                        username=username,
                        password=password,
                        url=url,
                        notes=row.get('Notes') or ''
                    )
                    imported += 1
                except Exception as e:
                    skipped.append(f"line {line_number}: {e}")

        return imported, skipped

    def create_backup(self):
        """Create database backup"""
        from PyQt5.QtWidgets import QFileDialog
        from datetime import datetime

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Create Backup",
            default_save_path(f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"),
            "Database Files (*.db)"
        )

        if file_path:
            try:
                # Consistent copy through SQLite's backup API, no need to disconnect
                self.app.db.backup_to(file_path)

                QMessageBox.information(self, "Success", f"Backup created:\n{file_path}")

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to create backup: {str(e)}")

    def restore_backup(self):
        """Restore from backup"""
        from PyQt5.QtWidgets import QFileDialog, QInputDialog

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Restore from Backup",
            "",
            "Database Files (*.db)"
        )

        if not file_path or not self.app.auth_manager.is_logged_in():
            return

        if not self.is_valid_backup(file_path):
            QMessageBox.critical(
                self, "Error",
                "This file is not a Password Manager backup (no account found in it)."
            )
            return

        # Check the backup's master password BEFORE replacing anything: restoring
        # a backup whose password is unknown would lock the user out of everything
        backup_password, ok = QInputDialog.getText(
            self, "Restore from Backup",
            "Enter the master password of this backup\n(the one used when the backup was made):",
            QLineEdit.Password
        )
        if not ok:
            return
        if not self.app.auth_manager.check_backup_password(file_path, backup_password):
            QMessageBox.critical(self, "Error",
                                 "Wrong master password for this backup. Nothing was changed.")
            return

        reply = QMessageBox.warning(
            self,
            "Confirm Restore",
            "Restoring from backup will replace all current data.\n\n"
            "A copy of the current vault will be saved next to it first.\n\n"
            "Continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply != QMessageBox.Yes or not self.app.auth_manager.is_logged_in():
            return

        # A running security check reads the database file that is about to be replaced
        self.security_page.shutdown()

        try:
            saved_copy = self.app.restore_database(file_path)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to restore: {str(e)}")
            return

        # The backup may use a different master password, so the key in
        # memory no longer matches: log in again with the backup's password.
        QMessageBox.information(
            self, "Success",
            "Database restored from backup.\n\n"
            f"The previous vault was saved as:\n{saved_copy}\n\n"
            "Please log in with the backup's master password."
        )
        self.app.lock_vault()

    @staticmethod
    def is_valid_backup(file_path):
        """Check that the file is a vault database with an account in it"""
        import sqlite3
        try:
            conn = sqlite3.connect(f"file:{file_path}?mode=ro", uri=True)
            try:
                row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
                return bool(row and row[0])
            finally:
                conn.close()
        except sqlite3.Error:
            return False

    # ---------------------------------------------------------------- window

    def lock_vault(self):
        """Lock the vault"""
        reply = QMessageBox.question(
            self,
            "Lock Vault",
            "Are you sure you want to lock the vault?\nYou'll need to enter your master password again.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes
        )

        if reply == QMessageBox.Yes:
            self.app.lock_vault()

    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self,
            "About Password Manager",
            f"<h2>Password Manager v{__version__}</h2>"
            "<p>A secure, local password management application.</p>"
            "<h3>Features:</h3>"
            "<ul>"
            "<li>AES-256-GCM encryption</li>"
            "<li>Argon2id key derivation</li>"
            "<li>Local SQLite database</li>"
            "<li>Password generator with strength analysis</li>"
            "<li>Breach check (Have I Been Pwned, k-anonymity)</li>"
            "<li>Category organization</li>"
            "<li>Favorites and search</li>"
            "<li>Export/Import functionality</li>"
            "<li>Auto-lock after inactivity</li>"
            "<li>Three colour themes</li>"
            "<li>Browser extension for Firefox and Safari</li>"
            "</ul>"
            "<p><b>Security:</b> Your passwords never leave your device.</p>"
            "<p>© 2025 SecureVault</p>"
        )

    def close_without_prompt(self):
        """Close the window without the exit confirmation (used when locking)"""
        self._skip_close_prompt = True
        self.security_page.shutdown()
        self.close()
        self.deleteLater()

    def closeEvent(self, event):
        """Handle window close"""
        if self._skip_close_prompt:
            event.accept()
            return

        reply = QMessageBox.question(
            self,
            "Exit",
            "Are you sure you want to exit?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            self.security_page.shutdown()
            event.accept()
        else:
            event.ignore()
