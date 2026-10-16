import html

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTableWidgetItem,
                             QHeaderView, QMessageBox, QToolTip, QWidget, QAbstractItemView)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QRectF
from PyQt5.QtGui import QFont, QColor, QPainter, QPen

from qfluentwidgets import (TableWidget, ProgressBar, TextEdit, PushButton, TransparentToolButton,
                            FluentIcon)
from security.breach_detector import BreachDetector
from database.db_manager import DatabaseManager
from security.encryption import EncryptionEngine, wipe
from ui import theme
from ui.clipboard import copy_secret
from ui.layout_utils import resize_to_fit_screen
import logging

logger = logging.getLogger(__name__)


class BreachCheckThread(QThread):
    """Background thread for breach checking"""

    progress = pyqtSignal(int, int)  # current, total
    result_ready = pyqtSignal(object)  # breach result
    error = pyqtSignal(str)
    # QThread's own `finished` signal is emitted when run() returns, success or not

    def __init__(self, user_id, encryption_key, db_path, bind_records=True):
        """
        Initialize breach check thread

        Args:
            user_id: User ID to check passwords for
            encryption_key: A copy of the encryption key (bytearray); wiped when the thread ends
            db_path: Path to database file
            bind_records: Vault format flag of the main encryption engine
        """
        super().__init__()
        self.user_id = user_id
        self.encryption_key = encryption_key
        self.db_path = db_path
        self.bind_records = bind_records

    def run(self):
        """Run the breach check in background thread"""
        db = None
        encryption = EncryptionEngine()
        try:
            # Create new database connection for this thread
            db = DatabaseManager(self.db_path)
            db.connect()

            # Create encryption engine with the key
            encryption.set_key(self.encryption_key)
            encryption.bind_records = self.bind_records
            wipe(self.encryption_key)

            # Create password manager with thread-local instances
            from managers.password_manager import PasswordManager
            password_manager = PasswordManager(db, encryption)

            # Create breach detector with thread-local db (results are stored encrypted)
            detector = BreachDetector(db, encryption)

            # Get all passwords
            passwords = password_manager.get_all_passwords(self.user_id)
            total = len(passwords)
            results = []

            for i, pwd in enumerate(passwords):
                self.progress.emit(i + 1, total)

                # Analyze password
                assessment = detector.analyze_password_risk(pwd.password)

                results.append({
                    'password_id': pwd.password_id,
                    'title': pwd.title,
                    'username': pwd.username,
                    'risk_level': assessment['risk_level'],
                    'breach_found': assessment['breach_found'],
                    'breach_count': assessment.get('breach_count', 0),
                    'sources': assessment.get('sources', []),
                    'recommendations': assessment['recommendations'],
                    'issues': assessment['issues'],
                    'check_failed': assessment.get('check_failed', False)
                })

                # Store in database using thread-local connection
                # (keep the previous result if the online check failed)
                if not assessment.get('check_failed'):
                    detector._store_breach_result(self.user_id, pwd.password_id, assessment)

            self.result_ready.emit(results)

        except Exception as e:
            logger.error(f"Breach check failed: {e}")
            self.error.emit(str(e))

        finally:
            wipe(self.encryption_key)
            encryption.clear_key()
            # Close thread-local database connection
            if db:
                db.disconnect()


class ScoreRing(theme.ThemedWidget):
    """Vault health score (0-100) drawn as a ring"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.score = None
        self.setFixedSize(84, 84)

    def set_score(self, score):
        self.score = score
        self.update()

    def paintEvent(self, e):
        p = theme.current()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(8, 8, 68, 68)
        pen = QPen(p.glass_line, 8)
        painter.setPen(pen)
        painter.drawEllipse(rect)
        if self.score:
            pen = QPen(QColor(p.accent2), 8)
            pen.setCapStyle(Qt.RoundCap)
            painter.setPen(pen)
            painter.drawArc(rect, 90 * 16, -int(360 * 16 * self.score / 100))


class StatCard(theme.GlassCard):
    """Big number with a caption, coloured by risk"""

    def __init__(self, caption, role, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(2)
        self.value_label = theme.label("0", role=role, size=30, weight=QFont.DemiBold, display=True)
        layout.addWidget(self.value_label)
        layout.addWidget(theme.label(caption, role="muted", size=13))

    def set_value(self, value):
        self.value_label.setText(str(value))


class BreachCheckPage(QWidget):
    """Breach and weakness check of all passwords (a page of the main window)"""

    entries_changed = pyqtSignal()        # a password was changed from here
    statistics_changed = pyqtSignal(int)  # number of compromised passwords

    def __init__(self, password_manager, user_id, parent=None, show_title=True):
        super().__init__(parent)
        self.setObjectName("securityPage")
        self.password_manager = password_manager
        self.user_id = user_id
        self.db_path = password_manager.db.db_path
        self.show_title = show_title
        # Main thread detector for UI (reads the encrypted stored results)
        self.detector = BreachDetector(password_manager.db, password_manager.encryption)
        self.breach_results = []
        self.check_thread = None

        self.setup_ui()
        self.load_previous_results()

    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        if self.show_title:
            layout.setContentsMargins(6, 6, 18, 18)
        else:
            layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        # Header
        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)
        header_layout.addWidget(theme.title_label("Security check"))
        header_layout.addStretch()

        # Last check info
        self.last_check_label = theme.label("Last check: never", role="faint", size=13)
        header_layout.addWidget(self.last_check_label)

        # Check now button
        self.check_btn = theme.primary_button("Check now", FluentIcon.SYNC)
        self.check_btn.clicked.connect(self.start_breach_check)
        header_layout.addWidget(self.check_btn)
        layout.addLayout(header_layout)

        # Progress (hidden until a check runs)
        self.progress_group = theme.GlassCard()
        self.progress_group.setVisible(False)
        progress_layout = QHBoxLayout(self.progress_group)
        progress_layout.setContentsMargins(18, 12, 18, 12)
        progress_layout.setSpacing(14)
        self.progress_label = theme.label("Preparing to check...", role="muted", size=13)
        progress_layout.addWidget(self.progress_label)
        self.progress_bar = ProgressBar()
        self.progress_bar.setRange(0, 100)
        progress_layout.addWidget(self.progress_bar, 1)
        layout.addWidget(self.progress_group)

        # Score and statistics
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(14)

        ring_card = theme.GlassCard()
        ring_layout = QHBoxLayout(ring_card)
        ring_layout.setContentsMargins(16, 12, 18, 12)
        ring_layout.setSpacing(14)
        self.score_ring = ScoreRing()
        ring_layout.addWidget(self.score_ring)
        ring_text = QVBoxLayout()
        ring_text.setSpacing(0)
        ring_text.addStretch(1)
        self.score_label = theme.label("—", size=28, weight=QFont.DemiBold, display=True)
        ring_text.addWidget(self.score_label)
        self.score_caption = theme.label("Vault health score out of 100", role="muted", size=13)
        self.score_caption.setWordWrap(True)
        ring_text.addWidget(self.score_caption)
        ring_text.addStretch(1)
        ring_layout.addLayout(ring_text, 1)
        ring_card.setMinimumWidth(250)
        stats_layout.addWidget(ring_card, 0)

        self.critical_card = StatCard("Critical risk", "bad")
        self.high_card = StatCard("High risk", "high")
        self.medium_card = StatCard("Medium risk", "warn")
        self.safe_card = StatCard("Safe", "ok")
        for card in (self.critical_card, self.high_card, self.medium_card, self.safe_card):
            stats_layout.addWidget(card, 1)
        layout.addLayout(stats_layout)

        # Results table
        results_card = theme.GlassCard()
        results_layout = QVBoxLayout(results_card)
        results_layout.setContentsMargins(6, 6, 6, 6)
        self.results_table = TableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels([
            "Title", "Risk level", "Breaches", "Status", "Actions"
        ])

        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        for col, width in ((1, 110), (2, 100), (3, 140), (4, 190)):
            header.setSectionResizeMode(col, QHeaderView.Fixed)
            self.results_table.setColumnWidth(col, width)

        self.results_table.verticalHeader().setDefaultSectionSize(46)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results_table.setBorderVisible(False)
        self.results_table.setWordWrap(False)
        self.results_table.setMinimumHeight(120)
        results_layout.addWidget(self.results_table)
        layout.addWidget(results_card, 1)

        # Details panel
        self.details_group = theme.GlassCard()
        details_layout = QVBoxLayout(self.details_group)
        details_layout.setContentsMargins(18, 12, 18, 12)
        details_layout.setSpacing(6)
        details_layout.addWidget(theme.label("Details & recommendations", size=14, weight=QFont.DemiBold))
        self.details_text = TextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFixedHeight(110)
        self.details_text.setPlaceholderText("Select a result to see why it is risky and what to do.")
        details_layout.addWidget(self.details_text)
        layout.addWidget(self.details_group)

        # Connect table click
        self.results_table.itemClicked.connect(self.on_result_clicked)
        theme.signals.changed.connect(self._on_theme_changed)

    def create_action_buttons(self, password_id):
        """View / copy / change buttons for one result row"""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(4)

        view_btn = TransparentToolButton(FluentIcon.VIEW)
        view_btn.setToolTip("View password details")
        view_btn.clicked.connect(lambda: self.view_password(password_id))
        layout.addWidget(view_btn)

        copy_btn = TransparentToolButton(FluentIcon.COPY)
        copy_btn.setToolTip("Copy password to clipboard")
        copy_btn.clicked.connect(lambda: self.copy_password(password_id))
        layout.addWidget(copy_btn)

        change_btn = PushButton("Change")
        change_btn.setToolTip("Open the entry to set a new password")
        change_btn.setFixedHeight(30)
        change_btn.clicked.connect(lambda: self.change_password(password_id))
        layout.addWidget(change_btn)

        layout.addStretch()
        return widget

    def load_statistics(self):
        """Refresh the score and the statistics cards from the stored results"""
        try:
            stats = self.detector.get_breach_statistics(self.user_id)
            levels = stats['risk_levels']
            checked = sum(levels.values())

            self.critical_card.set_value(levels.get('critical', 0))
            self.high_card.set_value(levels.get('high', 0))
            self.medium_card.set_value(levels.get('medium', 0))
            self.safe_card.set_value(levels.get('low', 0))

            if checked:
                score = round(100 * levels.get('low', 0) / checked)
                self.score_ring.set_score(score)
                self.score_label.setText(str(score))
                self.score_caption.setText(
                    f"Vault health out of 100 · {stats['total_checked']} checked, "
                    f"{stats['compromised']} compromised"
                )
            else:
                self.score_ring.set_score(None)
                self.score_label.setText("—")
                self.score_caption.setText("No check yet. Press “Check now”.")

            if stats['last_check']:
                if hasattr(stats['last_check'], 'strftime'):
                    self.last_check_label.setText(f"Last check: {stats['last_check'].strftime('%Y-%m-%d %H:%M')}")
                else:
                    self.last_check_label.setText(f"Last check: {stats['last_check']}")

            self.statistics_changed.emit(stats['compromised'])
        except Exception as e:
            logger.error(f"Failed to load breach statistics: {e}")

    def load_previous_results(self):
        """Load previous breach check results from database"""
        self.load_statistics()
        try:
            # Get compromised passwords
            compromised = self.detector.get_compromised_passwords(self.user_id)

            # For display, we need to get the actual passwords to show titles
            enhanced_results = []
            for comp in compromised:
                try:
                    pwd = self.password_manager.get_password(comp['password_id'], self.user_id)
                    enhanced_results.append({
                        'password_id': comp['password_id'],
                        'title': pwd.title,
                        'username': pwd.username,
                        'risk_level': comp['risk_level'],
                        'breach_found': comp['breach_found'],
                        'breach_count': comp['breach_count'],
                        'sources': comp.get('breach_details', []) if isinstance(comp.get('breach_details'), list) else [],
                        'recommendations': comp.get('recommendations', []) if isinstance(comp.get('recommendations'), list) else [],
                        'issues': []
                    })
                except Exception as e:
                    logger.warning(f"Failed to load password {comp.get('password_id')}: {e}")
                    continue

            self.display_results(enhanced_results)

        except Exception as e:
            logger.error(f"Failed to load previous results: {e}")

    def set_row_color(self, row, risk_level):
        """Tint the row with the risk colour"""
        color = QColor(theme.risk_color(risk_level))
        color.setAlpha(28)

        for col in range(self.results_table.columnCount()):
            item = self.results_table.item(row, col)
            if item:
                item.setBackground(color)

    def display_results(self, results):
        """Display results in table"""
        self.breach_results = results
        self.results_table.setRowCount(len(results))
        bold = QFont(theme.ui_font(13, QFont.DemiBold))

        for row, result in enumerate(results):
            # Title
            title_text = result['title'] + (f"  ·  {result['username']}" if result.get('username') else "")
            title_item = QTableWidgetItem(title_text)
            title_item.setData(Qt.UserRole, result)
            self.results_table.setItem(row, 0, title_item)

            # Risk Level
            risk_item = QTableWidgetItem(result['risk_level'].upper())
            risk_item.setTextAlignment(Qt.AlignCenter)
            risk_item.setForeground(self.get_risk_color(result['risk_level']))
            risk_item.setFont(bold)
            self.results_table.setItem(row, 1, risk_item)

            # Breach Count
            count_text = f"{result['breach_count']:,}" if result['breach_count'] > 0 else "0"
            count_item = QTableWidgetItem(count_text)
            count_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.results_table.setItem(row, 2, count_item)

            # Status
            p = theme.current()
            if result.get('check_failed'):
                status = "NOT CHECKED"
                status_color = p.faint
            elif result['breach_found']:
                status = "COMPROMISED"
                status_color = p.color("bad")
            else:
                status = "CLEAN"
                status_color = p.color("ok")

            status_item = QTableWidgetItem(status)
            status_item.setTextAlignment(Qt.AlignCenter)
            status_item.setForeground(status_color)
            status_item.setFont(bold)
            self.results_table.setItem(row, 3, status_item)

            # Actions (the empty item carries the row tint under the buttons)
            self.results_table.setItem(row, 4, QTableWidgetItem(""))
            actions_widget = self.create_action_buttons(result['password_id'])
            self.results_table.setCellWidget(row, 4, actions_widget)

            # Color the row based on risk level
            self.set_row_color(row, result['risk_level'])

    def get_risk_color(self, risk_level):
        """Get color for risk level"""
        return theme.risk_color(risk_level)

    def start_breach_check(self):
        """Start checking passwords for breaches"""
        self.check_btn.setEnabled(False)
        self.check_btn.setText("Checking...")

        self.progress_group.setVisible(True)
        self.progress_bar.setValue(0)

        # Clear previous results
        self.results_table.setRowCount(0)

        # Start background thread with thread-local database connection
        encryption = self.password_manager.encryption
        self.check_thread = BreachCheckThread(
            self.user_id,
            encryption.copy_key(),
            self.db_path,
            encryption.bind_records
        )
        self.check_thread.progress.connect(self.update_progress)
        self.check_thread.result_ready.connect(self.on_results_ready)
        self.check_thread.finished.connect(self.on_check_finished)
        self.check_thread.error.connect(self.on_check_error)
        self.check_thread.start()

    def update_progress(self, current, total):
        """Update progress bar"""
        percentage = int((current / total) * 100)
        self.progress_bar.setValue(percentage)
        self.progress_label.setText(f"Checking password {current} of {total}...")

    def on_results_ready(self, results):
        """Handle breach check results"""
        self.display_results(results)

        # Refresh statistics only, so the full results stay in the table
        self.load_statistics()

        not_checked = sum(1 for r in results if r.get('check_failed'))
        if results and not_checked == len(results):
            QMessageBox.warning(self, "Check Incomplete",
                                "Could not reach the online breach database (haveibeenpwned.com).\n"
                                "Check your internet connection and try again.\n\n"
                                "Only local weakness checks were performed.")
        elif not_checked:
            QMessageBox.warning(self, "Check Incomplete",
                                f"Breach check finished, but {not_checked} of {len(results)} passwords "
                                "could not be checked online. Please try again later.")
        else:
            QMessageBox.information(self, "Check Complete",
                                    "Breach check completed successfully!")

    def on_check_finished(self):
        """Reset the UI when the background check ends (success or error)"""
        self.check_btn.setEnabled(True)
        self.check_btn.setText("Check now")
        self.progress_group.setVisible(False)

    def on_check_error(self, error_msg):
        """Handle check error"""
        self.check_btn.setEnabled(True)
        self.check_btn.setText("Check now")
        self.progress_group.setVisible(False)

        QMessageBox.critical(self, "Error", f"Failed to check breaches:\n{error_msg}")

    def on_result_clicked(self, item):
        """Handle click on result row"""
        row = item.row()
        result_item = self.results_table.item(row, 0)
        if result_item and result_item.data(Qt.UserRole):
            result = result_item.data(Qt.UserRole)
            self.show_details(result)

    def show_details(self, result):
        """Show detailed information for a result"""
        p = theme.current()
        esc = html.escape
        risk = result['risk_level']
        text = (f"<p><b>{esc(result['title'])}</b>"
                + (f" <span style='color:{p.rgba('text', p.muted_alpha)}'>· {esc(result['username'])}</span>"
                   if result.get('username') else "")
                + f" — risk <b style='color:{self.get_risk_color(risk).name()}'>{esc(risk.upper())}</b>"
                + (f", found in breaches <b>{result['breach_count']:,}</b> times" if result['breach_found'] else
                   ", not found in known breaches")
                + "</p>")

        if result.get('sources'):
            text += "<p>Sources: " + ", ".join(esc(str(s)) for s in result['sources']) + "</p>"

        if result.get('issues'):
            text += "<p><b>Issues:</b> " + "; ".join(esc(str(i)) for i in result['issues']) + "</p>"

        if result.get('recommendations'):
            text += "<ul style='margin-left:-20px'>"
            for rec in result['recommendations']:
                color = p.ok if '✓' in rec else p.warn
                text += f"<li><span style='color:{color}'>{esc(rec.replace('✓', '').strip())}</span></li>"
            text += "</ul>"

        self.details_text.setHtml(text)

    def view_password(self, password_id):
        """View password details"""
        try:
            pwd = self.password_manager.get_password(password_id, self.user_id)

            message = f"Title: {pwd.title}\n"
            message += f"Username: {pwd.username}\n"
            message += f"Password: {pwd.password}\n"
            message += f"URL: {pwd.url or 'N/A'}\n\n"
            message += f"Created: {pwd.created_date}\n"
            message += f"Last Used: {pwd.last_used_date or 'Never'}"

            QMessageBox.information(self, f"Password: {pwd.title}", message)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to view password:\n{str(e)}")

    def copy_password(self, password_id):
        """Copy password to clipboard"""
        try:
            pwd = self.password_manager.get_password(password_id, self.user_id)

            # Copy to clipboard (cleared after 30 seconds or on exit)
            copy_secret(pwd.password)

            self.status_note(f"Password for '{pwd.title}' copied to clipboard")

            # Update last used
            self.password_manager.update_last_used(password_id, self.user_id)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to copy password:\n{str(e)}")

    def change_password(self, password_id):
        """Open the edit dialog so the user can generate and save a new password"""
        try:
            from ui.add_password_dialog import AddPasswordDialog

            pwd = self.password_manager.get_password(password_id, self.user_id)
            categories = self.password_manager.db.fetch_all(
                "SELECT * FROM categories WHERE user_id = ? ORDER BY sort_order",
                (self.user_id,)
            )

            QMessageBox.information(
                self,
                "Change Password",
                "Change the password on the website first, then use \"Generate\" "
                "in the next window (or type the new password) and click Save to keep it here."
            )

            dialog = AddPasswordDialog(self.password_manager, self.user_id, categories, pwd, parent=self)
            if dialog.exec_() == QDialog.Accepted:
                self.entries_changed.emit()
                self.status_note(f"Password for '{pwd.title}' updated. Run the check again to re-test it.")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to change password:\n{str(e)}")

    def status_note(self, text):
        QToolTip.showText(self.mapToGlobal(self.rect().center()), text, self, msecShowTime=3000)

    def shutdown(self):
        """Wait for a running check: destroying a running QThread crashes the app"""
        if self.check_thread is not None and self.check_thread.isRunning():
            self.check_thread.wait()

    def _on_theme_changed(self, key):
        try:
            self.display_results(self.breach_results)
        except RuntimeError:
            pass


class BreachDialog(QDialog):
    """The security check page in its own window"""

    def __init__(self, password_manager, user_id, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Password Breach Detection")
        self.setWindowIcon(theme.app_icon())
        # Must fit a 1366x768 screen with the taskbar (the old 1000x700 minimum did not)
        self.setMinimumSize(860, 560)
        resize_to_fit_screen(self, 1000, 700)

        self.page = BreachCheckPage(password_manager, user_id, show_title=False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 16)
        layout.setSpacing(12)
        layout.addWidget(self.page, 1)

        close_row = QHBoxLayout()
        close_row.addStretch()
        close_btn = PushButton("Close")
        close_btn.setMinimumWidth(100)
        close_btn.clicked.connect(self.accept)
        close_row.addWidget(close_btn)
        layout.addLayout(close_row)

    def paintEvent(self, e):
        painter = QPainter(self)
        theme.paint_backdrop(painter, self.rect())

    def __getattr__(self, name):
        # Expose the page's widgets and methods (check_btn, results_table, start_breach_check...)
        if name == "page":
            raise AttributeError(name)
        return getattr(self.page, name)

    def done(self, result):
        # Closing the dialog while the check is running would destroy a running QThread
        # (which crashes the app), so wait for it to finish first
        self.page.shutdown()
        super().done(result)
