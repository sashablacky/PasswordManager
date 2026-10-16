from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QTableWidget, QTableWidgetItem,
                             QHeaderView, QMessageBox, QProgressBar,
                             QGroupBox, QTextEdit, QSplitter, QFrame,
                             QToolTip, QApplication, QWidget)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, QPoint
from PyQt5.QtGui import QFont, QColor, QPalette

from security.breach_detector import BreachDetector
from database.db_manager import DatabaseManager
from security.encryption import EncryptionEngine, wipe
from ui.clipboard import copy_secret
from ui.layout_utils import resize_to_fit_screen
import logging
import json

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


class BreachDialog(QDialog):
    """Dialog for displaying breach check results"""

    def __init__(self, password_manager, user_id, parent=None):
        super().__init__(parent)
        self.password_manager = password_manager
        self.user_id = user_id
        self.db_path = password_manager.db.db_path
        # Main thread detector for UI (reads the encrypted stored results)
        self.detector = BreachDetector(password_manager.db, password_manager.encryption)
        self.breach_results = []
        self.check_thread = None

        self.setup_ui()
        self.load_previous_results()

    def setup_ui(self):
        """Setup the user interface"""
        self.setWindowTitle("🔒 Password Breach Detection")
        # Must fit a 1366x768 screen with the taskbar (the old 1000x700 minimum did not)
        self.setMinimumSize(860, 560)
        resize_to_fit_screen(self, 1000, 700)
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
                background-color: white;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QTableWidget {
                background-color: white;
                border: none;
                border-radius: 5px;
                gridline-color: #d0d0d0;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QHeaderView::section {
                background-color: #667eea;
                color: white;
                padding: 12px;
                border: none;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton {
                padding: 8px 16px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 13px;
            }
            QProgressBar {
                border: 2px solid #e0e0e0;
                border-radius: 5px;
                text-align: center;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #667eea;
                border-radius: 3px;
            }
        """)

        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        header_layout = QHBoxLayout()

        title_label = QLabel("🔍 Password Breach Checker")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #2c3e50;")
        header_layout.addWidget(title_label)

        header_layout.addStretch()

        # Last check info
        self.last_check_label = QLabel("Last check: Never")
        self.last_check_label.setStyleSheet("color: #7f8c8d; font-size: 12px;")
        header_layout.addWidget(self.last_check_label)

        # Check now button
        self.check_btn = QPushButton("🔄 Check Now")
        self.check_btn.setStyleSheet("""
            QPushButton {
                background-color: #667eea;
                color: white;
                border: none;
                padding: 10px 20px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #5568d3;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
        """)
        self.check_btn.clicked.connect(self.start_breach_check)
        header_layout.addWidget(self.check_btn)

        layout.addLayout(header_layout)

        # Progress bar (hidden initially)
        self.progress_group = QGroupBox("Checking Passwords...")
        self.progress_group.setVisible(False)
        progress_layout = QVBoxLayout()

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        progress_layout.addWidget(self.progress_bar)

        self.progress_label = QLabel("Preparing to check...")
        self.progress_label.setAlignment(Qt.AlignCenter)
        progress_layout.addWidget(self.progress_label)

        self.progress_group.setLayout(progress_layout)
        layout.addWidget(self.progress_group)

        # Statistics cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(10)

        self.total_card = self.create_stat_card("Total Checked", "0", "#667eea")
        stats_layout.addWidget(self.total_card)

        self.compromised_card = self.create_stat_card("Compromised", "0", "#e74c3c")
        stats_layout.addWidget(self.compromised_card)

        self.critical_card = self.create_stat_card("Critical Risk", "0", "#c0392b")
        stats_layout.addWidget(self.critical_card)

        self.high_card = self.create_stat_card("High Risk", "0", "#e67e22")
        stats_layout.addWidget(self.high_card)

        layout.addLayout(stats_layout)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels([
            "Title", "Risk Level", "Breach Count", "Status", "Actions"
        ])

        # Set column widths
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)  # Title
        header.setSectionResizeMode(1, QHeaderView.Fixed)  # Risk Level
        header.setSectionResizeMode(2, QHeaderView.Fixed)  # Breach Count
        header.setSectionResizeMode(3, QHeaderView.Fixed)  # Status
        header.setSectionResizeMode(4, QHeaderView.Fixed)  # Actions

        self.results_table.setColumnWidth(1, 120)  # Risk Level
        self.results_table.setColumnWidth(2, 120)  # Breach Count
        self.results_table.setColumnWidth(3, 130)  # Status
        self.results_table.setColumnWidth(4, 250)  # Actions (wider for buttons)

        # Increase row height to accommodate buttons
        self.results_table.verticalHeader().setDefaultSectionSize(40)

        # Better row height for buttons
        self.results_table.verticalHeader().setDefaultSectionSize(50)

        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setShowGrid(True)
        self.results_table.setGridStyle(Qt.SolidLine)
        self.results_table.verticalHeader().setVisible(False)

        layout.addWidget(self.results_table)

        # Details panel
        self.details_group = QGroupBox("Details & Recommendations")
        details_layout = QVBoxLayout()

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(150)
        self.details_text.setStyleSheet("""
            QTextEdit {
                background-color: white;
                border: 1px solid #e0e0e0;
                border-radius: 5px;
                padding: 10px;
                font-family: monospace;
            }
        """)
        details_layout.addWidget(self.details_text)

        self.details_group.setLayout(details_layout)
        layout.addWidget(self.details_group)

        # Bottom buttons
        button_layout = QHBoxLayout()

        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                min-width: 100px;
                padding: 10px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        close_btn.clicked.connect(self.accept)
        button_layout.addStretch()
        button_layout.addWidget(close_btn)

        layout.addLayout(button_layout)

        self.setLayout(layout)

        # Connect table click
        self.results_table.itemClicked.connect(self.on_result_clicked)

    def create_stat_card(self, label, value, color):
        """Create a statistics card"""
        card = QFrame()
        card.setFrameStyle(QFrame.StyledPanel)
        card.setStyleSheet(f"""
            QFrame {{
                background-color: {color};
                border-radius: 8px;
                padding: 15px;
            }}
        """)

        layout = QVBoxLayout()

        value_label = QLabel(value)
        value_label.setStyleSheet("color: white; font-size: 28px; font-weight: bold;")
        value_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(value_label)

        text_label = QLabel(label)
        text_label.setStyleSheet("color: white; font-size: 14px; opacity: 0.9;")
        text_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(text_label)

        card.setLayout(layout)
        return card

    def create_action_buttons(self, password_id):
        """Create action buttons for a row with better visibility"""
        widget = QWidget()

        # Set a background color for the widget to make it stand out
        widget.setStyleSheet("""
            QWidget {
                background-color: transparent;
            }
        """)

        layout = QHBoxLayout()
        layout.setContentsMargins(5, 2, 5, 2)
        layout.setSpacing(8)

        # View button - prominent blue
        view_btn = QPushButton("🔍 View")
        view_btn.setToolTip("View password details")
        view_btn.setMinimumWidth(70)
        view_btn.setFixedHeight(28)
        view_btn.setCursor(Qt.PointingHandCursor)
        view_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 11px;
                font-weight: bold;
                padding: 5px 8px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #1f618d;
            }
        """)
        view_btn.clicked.connect(lambda: self.view_password(password_id))
        layout.addWidget(view_btn)

        # Copy button - prominent green
        copy_btn = QPushButton("📋 Copy")
        copy_btn.setToolTip("Copy password to clipboard")
        copy_btn.setMinimumWidth(70)
        copy_btn.setFixedHeight(28)
        copy_btn.setCursor(Qt.PointingHandCursor)
        copy_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 11px;
                font-weight: bold;
                padding: 5px 8px;
            }
            QPushButton:hover {
                background-color: #229954;
            }
            QPushButton:pressed {
                background-color: #1e8449;
            }
        """)
        copy_btn.clicked.connect(lambda: self.copy_password(password_id))
        layout.addWidget(copy_btn)

        # Change button - prominent orange
        change_btn = QPushButton("🔄 Change")
        change_btn.setToolTip("Generate a new strong password")
        change_btn.setMinimumWidth(75)
        change_btn.setFixedHeight(28)
        change_btn.setCursor(Qt.PointingHandCursor)
        change_btn.setStyleSheet("""
            QPushButton {
                background-color: #e67e22;
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 11px;
                font-weight: bold;
                padding: 5px 8px;
            }
            QPushButton:hover {
                background-color: #d35400;
            }
            QPushButton:pressed {
                background-color: #ba4a00;
            }
        """)
        change_btn.clicked.connect(lambda: self.change_password(password_id))
        layout.addWidget(change_btn)

        # Add stretch to keep buttons left-aligned
        layout.addStretch()

        widget.setLayout(layout)

        # Ensure the widget has a proper size
        widget.setMinimumHeight(35)

        return widget

    def load_statistics(self):
        """Refresh the statistics cards from the stored results"""
        try:
            stats = self.detector.get_breach_statistics(self.user_id)

            self.total_card.findChild(QLabel).setText(str(stats['total_checked']))
            self.compromised_card.findChild(QLabel).setText(str(stats['compromised']))
            self.critical_card.findChild(QLabel).setText(str(stats['risk_levels'].get('critical', 0)))
            self.high_card.findChild(QLabel).setText(str(stats['risk_levels'].get('high', 0)))

            if stats['last_check']:
                if hasattr(stats['last_check'], 'strftime'):
                    self.last_check_label.setText(f"Last check: {stats['last_check'].strftime('%Y-%m-%d %H:%M')}")
                else:
                    self.last_check_label.setText(f"Last check: {stats['last_check']}")
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
        """Set row background color based on risk level"""
        colors = {
            'critical': QColor(255, 200, 200),  # Light red
            'high': QColor(255, 220, 180),      # Light orange
            'medium': QColor(255, 255, 180),    # Light yellow
            'low': QColor(220, 255, 220)        # Light green
        }

        color = colors.get(risk_level.lower(), QColor(255, 255, 255))

        for col in range(self.results_table.columnCount()):
            item = self.results_table.item(row, col)
            if item:
                item.setBackground(color)

    def display_results(self, results):
        """Display results in table"""
        self.results_table.setRowCount(len(results))

        for row, result in enumerate(results):
            # Title
            title_item = QTableWidgetItem(result['title'])
            title_item.setData(Qt.UserRole, result)
            self.results_table.setItem(row, 0, title_item)

            # Risk Level
            risk_item = QTableWidgetItem(result['risk_level'].upper())
            risk_item.setTextAlignment(Qt.AlignCenter)
            risk_item.setForeground(self.get_risk_color(result['risk_level']))
            risk_item.setFont(QFont("", weight=QFont.Bold))
            self.results_table.setItem(row, 1, risk_item)

            # Breach Count
            count_text = f"{result['breach_count']:,}" if result['breach_count'] > 0 else "0"
            count_item = QTableWidgetItem(count_text)
            count_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.results_table.setItem(row, 2, count_item)

            # Status
            if result.get('check_failed'):
                status = "❔ NOT CHECKED"
                status_color = QColor("#7f8c8d")
            elif result['breach_found']:
                status = "⚠️ COMPROMISED"
                status_color = QColor("#e74c3c")
            else:
                status = "✅ CLEAN"
                status_color = QColor("#27ae60")

            status_item = QTableWidgetItem(status)
            status_item.setTextAlignment(Qt.AlignCenter)
            status_item.setForeground(status_color)
            status_item.setFont(QFont("", weight=QFont.Bold))
            self.results_table.setItem(row, 3, status_item)

            # Actions
            actions_widget = self.create_action_buttons(result['password_id'])
            self.results_table.setCellWidget(row, 4, actions_widget)

            # Color the row based on risk level
            self.set_row_color(row, result['risk_level'])

    def get_risk_color(self, risk_level):
        """Get color for risk level"""
        colors = {
            'low': QColor("#27ae60"),      # Green
            'medium': QColor("#f39c12"),    # Yellow/Orange
            'high': QColor("#e67e22"),      # Orange
            'critical': QColor("#e74c3c")   # Red
        }
        return colors.get(risk_level.lower(), QColor("#7f8c8d"))

    def start_breach_check(self):
        """Start checking passwords for breaches"""
        self.check_btn.setEnabled(False)
        self.check_btn.setText("⏳ Checking...")

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
        self.breach_results = results
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
        self.check_btn.setText("🔄 Check Now")
        self.progress_group.setVisible(False)

    def on_check_error(self, error_msg):
        """Handle check error"""
        self.check_btn.setEnabled(True)
        self.check_btn.setText("🔄 Check Now")
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
        html = f"""
        <h3>{result['title']} - {result['username']}</h3>
        <p><b>Risk Level:</b> <span style="color:{self.get_risk_color(result['risk_level']).name()};">{result['risk_level'].upper()}</span></p>
        <p><b>Breach Found:</b> {'YES' if result['breach_found'] else 'NO'}</p>
        """

        if result['breach_found']:
            html += f"<p><b>Breach Count:</b> {result['breach_count']:,}</p>"

            if result.get('sources'):
                html += "<p><b>Sources:</b></p><ul>"
                for source in result['sources']:
                    html += f"<li>{source}</li>"
                html += "</ul>"

        if result.get('issues'):
            html += "<p><b>Issues Found:</b></p><ul>"
            for issue in result['issues']:
                html += f"<li>⚠️ {issue}</li>"
            html += "</ul>"

        html += "<p><b>Recommendations:</b></p><ul>"
        for rec in result['recommendations']:
            html += f"<li>{'✅' if '✓' in rec else '🔴'} {rec}</li>"
        html += "</ul>"

        self.details_text.setHtml(html)

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

            # Show tooltip feedback
            cursor_pos = self.mapToGlobal(self.rect().center())
            QToolTip.showText(cursor_pos,
                             f"✅ Password for '{pwd.title}' copied to clipboard!",
                             self, msecShowTime=2000)

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
                "Change the password on the website first, then use \"🎲 Generate\" "
                "in the next window (or type the new password) and click OK to save it here."
            )

            dialog = AddPasswordDialog(self.password_manager, self.user_id, categories, pwd)
            if dialog.exec_() == QDialog.Accepted:
                self.status_note(f"Password for '{pwd.title}' updated. Run the check again to re-test it.")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to change password:\n{str(e)}")

    def status_note(self, text):
        QToolTip.showText(self.mapToGlobal(self.rect().center()), text, self, msecShowTime=3000)

    def done(self, result):
        # Closing the dialog while the check is running would destroy a running QThread
        # (which crashes the app), so wait for it to finish first
        if self.check_thread is not None and self.check_thread.isRunning():
            self.check_thread.wait()
        super().done(result)
