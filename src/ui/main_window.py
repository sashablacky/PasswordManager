from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QPushButton, QTableWidget, QTableWidgetItem,
                             QLineEdit, QMessageBox, QHeaderView, QMenu,
                             QToolBar, QStatusBar, QApplication, QSplitter,
                             QListWidget, QListWidgetItem, QFrame, QProgressBar,
                             QComboBox, QDateEdit, QAction)
from PyQt5.QtCore import Qt, QTimer, QSize, QDate
from PyQt5.QtGui import QIcon, QFont, QColor, QPalette

from ui.add_password_dialog import AddPasswordDialog
from ui.password_generator_dialog import PasswordGeneratorDialog


class MainWindow(QMainWindow):
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

        self.setup_ui()
        self.load_categories()
        self.load_passwords()

        # Auto-refresh timer (every 30 seconds)
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_data)
        self.refresh_timer.start(30000)  # 30 seconds

        # Install event filter for auto-lock
        self.installEventFilter(self)

    def eventFilter(self, obj, event):
        """Handle events for auto-lock"""
        # Reset auto-lock timer on user activity
        if event.type() in [event.MouseButtonPress, event.KeyPress, event.MouseMove]:
            self.app.reset_auto_lock()
        return super().eventFilter(obj, event)

    def setup_ui(self):
        """Set up the user interface"""
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 1400, 800)
        self.setMinimumSize(1000, 600)

        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        main_layout = QHBoxLayout()
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Left sidebar
        sidebar = self.create_sidebar()
        main_layout.addWidget(sidebar)

        # Right content area
        content_area = self.create_content_area()
        main_layout.addWidget(content_area, 1)

        central_widget.setLayout(main_layout)

        # Create menu bar
        self.create_menu_bar()

        # Create toolbar
        self.create_toolbar()

        # Create status bar
        self.create_status_bar()

        # Apply stylesheet
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f7fa;
            }
            QLabel {
                color: #2c3e50;
            }
            QPushButton {
                padding: 8px 16px;
                border-radius: 5px;
                font-weight: bold;
            }
        """)

    def create_sidebar(self):
        """Create left sidebar"""
        sidebar = QWidget()
        sidebar.setFixedWidth(250)
        sidebar.setStyleSheet("""
            QWidget {
                background-color: white;
                border-right: 1px solid #e0e0e0;
            }
        """)

        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(15, 20, 15, 20)

        # User info
        user_label = QLabel("🔐 My Vault")
        user_font = QFont()
        user_font.setPointSize(16)
        user_font.setBold(True)
        user_label.setFont(user_font)
        user_label.setStyleSheet("color: #667eea; padding: 10px 0;")
        layout.addWidget(user_label)

        # Quick actions
        actions_label = QLabel("QUICK ACTIONS")
        actions_label.setStyleSheet("color: #7f8c8d; font-size: 11px; font-weight: bold;")
        layout.addWidget(actions_label)

        # Add password button
        add_btn = QPushButton("➕ Add Password")
        add_btn.setStyleSheet("""
            QPushButton {
                background-color: #667eea;
                color: white;
                border: none;
                text-align: left;
                padding: 12px;
            }
            QPushButton:hover {
                background-color: #5568d3;
            }
        """)
        add_btn.clicked.connect(self.show_add_password_dialog)
        layout.addWidget(add_btn)

        # Generate password button
        gen_btn = QPushButton("🎲 Generate Password")
        gen_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                text-align: left;
                padding: 12px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        gen_btn.clicked.connect(self.show_generator_dialog)
        layout.addWidget(gen_btn)

        layout.addSpacing(20)

        # Views
        views_label = QLabel("VIEWS")
        views_label.setStyleSheet("color: #7f8c8d; font-size: 11px; font-weight: bold;")
        layout.addWidget(views_label)

        views = [
            ("📋 All Passwords", "all"),
            ("⭐ Favorites", "favorites"),
            ("⚠️ Weak Passwords", "weak"),
            ("🕐 Recently Used", "recent"),
        ]

        self.view_buttons = {}
        for text, view_id in views:
            btn = QPushButton(text)
            btn.setCheckable(True)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    color: #2c3e50;
                    border: none;
                    text-align: left;
                    padding: 10px;
                }
                QPushButton:hover {
                    background-color: #f0f3ff;
                }
                QPushButton:checked {
                    background-color: #e3f2fd;
                    color: #667eea;
                    font-weight: bold;
                    border-left: 3px solid #667eea;
                }
            """)
            btn.clicked.connect(lambda checked, v=view_id: self.change_view(v))
            layout.addWidget(btn)
            self.view_buttons[view_id] = btn

        # Set "all" as checked by default
        self.view_buttons["all"].setChecked(True)

        layout.addSpacing(20)

        # Categories
        categories_label = QLabel("CATEGORIES")
        categories_label.setStyleSheet("color: #7f8c8d; font-size: 11px; font-weight: bold;")
        layout.addWidget(categories_label)

        self.category_list = QListWidget()
        self.category_list.setStyleSheet("""
            QListWidget {
                border: none;
                background-color: transparent;
            }
            QListWidget::item {
                padding: 8px;
                border-radius: 5px;
            }
            QListWidget::item:selected {
                background-color: #e3f2fd;
                color: #667eea;
            }
            QListWidget::item:hover {
                background-color: #f0f3ff;
            }
        """)
        self.category_list.itemClicked.connect(self.on_category_selected)
        layout.addWidget(self.category_list)

        layout.addStretch()

        # Lock button at bottom
        lock_btn = QPushButton("🔒 Lock Vault")
        lock_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                text-align: left;
                padding: 12px;
                margin-top: 10px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        lock_btn.clicked.connect(self.lock_vault)
        layout.addWidget(lock_btn)

        sidebar.setLayout(layout)
        return sidebar

    def create_content_area(self):
        """Create main content area"""
        content = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(25, 25, 25, 25)

        # Header with title and search
        header_layout = QHBoxLayout()

        self.view_title = QLabel("All Passwords")
        title_font = QFont()
        title_font.setPointSize(20)
        title_font.setBold(True)
        self.view_title.setFont(title_font)
        self.view_title.setStyleSheet("color: #2c3e50;")
        header_layout.addWidget(self.view_title)

        header_layout.addStretch()

        # Search bar
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search passwords...")
        self.search_input.setMinimumWidth(300)
        self.search_input.setMaximumHeight(35)
        self.search_input.setStyleSheet("""
            QLineEdit {
                padding: 8px 12px;
                border: 2px solid #e0e0e0;
                border-radius: 5px;
                font-size: 14px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #667eea;
            }
        """)
        self.search_input.textChanged.connect(self.on_search)
        search_layout.addWidget(self.search_input)

        # Filter combo
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All", "Strong", "Medium", "Weak"])
        self.filter_combo.setMaximumWidth(100)
        self.filter_combo.setMaximumHeight(35)
        self.filter_combo.setStyleSheet("""
            QComboBox {
                padding: 8px;
                border: 2px solid #e0e0e0;
                border-radius: 5px;
                background-color: white;
            }
        """)
        self.filter_combo.currentTextChanged.connect(self.apply_filter)
        search_layout.addWidget(self.filter_combo)

        # Refresh button
        refresh_btn = QPushButton("🔄")
        refresh_btn.setToolTip("Refresh")
        refresh_btn.setFixedSize(35, 35)
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #ecf0f1;
                border: none;
                border-radius: 5px;
                font-size: 16px;
            }
            QPushButton:hover {
                background-color: #bdc3c7;
            }
        """)
        refresh_btn.clicked.connect(self.refresh_data)
        search_layout.addWidget(refresh_btn)

        header_layout.addLayout(search_layout)
        layout.addLayout(header_layout)

        # Statistics cards
        self.stats_layout = QHBoxLayout()
        self.stats_layout.setSpacing(15)
        layout.addLayout(self.stats_layout)

        # Password table
        self.password_table = self.create_password_table()
        layout.addWidget(self.password_table)

        # Quick stats bar
        stats_bar = QHBoxLayout()
        stats_bar.addWidget(QLabel("🔄 Auto-refresh every 30s"))
        stats_bar.addStretch()
        self.record_count_label = QLabel("0 passwords")
        stats_bar.addWidget(self.record_count_label)
        layout.addLayout(stats_bar)

        content.setLayout(layout)
        return content

    def create_password_table(self):
        """Create password table"""
        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels([
            "Title", "Username", "Strength", "Last Used", "Favorite", "Actions"
        ])

        # Set column widths
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)  # Title
        header.setSectionResizeMode(1, QHeaderView.Stretch)  # Username
        header.setSectionResizeMode(2, QHeaderView.Fixed)    # Strength
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Last Used
        header.setSectionResizeMode(4, QHeaderView.Fixed)    # Favorite
        header.setSectionResizeMode(5, QHeaderView.Fixed)    # Actions

        table.setColumnWidth(2, 100)
        table.setColumnWidth(4, 60)
        table.setColumnWidth(5, 150)

        # Style
        table.setStyleSheet("""
            QTableWidget {
                background-color: white;
                border: none;
                border-radius: 10px;
                gridline-color: #ecf0f1;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QTableWidget::item:selected {
                background-color: #e3f2fd;
                color: #2c3e50;
            }
            QHeaderView::section {
                background-color: #667eea;
                color: white;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
        """)

        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setAlternatingRowColors(True)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.NoEditTriggers)

        # Connect double-click
        table.doubleClicked.connect(self.on_table_double_click)

        return table

    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()
        menubar.setStyleSheet("""
            QMenuBar {
                background-color: white;
                border-bottom: 1px solid #e0e0e0;
            }
            QMenuBar::item {
                padding: 8px 12px;
            }
            QMenuBar::item:selected {
                background-color: #e3f2fd;
            }
        """)

        # File menu
        file_menu = menubar.addMenu("File")

        export_action = QAction("Export Passwords", self)
        export_action.triggered.connect(self.export_passwords)
        file_menu.addAction(export_action)

        import_action = QAction("Import Passwords", self)
        import_action.triggered.connect(self.import_passwords)
        file_menu.addAction(import_action)

        file_menu.addSeparator()

        backup_action = QAction("Create Backup", self)
        backup_action.triggered.connect(self.create_backup)
        file_menu.addAction(backup_action)

        restore_action = QAction("Restore from Backup", self)
        restore_action.triggered.connect(self.restore_backup)
        file_menu.addAction(restore_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Edit menu
        edit_menu = menubar.addMenu("Edit")

        add_action = QAction("Add Password", self)
        add_action.setShortcut("Ctrl+N")
        add_action.triggered.connect(self.show_add_password_dialog)
        edit_menu.addAction(add_action)

        edit_menu.addSeparator()

        change_master_action = QAction("Change Master Password", self)
        change_master_action.triggered.connect(self.change_master_password)
        edit_menu.addAction(change_master_action)

        # View menu
        view_menu = menubar.addMenu("View")

        show_all_action = QAction("Show All Passwords", self)
        show_all_action.triggered.connect(lambda: self.change_view("all"))
        view_menu.addAction(show_all_action)

        show_favorites_action = QAction("Show Favorites", self)
        show_favorites_action.triggered.connect(lambda: self.change_view("favorites"))
        view_menu.addAction(show_favorites_action)

        show_weak_action = QAction("Show Weak Passwords", self)
        show_weak_action.triggered.connect(lambda: self.change_view("weak"))
        view_menu.addAction(show_weak_action)

        # Tools menu
        tools_menu = menubar.addMenu("Tools")

        gen_action = QAction("Password Generator", self)
        gen_action.setShortcut("Ctrl+G")
        gen_action.triggered.connect(self.show_generator_dialog)
        tools_menu.addAction(gen_action)

        breach_action = QAction("Check for Breaches", self)
        breach_action.triggered.connect(self.check_breaches)
        tools_menu.addAction(breach_action)

        health_action = QAction("Password Health Check", self)
        health_action.triggered.connect(self.show_health_check)
        tools_menu.addAction(health_action)

        # Help menu
        help_menu = menubar.addMenu("Help")

        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def create_toolbar(self):
        """Create toolbar"""
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(24, 24))
        toolbar.setStyleSheet("""
            QToolBar {
                background-color: white;
                border-bottom: 1px solid #e0e0e0;
                spacing: 10px;
                padding: 5px;
            }
        """)

        # Add actions
        add_action = QAction("➕ Add", self)
        add_action.triggered.connect(self.show_add_password_dialog)
        toolbar.addAction(add_action)

        toolbar.addSeparator()

        gen_action = QAction("🎲 Generate", self)
        gen_action.triggered.connect(self.show_generator_dialog)
        toolbar.addAction(gen_action)

        toolbar.addSeparator()

        export_action = QAction("📤 Export", self)
        export_action.triggered.connect(self.export_passwords)
        toolbar.addAction(export_action)

        toolbar.addSeparator()

        health_action = QAction("📊 Health", self)
        health_action.triggered.connect(self.show_health_check)
        toolbar.addAction(health_action)

        self.addToolBar(toolbar)

    def create_status_bar(self):
        """Create status bar"""
        status_bar = QStatusBar()
        status_bar.setStyleSheet("""
            QStatusBar {
                background-color: white;
                border-top: 1px solid #e0e0e0;
            }
        """)
        self.setStatusBar(status_bar)

        # Add permanent widgets
        self.status_label = QLabel("Ready")
        status_bar.addWidget(self.status_label)

        self.encryption_status = QLabel("🔒 Encrypted")
        self.encryption_status.setStyleSheet("color: #27ae60;")
        status_bar.addPermanentWidget(self.encryption_status)

    def create_stat_card(self, label, value, color, icon=""):
        """Create a statistics card"""
        card = QFrame()
        card.setFrameStyle(QFrame.StyledPanel)
        card.setStyleSheet(f"""
            QFrame {{
                background-color: {color};
                border-radius: 10px;
                padding: 15px;
            }}
        """)

        layout = QVBoxLayout()

        # Value
        value_label = QLabel(f"{icon} {value}")
        value_label.setStyleSheet("color: white; font-size: 28px; font-weight: bold;")
        value_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(value_label)

        # Label
        text_label = QLabel(label)
        text_label.setStyleSheet("color: white; font-size: 14px; opacity: 0.9;")
        text_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(text_label)

        card.setLayout(layout)
        return card

    def update_statistics(self):
        """Update statistics cards"""
        try:
            # Clear existing cards
            while self.stats_layout.count():
                item = self.stats_layout.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()

            # Get statistics
            stats = self.app.password_manager.get_statistics(self.user_id)

            # Create cards
            cards = [
                ("Total", str(stats['total']), "#667eea", "📋"),
                ("Strong", str(stats['strong']), "#27ae60", "💪"),
                ("Medium", str(stats['medium']), "#f39c12", "👌"),
                ("Weak", str(stats['weak']), "#e74c3c", "⚠️"),
                ("Favorites", str(stats['favorites']), "#9b59b6", "⭐"),
            ]

            for label, value, color, icon in cards:
                card = self.create_stat_card(label, value, color, icon)
                self.stats_layout.addWidget(card)

        except Exception as e:
            # Show error card
            error_card = self.create_stat_card("Error", "?", "#e74c3c", "⚠️")
            self.stats_layout.addWidget(error_card)

    def load_categories(self):
        """Load categories from database"""
        try:
            categories = self.app.db.fetch_all(
                "SELECT * FROM categories WHERE user_id = ? ORDER BY sort_order",
                (self.user_id,)
            )

            self.category_list.clear()

            # Add "All Categories" item
            all_item = QListWidgetItem("📁 All Categories")
            all_item.setData(Qt.UserRole, None)
            self.category_list.addItem(all_item)

            # Add categories
            for cat in categories:
                item = QListWidgetItem(f"{cat['icon']} {cat['name']}")
                item.setData(Qt.UserRole, cat['category_id'])
                item.setForeground(QColor(cat.get('color', '#667eea')))
                self.category_list.addItem(item)

            # Select "All Categories"
            self.category_list.setCurrentRow(0)

        except Exception as e:
            print(f"Error loading categories: {e}")

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

            self.display_passwords(passwords)
            self.update_statistics()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load passwords:\n{str(e)}")

    def display_passwords(self, passwords):
        """Display passwords in table"""
        self.password_table.setRowCount(len(passwords))

        for row, pwd in enumerate(passwords):
            # Title
            title_item = QTableWidgetItem(pwd.title)
            title_item.setData(Qt.UserRole, pwd.password_id)
            self.password_table.setItem(row, 0, title_item)

            # Username
            username_item = QTableWidgetItem(pwd.username)
            self.password_table.setItem(row, 1, username_item)

            # Strength
            strength_text = self.get_strength_text(pwd.strength_score)
            strength_item = QTableWidgetItem(strength_text)
            strength_item.setForeground(self.get_strength_color(pwd.strength_score))
            strength_item.setTextAlignment(Qt.AlignCenter)
            self.password_table.setItem(row, 2, strength_item)

            # Last used - safely format date
            last_used_text = "Never"
            if pwd.last_used_date:
                try:
                    if hasattr(pwd.last_used_date, 'strftime'):
                        last_used_text = pwd.last_used_date.strftime("%Y-%m-%d %H:%M")
                    else:
                        # If it's already a string, use it as is
                        last_used_text = str(pwd.last_used_date)
                except Exception:
                    last_used_text = str(pwd.last_used_date)

            last_used_item = QTableWidgetItem(last_used_text)
            self.password_table.setItem(row, 3, last_used_item)

            # Favorite
            fav_text = "⭐" if pwd.is_favorite else "☆"
            fav_item = QTableWidgetItem(fav_text)
            fav_item.setTextAlignment(Qt.AlignCenter)
            self.password_table.setItem(row, 4, fav_item)

            # Actions (create buttons)
            actions_widget = self.create_action_buttons(pwd.password_id)
            self.password_table.setCellWidget(row, 5, actions_widget)

        # Update record count
        self.record_count_label.setText(f"{len(passwords)} passwords")

    def create_action_buttons(self, password_id):
        """Create action buttons for a password row"""
        widget = QWidget()
        layout = QHBoxLayout()
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(2)

        button_style = """
            QPushButton {
                background-color: transparent;
                border: none;
                padding: 5px;
                font-size: 14px;
                min-width: 30px;
            }
            QPushButton:hover {
                background-color: #f0f3ff;
                border-radius: 3px;
            }
        """

        # Copy button
        copy_btn = QPushButton("📋")
        copy_btn.setToolTip("Copy Password")
        copy_btn.setFixedSize(30, 30)
        copy_btn.setStyleSheet(button_style)
        copy_btn.clicked.connect(lambda: self.copy_password(password_id))
        layout.addWidget(copy_btn)

        # View button
        view_btn = QPushButton("👁")
        view_btn.setToolTip("View Details")
        view_btn.setFixedSize(30, 30)
        view_btn.setStyleSheet(button_style)
        view_btn.clicked.connect(lambda: self.view_password(password_id))
        layout.addWidget(view_btn)

        # Edit button
        edit_btn = QPushButton("✏️")
        edit_btn.setToolTip("Edit")
        edit_btn.setFixedSize(30, 30)
        edit_btn.setStyleSheet(button_style)
        edit_btn.clicked.connect(lambda: self.edit_password(password_id))
        layout.addWidget(edit_btn)

        # Delete button
        delete_btn = QPushButton("🗑️")
        delete_btn.setToolTip("Delete")
        delete_btn.setFixedSize(30, 30)
        delete_btn.setStyleSheet(button_style)
        delete_btn.clicked.connect(lambda: self.delete_password(password_id))
        layout.addWidget(delete_btn)

        widget.setLayout(layout)
        return widget

    def get_strength_text(self, score):
        """Get strength text from score"""
        if score < 30:
            return "Very Weak"
        elif score < 50:
            return "Weak"
        elif score < 75:
            return "Medium"
        else:
            return "Strong"

    def get_strength_color(self, score):
        """Get color for strength score"""
        if score < 30:
            return QColor("#e74c3c")  # Red
        elif score < 50:
            return QColor("#e67e22")  # Orange
        elif score < 75:
            return QColor("#f39c12")  # Yellow
        else:
            return QColor("#27ae60")  # Green

    def change_view(self, view_id):
        """Change current view"""
        self.current_view = view_id

        # Update button states
        for vid, btn in self.view_buttons.items():
            btn.setChecked(vid == view_id)

        # Update title
        titles = {
            "all": "All Passwords",
            "favorites": "⭐ Favorites",
            "weak": "⚠️ Weak Passwords",
            "recent": "🕐 Recently Used"
        }
        self.view_title.setText(titles.get(view_id, "Passwords"))

        # Reload passwords
        self.load_passwords()

    def on_category_selected(self, item):
        """Handle category selection"""
        self.current_category = item.data(Qt.UserRole)
        self.load_passwords()

    def on_search(self, text):
        """Handle search"""
        if not text:
            self.load_passwords()
        else:
            passwords = self.app.password_manager.search_passwords(self.user_id, text)
            self.display_passwords(passwords)
            self.record_count_label.setText(f"{len(passwords)} results")

    def apply_filter(self, filter_text):
        """Apply strength filter"""
        # This will be implemented with the current displayed passwords
        pass

    def on_table_double_click(self, index):
        """Handle table double-click"""
        row = index.row()
        password_id = self.password_table.item(row, 0).data(Qt.UserRole)
        self.view_password(password_id)

    def refresh_data(self):
        """Refresh all data"""
        self.load_categories()
        self.load_passwords()
        self.status_label.setText("Refreshed")
        QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))

    def copy_password(self, password_id):
        """Copy password to clipboard"""
        try:
            pwd = self.app.password_manager.get_password(password_id, self.user_id)

            # Copy to clipboard
            clipboard = QApplication.clipboard()
            clipboard.setText(pwd.password)

            # Update last used
            self.app.password_manager.update_last_used(password_id, self.user_id)

            self.status_label.setText(f"Password for '{pwd.title}' copied to clipboard")

            # Auto-clear clipboard after 30 seconds
            QTimer.singleShot(30000, lambda: clipboard.clear() if clipboard.text() == pwd.password else None)

            # Refresh to show updated last used
            QTimer.singleShot(500, self.refresh_data)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to copy password:\n{str(e)}")

    def view_password(self, password_id):
        """View password details"""
        try:
            pwd = self.app.password_manager.get_password(password_id, self.user_id)

            # Format dates safely
            created_date_str = "Unknown"
            if pwd.created_date:
                try:
                    if hasattr(pwd.created_date, 'strftime'):
                        created_date_str = pwd.created_date.strftime('%Y-%m-%d %H:%M')
                    else:
                        created_date_str = str(pwd.created_date)
                except Exception:
                    created_date_str = str(pwd.created_date)

            last_used_str = "Never"
            if pwd.last_used_date:
                try:
                    if hasattr(pwd.last_used_date, 'strftime'):
                        last_used_str = pwd.last_used_date.strftime('%Y-%m-%d %H:%M')
                    else:
                        last_used_str = str(pwd.last_used_date)
                except Exception:
                    last_used_str = str(pwd.last_used_date)

            # Create detail message
            message = f"Title: {pwd.title}\n\n"
            message += f"Username: {pwd.username}\n"
            message += f"Password: {pwd.password}\n"
            message += f"URL: {pwd.url or 'N/A'}\n\n"
            message += f"Strength: {pwd.strength_score}/100 ({self.get_strength_text(pwd.strength_score)})\n"
            message += f"Created: {created_date_str}\n"
            message += f"Last Used: {last_used_str}\n"
            message += f"Favorite: {'Yes' if pwd.is_favorite else 'No'}\n\n"
            message += f"Notes:\n{pwd.notes or 'No notes'}"

            QMessageBox.information(self, f"Password Details - {pwd.title}", message)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to view password:\n{str(e)}")

    def edit_password(self, password_id):
        """Edit password"""
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
                pwd
            )
            dialog.password_updated.connect(self.on_password_updated)
            dialog.exec_()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to edit password:\n{str(e)}")

    def delete_password(self, password_id):
        """Delete password"""
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
                self.status_label.setText("Password deleted")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete password:\n{str(e)}")

    def show_add_password_dialog(self):
        """Show add password dialog"""
        try:
            # Get categories
            categories = self.app.db.fetch_all(
                "SELECT * FROM categories WHERE user_id = ?",
                (self.user_id,)
            )

            dialog = AddPasswordDialog(
                self.app.password_manager,
                self.user_id,
                categories
            )
            dialog.password_added.connect(self.on_password_added)
            dialog.exec_()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open dialog:\n{str(e)}")

    def on_password_added(self, password_id):
        """Handle password added"""
        self.refresh_data()
        self.status_label.setText("Password added successfully")

    def on_password_updated(self, password_id):
        """Handle password updated"""
        self.refresh_data()
        self.status_label.setText("Password updated successfully")

    def show_generator_dialog(self):
        """Show password generator dialog"""
        dialog = PasswordGeneratorDialog(self.app.generator)
        dialog.exec_()

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

    def check_breaches(self):
        """Open breach detection dialog"""
        from ui.breach_dialog import BreachDialog

        dialog = BreachDialog(self.app.password_manager, self.user_id, self)
        dialog.exec_()

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
            message += "⚠️ Weak Passwords:\n"
            for pwd in weak[:5]:  # Show first 5
                message += f"  • {pwd.title} ({pwd.strength_score}/100)\n"

        QMessageBox.information(self, "Password Health", message)



    def export_passwords(self):
        """Export passwords to CSV"""
        from PyQt5.QtWidgets import QFileDialog
        import csv
        from datetime import datetime

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Passwords",
            f"passwords_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV Files (*.csv)"
        )

        if file_path:
            try:
                passwords = self.app.password_manager.get_all_passwords(self.user_id)

                with open(file_path, 'w', newline='', encoding='utf-8') as f:
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
        import csv

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Passwords",
            "",
            "CSV Files (*.csv)"
        )

        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)

                    imported = 0
                    for row in reader:
                        self.app.password_manager.add_password(
                            user_id=self.user_id,
                            title=row.get('Title', ''),
                            username=row.get('Username', ''),
                            password=row.get('Password', ''),
                            url=row.get('URL', ''),
                            notes=row.get('Notes', '')
                        )
                        imported += 1

                self.refresh_data()
                QMessageBox.information(self, "Success", f"Imported {imported} passwords")

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to import: {str(e)}")

    def create_backup(self):
        """Create database backup"""
        from PyQt5.QtWidgets import QFileDialog
        import shutil
        from datetime import datetime

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Create Backup",
            f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db",
            "Database Files (*.db)"
        )

        if file_path:
            try:
                # Close current connection
                self.app.db.disconnect()

                # Copy database file
                shutil.copy2(self.app.db_path, file_path)

                # Reconnect
                self.app.db.connect()

                QMessageBox.information(self, "Success", f"Backup created:\n{file_path}")

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to create backup: {str(e)}")

    def restore_backup(self):
        """Restore from backup"""
        from PyQt5.QtWidgets import QFileDialog
        import shutil

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Restore from Backup",
            "",
            "Database Files (*.db)"
        )

        if file_path:
            reply = QMessageBox.warning(
                self,
                "Confirm Restore",
                "Restoring from backup will overwrite all current data.\n\n"
                "This action cannot be undone!\n\n"
                "Are you absolutely sure?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                try:
                    # Close current connection
                    self.app.db.disconnect()

                    # Copy backup file
                    shutil.copy2(file_path, self.app.db_path)

                    # Reconnect
                    self.app.db.connect()
                    self.app.db.create_tables()

                    self.refresh_data()
                    QMessageBox.information(self, "Success", "Database restored from backup")

                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to restore: {str(e)}")

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
            "<h2>Password Manager v1.0</h2>"
            "<p>A secure, local password management application.</p>"
            "<h3>Features:</h3>"
            "<ul>"
            "<li>AES-256-GCM encryption</li>"
            "<li>Argon2id key derivation</li>"
            "<li>Local SQLite database</li>"
            "<li>Password generator with strength analysis</li>"
            "<li>Category organization</li>"
            "<li>Favorites and search</li>"
            "<li>Export/Import functionality</li>"
            "<li>Auto-lock after inactivity</li>"
            "</ul>"
            "<p><b>Security:</b> Your passwords never leave your device.</p>"
            "<p>© 2025 SecureVault</p>"
        )

    def closeEvent(self, event):
        """Handle window close"""
        reply = QMessageBox.question(
            self,
            "Exit",
            "Are you sure you want to exit?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            self.refresh_timer.stop()
            event.accept()
        else:
            event.ignore()