"""
Smoke tests for the user interface (run headless with QT_QPA_PLATFORM=offscreen).
Message boxes are replaced with stubs so no dialog blocks the test.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt5.QtWidgets import QApplication, QMessageBox, QDialog, QInputDialog

MASTER = "FirstPass11!"


@pytest.fixture
def messages(monkeypatch):
    """Record message boxes instead of showing them; question/warning answer Yes"""
    shown = []

    def record(kind, answer):
        def stub(parent, title, text, *args, **kwargs):
            shown.append((kind, title, text))
            return answer
        return stub

    monkeypatch.setattr(QMessageBox, "information", record("information", QMessageBox.Ok))
    monkeypatch.setattr(QMessageBox, "critical", record("critical", QMessageBox.Ok))
    monkeypatch.setattr(QMessageBox, "warning", record("warning", QMessageBox.Yes))
    monkeypatch.setattr(QMessageBox, "question", record("question", QMessageBox.Yes))

    # An unexpected input dialog would block the test (until the auto-lock closes it)
    def unexpected_input(*args, **kwargs):
        pytest.fail("QInputDialog.getText was not stubbed in this test")
    monkeypatch.setattr(QInputDialog, "getText", unexpected_input)
    return shown


@pytest.fixture
def app(qtbot, tmp_path, monkeypatch, messages):
    monkeypatch.setenv("PASSWORD_VAULT_DB", str(tmp_path / "vault.db"))
    from main import PasswordManagerApp

    pm_app = PasswordManagerApp()
    pm_app.start()
    yield pm_app
    if pm_app.main_window:
        pm_app.main_window.close_without_prompt()
    if pm_app.login_widget:
        pm_app.login_widget.close()
    pm_app.shutdown()


def create_account(pm_app, monkeypatch, password=MASTER):
    login = pm_app.login_widget
    monkeypatch.setattr(login, "show_confirm_password_dialog", lambda: (password, True))
    login.password_input.setText(password)
    login.on_create_account_clicked()


def log_in(pm_app, password=MASTER):
    pm_app.login_widget.password_input.setText(password)
    pm_app.login_widget.on_login_clicked()


def test_create_account_opens_main_window(app, monkeypatch):
    assert not app.login_widget.account_exists
    create_account(app, monkeypatch)
    assert app.main_window is not None
    assert app.auth_manager.is_logged_in()


def test_lock_vault_button_returns_to_login(app, monkeypatch, messages):
    create_account(app, monkeypatch)
    window = app.main_window

    window.lock_vault()

    assert app.main_window is None
    assert not app.auth_manager.is_logged_in()
    assert app.login_widget is not None and app.login_widget.isVisible()
    assert not any(kind == "critical" for kind, _, _ in messages)

    log_in(app)
    assert app.auth_manager.is_logged_in()
    assert app.main_window is not None


def test_auto_lock_locks_instead_of_quitting(app, monkeypatch):
    create_account(app, monkeypatch)
    assert app.auto_lock_timer.isActive()

    app.auto_lock()

    assert not app.auth_manager.is_logged_in()
    assert app.login_widget.isVisible()


def test_reset_vault_button_creates_new_account(app, monkeypatch):
    create_account(app, monkeypatch)
    uid = app.auth_manager.get_current_user_id()
    app.password_manager.add_password(uid, "Bank", "bob", "Secret123!")
    app.lock_vault()

    assert app.login_widget.account_exists
    create_account(app, monkeypatch, password="SecondPass2@")

    assert app.auth_manager.is_logged_in()
    uid = app.auth_manager.get_current_user_id()
    assert app.password_manager.get_all_passwords(uid) == []


def test_search_survives_refresh_and_filter_works(app, monkeypatch):
    create_account(app, monkeypatch)
    uid = app.auth_manager.get_current_user_id()
    app.password_manager.add_password(uid, "Bank", "bob", "a")
    app.password_manager.add_password(uid, "Mail", "bob", "Xy9$mK#pL2@vN8qR")
    window = app.main_window
    window.refresh_data()

    window.search_input.setText("bank")
    window.refresh_data()
    assert window.entry_list.count() == 1
    assert window.entry_title(0) == "Bank"

    # The strength filter moved from a combo box to the count chips above the list
    window.search_input.setText("")
    window.strength_chips["Strong"].click()
    assert window.entry_list.count() == 1
    assert window.entry_title(0) == "Mail"


def test_restore_backup_requires_new_login(app, monkeypatch, tmp_path):
    from PyQt5.QtWidgets import QFileDialog

    create_account(app, monkeypatch)
    uid = app.auth_manager.get_current_user_id()
    app.password_manager.add_password(uid, "Bank", "bob", "Secret123!")

    backup = str(tmp_path / "backup.db")
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (backup, ""))
    app.main_window.create_backup()
    assert os.path.exists(backup)

    # An entry added after the backup: it must survive in the saved copy of the vault
    app.password_manager.add_password(uid, "Mail", "bob", "Other456!")

    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (backup, ""))
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: (MASTER, True))
    app.main_window.restore_backup()

    assert not app.auth_manager.is_logged_in()
    log_in(app)
    uid = app.auth_manager.get_current_user_id()
    assert [p.title for p in app.password_manager.get_all_passwords(uid)] == ["Bank"]

    saved = [f for f in os.listdir(tmp_path) if "_before_restore_" in f]
    assert len(saved) == 1


def test_restore_backup_with_wrong_password_changes_nothing(app, monkeypatch, tmp_path, messages):
    from PyQt5.QtWidgets import QFileDialog

    create_account(app, monkeypatch)
    uid = app.auth_manager.get_current_user_id()
    backup = str(tmp_path / "backup.db")
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (backup, ""))
    app.main_window.create_backup()
    app.password_manager.add_password(uid, "Mail", "bob", "Other456!")

    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (backup, ""))
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("NotTheRightOne1!", True))
    messages.clear()
    app.main_window.restore_backup()

    assert app.auth_manager.is_logged_in()
    assert [p.title for p in app.password_manager.get_all_passwords(uid)] == ["Mail"]
    assert any(kind == "critical" for kind, _, _ in messages)
    assert not [f for f in os.listdir(tmp_path) if "_before_restore_" in f]


def test_export_needs_master_password(app, monkeypatch, tmp_path, messages):
    from PyQt5.QtWidgets import QFileDialog

    create_account(app, monkeypatch)
    uid = app.auth_manager.get_current_user_id()
    app.password_manager.add_password(uid, "Bank", "bob", "Secret123!")
    target = tmp_path / "export.csv"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(target), ""))

    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("WrongPass99!", True))
    messages.clear()
    app.main_window.export_passwords()
    assert not target.exists()
    # The warning about the unencrypted file was shown first
    assert messages[0][0] == "warning"

    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: (MASTER, True))
    app.main_window.export_passwords()
    assert "Secret123!" in target.read_text(encoding="utf-8")
    # A wrong password here is not a failed login
    assert app.auth_manager.is_logged_in()


def test_import_skips_bad_rows_and_reports_them(app, monkeypatch, tmp_path, messages):
    from PyQt5.QtWidgets import QFileDialog

    create_account(app, monkeypatch)
    uid = app.auth_manager.get_current_user_id()
    source = tmp_path / "import.csv"
    # Excel-style file with a byte-order mark; the second row has no password
    source.write_text(
        "Title,Username,Password,URL,Notes\n"
        "Bank,bob,Secret123!,,\n"
        "Broken,bob,,,\n"
        ",alice,Other456!,https://mail.example.com,\n",
        encoding="utf-8-sig"
    )
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(source), ""))
    messages.clear()
    app.main_window.import_passwords()

    titles = sorted(p.title for p in app.password_manager.get_all_passwords(uid))
    assert titles == ["Bank", "Mail"]
    kind, _, text = messages[-1]
    assert kind == "warning" and "line 3: no password" in text


def test_add_entry_without_username(app, monkeypatch):
    from ui.add_password_dialog import AddPasswordDialog

    create_account(app, monkeypatch)
    uid = app.auth_manager.get_current_user_id()
    dialog = AddPasswordDialog(app.password_manager, uid, [])
    dialog.title_input.setText("Home Wi-Fi")
    dialog.password_input.setText("wifi-secret-123")
    dialog.save_password()

    [entry] = app.password_manager.get_all_passwords(uid)
    assert entry.title == "Home Wi-Fi" and entry.username == ""


def test_lock_clears_copied_password(app, monkeypatch):
    create_account(app, monkeypatch)
    uid = app.auth_manager.get_current_user_id()
    pid = app.password_manager.add_password(uid, "Bank", "bob", "Secret123!")
    app.main_window.copy_password(pid)
    assert QApplication.clipboard().text() == "Secret123!"

    app.lock_vault()
    assert QApplication.clipboard().text() != "Secret123!"


def test_edit_dialog_keeps_spaces_and_clears_category(app, monkeypatch):
    from ui.add_password_dialog import AddPasswordDialog

    create_account(app, monkeypatch)
    uid = app.auth_manager.get_current_user_id()
    categories = app.db.fetch_all("SELECT * FROM categories")
    pid = app.password_manager.add_password(uid, "Bank", "bob", "Secret123!",
                                            category_id=categories[0]['category_id'])

    dialog = AddPasswordDialog(app.password_manager, uid, categories,
                               app.password_manager.get_password(pid, uid))
    assert dialog.title_input.text() == "Bank"
    dialog.password_input.setText(" with spaces ")
    dialog.category_combo.setCurrentIndex(0)  # "None"
    dialog.save_password()

    entry = app.password_manager.get_password(pid, uid)
    assert entry.password == " with spaces "
    assert entry.category_id is None


@pytest.mark.parametrize("dialog_name", ["login", "add", "generator", "breach", "main"])
def test_windows_fit_small_screen(app, monkeypatch, dialog_name):
    from ui.add_password_dialog import AddPasswordDialog
    from ui.password_generator_dialog import PasswordGeneratorDialog
    from ui.breach_dialog import BreachDialog

    if dialog_name == "login":
        widget = app.login_widget
    elif dialog_name == "add":
        widget = AddPasswordDialog(app.password_manager, 1, [])
    elif dialog_name == "generator":
        widget = PasswordGeneratorDialog()
    else:
        create_account(app, monkeypatch)
        if dialog_name == "breach":
            widget = BreachDialog(app.password_manager, app.auth_manager.get_current_user_id())
        else:
            widget = app.main_window

    # 1366x768 laptop screen minus the taskbar
    assert widget.minimumSize().height() <= 720
    assert widget.minimumSizeHint().height() <= 720
    assert widget.size().height() <= 720
    assert widget.minimumSize().width() <= 1340
    assert widget.minimumSizeHint().width() <= 1340


def test_breach_check_error_is_not_reported_as_success(app, monkeypatch, messages, qtbot):
    from ui.breach_dialog import BreachDialog

    create_account(app, monkeypatch)
    dialog = BreachDialog(app.password_manager, app.auth_manager.get_current_user_id())
    # A bad key makes the background check fail
    monkeypatch.setattr(app.password_manager.encryption, "copy_key", lambda: bytearray(b"short"))
    messages.clear()

    dialog.start_breach_check()
    qtbot.waitUntil(lambda: dialog.check_btn.isEnabled(), timeout=5000)
    qtbot.wait(100)

    kinds = [kind for kind, _, _ in messages]
    assert "critical" in kinds
    assert not any(title == "Check Complete" for _, title, _ in messages)
    dialog.done(QDialog.Rejected)


def test_breach_check_offline_is_flagged(app, monkeypatch, messages, qtbot):
    from security.breach_detector import BreachDetector
    from ui.breach_dialog import BreachDialog

    monkeypatch.setattr(BreachDetector, "_fetch_hibp_hashes", lambda self, prefix: None)
    create_account(app, monkeypatch)
    uid = app.auth_manager.get_current_user_id()
    app.password_manager.add_password(uid, "Bank", "bob", "Secret123!")

    dialog = BreachDialog(app.password_manager, uid)
    messages.clear()
    dialog.start_breach_check()
    qtbot.waitUntil(lambda: dialog.check_btn.isEnabled(), timeout=5000)
    qtbot.wait(100)

    assert dialog.results_table.rowCount() == 1
    assert "NOT CHECKED" in dialog.results_table.item(0, 3).text()
    assert any(title == "Check Incomplete" for _, title, _ in messages)
    dialog.done(QDialog.Rejected)
