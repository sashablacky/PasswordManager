"""
Screenshots of the redesigned UI in every theme, saved to design/screenshots/.

Runs the real application windows on a throw-away vault in a temporary folder
(PASSWORD_VAULT_DB / PASSWORD_MANAGER_SETTINGS overrides): the user's own vault
and settings in %APPDATA%\\SecureVault are never opened. All entries are made up.

    .venv\\Scripts\\python design\\make_screenshots.py
"""

import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "design", "screenshots")
sys.path.insert(0, os.path.join(ROOT, "src"))

TMP_DIR = tempfile.mkdtemp(prefix="pm-screenshots-")
os.environ["PASSWORD_VAULT_DB"] = os.path.join(TMP_DIR, "vault.db")
os.environ["PASSWORD_MANAGER_SETTINGS"] = os.path.join(TMP_DIR, "settings.json")

from PyQt5.QtCore import Qt  # noqa: E402
from PyQt5.QtTest import QTest  # noqa: E402
from PyQt5.QtWidgets import QApplication, QMessageBox  # noqa: E402

MASTER = "Screenshot-Vault-42!"

ENTRIES = [
    # title, username, password, url, notes, category, favorite, used
    ("GitHub", "alex.dev@example.com", "vK7#qT2m!Lx9pR$w4Zb", "https://github.com",
     "2FA through the authenticator app. Recovery codes are in the safe.", "Work", True, True),
    ("Gmail", "alex@example.com", "Hq8!wPz3@rT6nB2mXc", "https://mail.google.com", "", "Email", True, True),
    ("PayPal", "alex@example.com", "orbit-Maple-candle-river-71", "https://paypal.com", "", "Banking", False, False),
    ("Steam", "alex_gamer", "Gamer2019steam", "https://store.steampowered.com", "", "Entertainment", False, True),
    ("Amazon", "alex@example.com", "T4!kq9Lm#2xVp8Rz", "https://amazon.com", "Prime until May.", "Shopping", False, False),
    ("Netflix", "family@example.com", "netflix1", "https://netflix.com", "Shared with the family.", "Entertainment", False, False),
    ("LinkedIn", "alex.chernysh@example.com", "Wq7$Lp2!nZ8@kR4v", "https://linkedin.com", "", "Social Media", False, False),
    ("Monzo", "alex@example.com", "Cobalt-Fern-Quartz-Lamp-88", "https://monzo.com", "", "Banking", True, False),
    ("Discord", "alex#2041", "Discord2041!", "https://discord.com", "", "Social Media", False, False),
    ("Home Wi-Fi", "", "correct horse battery", "", "Router in the hall.", None, False, False),
]

BREACHES = {
    "Netflix": dict(breach_found=True, breach_count=3_412, risk_level="critical",
                    recommendations=["Change this password now: it is in known breaches",
                                     "Use a unique password for every site"]),
    "Steam": dict(breach_found=False, breach_count=0, risk_level="high",
                  recommendations=["Use at least 16 characters", "✓ Not found in known breaches"]),
    "Discord": dict(breach_found=True, breach_count=12, risk_level="high",
                    recommendations=["Change this password", "Turn on two-factor authentication"]),
}


def fill_vault(pm_app):
    from security.breach_detector import BreachDetector

    pm = pm_app.password_manager
    uid = pm_app.auth_manager.get_current_user_id()
    categories = {c["name"]: c["category_id"] for c in pm_app.db.fetch_all(
        "SELECT * FROM categories WHERE user_id = ?", (uid,))}
    ids = {}
    for title, user, password, url, notes, category, favorite, used in ENTRIES:
        pid = pm.add_password(uid, title, user, password, url=url, notes=notes,
                              category_id=categories.get(category))
        if favorite:
            pm.toggle_favorite(pid, uid)
        if used:
            pm.update_last_used(pid, uid)
        ids[title] = pid

    detector = BreachDetector(pm_app.db, pm.encryption)
    for title, pid in ids.items():
        result = BREACHES.get(title, dict(breach_found=False, breach_count=0, risk_level="low",
                                          recommendations=["✓ Not found in known breaches"]))
        detector._store_breach_result(uid, pid, result)


def _find(window, title):
    for row in range(window.entry_list.count()):
        if window.entry_title(row) == title:
            return window.entry_list.item(row).data(Qt.UserRole)
    return None


def save(widget, name):
    QTest.qWait(450)  # page switch and fade animations
    path = os.path.join(OUT_DIR, name)
    widget.grab().save(path)
    print("saved", os.path.relpath(path, ROOT))


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    for name in ("information", "warning", "critical"):
        setattr(QMessageBox, name, staticmethod(lambda *a, **k: QMessageBox.Ok))

    from main import PasswordManagerApp
    from ui import theme
    from ui.login_widget import LoginWidget
    from ui.main_window import MainWindow

    pm_app = PasswordManagerApp()
    pm_app.auth_manager.create_account(MASTER)
    pm_app.auth_manager.authenticate(MASTER)
    fill_vault(pm_app)
    pm_app.auth_manager.logout()

    try:
        for key in theme.THEME_ORDER:
            theme.apply_theme(key)

            login = LoginWidget(pm_app.auth_manager)
            login.resize(520, 680)
            login.show()
            save(login, f"{key}-login.png")
            login.close()

            pm_app.auth_manager.authenticate(MASTER)
            window = MainWindow(pm_app)
            window.resize(1280, 800)
            window.show()
            window.view_password(_find(window, "GitHub"))
            save(window, f"{key}-vault.png")

            window.show_page("generator")
            save(window, f"{key}-generator.png")

            window.show_page("security")
            page = window.security_page
            page.load_previous_results()
            if page.results_table.rowCount():
                page.results_table.selectRow(0)
                page.show_details(page.results_table.item(0, 0).data(Qt.UserRole))
            save(window, f"{key}-security.png")

            window.show_page("settings")
            save(window, f"{key}-settings.png")

            window.close_without_prompt()
            pm_app.auth_manager.logout()
            app.processEvents()
    finally:
        pm_app.shutdown()
        shutil.rmtree(TMP_DIR, ignore_errors=True)


if __name__ == "__main__":
    main()
