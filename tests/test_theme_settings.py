"""
The colour theme chosen in Settings is saved to a small JSON file in the app
data folder (not in the vault) and applied again on the next start.
"""

import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt5.QtWidgets import QMessageBox

import app_settings
from ui import theme

MASTER = "FirstPass11!"


@pytest.fixture
def quiet_messages(monkeypatch):
    for name in ("information", "critical", "warning", "question"):
        monkeypatch.setattr(QMessageBox, name, lambda *a, **k: QMessageBox.Yes)


@pytest.fixture(autouse=True)
def restore_default_theme(qapp):
    yield
    theme.apply_theme(theme.DEFAULT_THEME)


def test_defaults_without_a_settings_file(isolated_settings):
    assert not isolated_settings.exists()
    assert app_settings.load_settings()["theme"] == "dusk"


def test_theme_is_saved_and_loaded(isolated_settings):
    app_settings.save_settings(theme="slate")

    assert json.loads(isolated_settings.read_text(encoding="utf-8"))["theme"] == "slate"
    assert app_settings.load_settings()["theme"] == "slate"


def test_settings_file_lives_in_the_app_data_folder(monkeypatch, tmp_path):
    monkeypatch.delenv(app_settings.SETTINGS_PATH_ENV, raising=False)
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr(os.path, "expanduser", lambda p: str(tmp_path) if p == "~" else p)

    path = app_settings.get_settings_path()
    assert os.path.dirname(path) == app_settings.get_data_dir()
    assert path.startswith(str(tmp_path))


def test_broken_or_unknown_settings_fall_back_to_default(isolated_settings):
    isolated_settings.write_text("{not json", encoding="utf-8")
    assert app_settings.load_settings()["theme"] == "dusk"

    isolated_settings.write_text(json.dumps({"theme": "neon"}), encoding="utf-8")
    assert theme.init_theme().key == "dusk"


def test_switching_theme_in_settings_applies_live_and_survives_restart(
        qtbot, tmp_path, monkeypatch, quiet_messages, isolated_settings):
    monkeypatch.setenv("PASSWORD_VAULT_DB", str(tmp_path / "vault.db"))
    from main import PasswordManagerApp

    pm_app = PasswordManagerApp()
    assert theme.current_key() == "dusk"
    pm_app.auth_manager.create_account(MASTER)
    pm_app.auth_manager.authenticate(MASTER)
    pm_app.show_main_window()
    window = pm_app.main_window

    changed = []
    theme.signals.changed.connect(changed.append)
    window.settings_page.theme_card.swatches["midnight"].click()

    # Applied right away: Fluent accent colour, palette and the Settings page selection
    from qfluentwidgets import qconfig
    assert theme.current_key() == "midnight"
    assert changed == ["midnight"]
    assert qconfig.get(qconfig.themeColor).name().lower() == theme.THEMES["midnight"].accent.lower()
    assert window.settings_page.theme_card.swatches["midnight"].isChecked()
    assert app_settings.load_settings()["theme"] == "midnight"

    window.close_without_prompt()
    pm_app.main_window = None
    pm_app.shutdown()
    theme.signals.changed.disconnect(changed.append)

    # Next start: the saved theme is applied before the login window appears
    theme.apply_theme("dusk")
    pm_app = PasswordManagerApp()
    try:
        assert theme.current_key() == "midnight"
    finally:
        pm_app.shutdown()
