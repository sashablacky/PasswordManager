"""
The browser bridge inside the running program: starts with it, ends sessions
on lock, can be switched off in Settings, and connected browsers can be removed.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import app_settings
from test_browser_bridge import Client, RecordingUI, add_entry
from test_ui_smoke import app, create_account, messages, log_in  # noqa: F401 (fixtures)


def test_bridge_starts_with_the_program(app):  # noqa: F811
    assert app.bridge is not None and app.bridge.is_listening()
    reply = app.bridge.service.handle({"type": "hello", "client_id": None})
    assert reply["state"] == "locked"


def paired(app, monkeypatch):  # noqa: F811
    service = app.bridge.service
    ui = RecordingUI()
    monkeypatch.setattr(service, "ui", ui)
    client = Client(service.handle)
    client.pair_start()
    ui.questions[-1][2](True)
    assert client.pair_poll() == "approved"
    assert client.hello() == "ready"
    return client


def test_lock_ends_browser_sessions(app, monkeypatch):  # noqa: F811
    create_account(app, monkeypatch)
    client = paired(app, monkeypatch)

    app.main_window.lock_vault()
    assert client.call("ping") == {"type": "error", "code": "session_expired"}
    assert client.hello() == "locked"

    log_in(app)
    assert client.hello() == "ready"


def test_saved_login_shows_up_in_the_list(app, monkeypatch):  # noqa: F811
    create_account(app, monkeypatch)
    client = paired(app, monkeypatch)
    from integration.server import AppBridgeUI
    monkeypatch.setattr(app.bridge.service, "ui", AppBridgeUI(app))

    client.call("save_login", url="https://example.com/login", username="alice", password="Pw-123456")
    assert app.main_window.entry_list.count() == 1


def test_switch_off_in_settings(app, monkeypatch):  # noqa: F811
    create_account(app, monkeypatch)
    page = app.main_window.settings_page
    assert page.browser_switch.isChecked()

    page.browser_switch.setChecked(False)
    assert app.bridge is None
    assert app_settings.load_settings()["browser_integration"] is False

    page.browser_switch.setChecked(True)
    assert app.bridge is not None and app.bridge.is_listening()


def test_disconnect_all_browsers(app, monkeypatch, messages):  # noqa: F811
    create_account(app, monkeypatch)
    client = paired(app, monkeypatch)
    window = app.main_window
    assert len(window.paired_browsers()) == 1

    window.forget_browsers()
    assert window.paired_browsers() == []
    assert client.hello() == "unpaired"
    assert not window.settings_page.browsers_card.button.isEnabled()
