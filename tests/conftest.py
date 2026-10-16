"""
Make the application modules importable as top-level packages
(database, managers, security, ui), the same way main.py imports them.
"""

import os
import sys
import tempfile
import uuid

import pytest

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src'))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    """Tests never read or write the user's real settings file (theme choice)"""
    path = tmp_path / "settings.json"
    monkeypatch.setenv("PASSWORD_MANAGER_SETTINGS", str(path))
    return path


@pytest.fixture(autouse=True)
def isolated_bridge_endpoint(monkeypatch):
    """The browser bridge of a test app never listens where the real program does"""
    name = f"svb-test-{uuid.uuid4().hex[:10]}"
    if sys.platform != "win32":
        # Unix socket paths are limited to about 100 characters, so not in tmp_path
        name = os.path.join(tempfile.gettempdir(), name + ".sock")
    monkeypatch.setenv("SECUREVAULT_BRIDGE_ENDPOINT", name)
    yield name
    if sys.platform != "win32" and os.path.exists(name):
        os.remove(name)
