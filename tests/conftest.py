"""
Make the application modules importable as top-level packages
(database, managers, security, ui), the same way main.py imports them.
"""

import os
import sys

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
