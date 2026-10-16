"""
Small user preferences that are not secret (colour theme, browser extension on/off).

They live in a JSON file in the per-user data folder, next to the vault but
not inside it, so the theme can be applied before the vault is unlocked.
"""

import json
import logging
import os

from app_paths import get_data_dir

logger = logging.getLogger(__name__)

SETTINGS_FILE_NAME = "settings.json"

# Set this environment variable to use a different settings file (e.g. for testing)
SETTINGS_PATH_ENV = "PASSWORD_MANAGER_SETTINGS"

DEFAULTS = {
    "theme": "dusk",
    # Accept connections from the browser extension (integration/)
    "browser_integration": True,
}


def get_settings_path() -> str:
    override = os.environ.get(SETTINGS_PATH_ENV)
    if override:
        return os.path.abspath(override)
    return os.path.join(get_data_dir(), SETTINGS_FILE_NAME)


def load_settings() -> dict:
    """Saved settings merged over the defaults; a missing or broken file gives the defaults"""
    settings = dict(DEFAULTS)
    path = get_settings_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            settings.update({k: v for k, v in data.items() if k in DEFAULTS})
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as e:
        logger.warning(f"Could not read settings from {path}: {e}")
    return settings


def save_settings(**changes) -> None:
    """Update the given settings and write the file (atomically, so a crash cannot corrupt it)"""
    settings = load_settings()
    settings.update(changes)
    path = get_settings_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
    os.replace(tmp_path, path)
