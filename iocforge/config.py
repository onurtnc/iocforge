"""API anahtarlarini ortam degiskeni, .env veya config dosyasindan okur."""
from __future__ import annotations

import json
import os
from typing import Dict

CONFIG_PATHS = (
    os.path.join(os.getcwd(), "iocforge.json"),
    os.path.join(os.path.expanduser("~"), ".iocforge", "config.json"),
)
ENV_PATHS = (os.path.join(os.getcwd(), ".env"),)

KEY_NAMES = ("VT_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY", "GREYNOISE_API_KEY")


def _load_env_file(path: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not os.path.isfile(path):
        return values
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip().strip("'\"")
    return values


def load_keys() -> Dict[str, str]:
    """Oncelik: ortam degiskeni > .env > config.json"""
    keys: Dict[str, str] = {}
    for path in reversed(CONFIG_PATHS):
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    keys.update({k: str(v) for k, v in json.load(fh).items()})
            except (json.JSONDecodeError, OSError):
                pass
    for path in ENV_PATHS:
        keys.update(_load_env_file(path))
    for name in KEY_NAMES:
        if os.environ.get(name):
            keys[name] = os.environ[name]
    return {k: v for k, v in keys.items() if v}
