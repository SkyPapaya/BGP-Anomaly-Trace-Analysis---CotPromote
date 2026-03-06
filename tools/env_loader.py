"""
Simple .env loader (no external dependency).

Load order:
1) <project_root>/.env
2) <project_root>/.env.local

Existing process environment variables keep highest priority.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]


def _parse_env_line(line: str):
    s = line.strip()
    if not s or s.startswith("#") or "=" not in s:
        return None, None
    key, value = s.split("=", 1)
    key = key.strip()
    value = value.strip()
    if not key:
        return None, None
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        value = value[1:-1]
    return key, value


@lru_cache(maxsize=1)
def ensure_env_loaded() -> None:
    for path in (ROOT_DIR / ".env", ROOT_DIR / ".env.local"):
        if not path.exists() or not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            key, value = _parse_env_line(line)
            if key is None:
                continue
            if key in os.environ:
                continue
            os.environ[key] = value


def get_env(name: str, default: str = "") -> str:
    ensure_env_loaded()
    return os.getenv(name, default)


def get_first_env(*names: str, default: str = "") -> str:
    ensure_env_loaded()
    for name in names:
        value = os.getenv(name, "")
        if value:
            return value
    return default
