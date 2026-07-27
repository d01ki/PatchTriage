"""User configuration — created by `patchtriage setup`, loaded on startup.

Stored as JSON at ~/.config/patchtriage/config.json (0600 on POSIX; override
the directory with PATCHTRIAGE_CONFIG_DIR). Precedence: environment variables
always win over the config file, so CI pipelines and containers that inject
keys via env keep working unchanged.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# Values mirrored into the environment for provider/enrichment clients.
ENV_KEYS = (
    "PATCHTRIAGE_AI_PROVIDER",
    "PATCHTRIAGE_AI_API_KEY",
    "PATCHTRIAGE_AI_BASE_URL",
    "PATCHTRIAGE_AI_MODEL",
    "PATCHTRIAGE_AI_SCREEN_MODEL",
    "PATCHTRIAGE_AI_DEEP_MODEL",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "NVD_API_KEY",
    "GITHUB_TOKEN",
)

ANTHROPIC_MODELS_URL = "https://api.anthropic.com/v1/models"
OPENAI_MODELS_URL = "https://api.openai.com/v1/models"


def config_dir() -> Path:
    override = os.environ.get("PATCHTRIAGE_CONFIG_DIR")
    if override:
        return Path(override)
    return Path.home() / ".config" / "patchtriage"


def config_path() -> Path:
    return config_dir() / "config.json"


def load() -> dict:
    p = config_path()
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save(cfg: dict) -> Path:
    d = config_dir()
    d.mkdir(parents=True, exist_ok=True)
    p = config_path()
    p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    try:
        p.chmod(0o600)  # keys inside — keep it private (no-op on Windows)
    except OSError:
        pass
    return p


def apply_to_env(cfg: dict | None = None) -> None:
    """Export saved keys into the process env unless already set there."""
    cfg = load() if cfg is None else cfg
    for key in ENV_KEYS:
        value = cfg.get(key)
        if value and not os.environ.get(key):
            os.environ[key] = value


def validate_anthropic_key(key: str) -> tuple[bool, str]:
    """Check a key against the API without spending tokens (GET /v1/models)."""
    import httpx

    try:
        r = httpx.get(ANTHROPIC_MODELS_URL, timeout=15,
                      headers={"x-api-key": key,
                               "anthropic-version": "2023-06-01"})
    except httpx.HTTPError as exc:
        return False, f"network error: {exc}"
    if r.status_code == 200:
        return True, "key is valid"
    if r.status_code == 401:
        return False, "authentication failed (401) - check the key"
    return False, f"unexpected response: HTTP {r.status_code}"


def validate_openai_key(key: str) -> tuple[bool, str]:
    """Check an OpenAI key against the models endpoint without inference."""
    import httpx

    try:
        r = httpx.get(
            OPENAI_MODELS_URL,
            timeout=15,
            headers={"Authorization": f"Bearer {key}"},
        )
    except httpx.HTTPError as exc:
        return False, f"network error: {exc}"
    if r.status_code == 200:
        return True, "key is valid"
    if r.status_code == 401:
        return False, "authentication failed (401) - check the key"
    return False, f"unexpected response: HTTP {r.status_code}"


def mask(secret: str) -> str:
    if len(secret) <= 10:
        return "*" * len(secret)
    return f"{secret[:7]}...{secret[-4:]}"
