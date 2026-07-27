"""Config: save/load roundtrip, env precedence, key masking."""

import json
import os

from patchtriage import config as cfg


def test_save_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path))
    path = cfg.save({"ANTHROPIC_API_KEY": "sk-ant-test", "default_backend": "cascade"})
    assert path.exists()
    loaded = cfg.load()
    assert loaded["ANTHROPIC_API_KEY"] == "sk-ant-test"
    assert loaded["default_backend"] == "cascade"


def test_apply_to_env_does_not_override_existing_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path))
    cfg.save({"ANTHROPIC_API_KEY": "from-config"})
    monkeypatch.setenv("ANTHROPIC_API_KEY", "from-env")
    cfg.apply_to_env()
    assert os.environ["ANTHROPIC_API_KEY"] == "from-env"


def test_apply_to_env_fills_missing_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    cfg.save({"ANTHROPIC_API_KEY": "from-config"})
    cfg.apply_to_env()
    assert os.environ["ANTHROPIC_API_KEY"] == "from-config"
    os.environ.pop("ANTHROPIC_API_KEY", None)


def test_apply_to_env_supports_provider_neutral_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path))
    for key in (
        "PATCHTRIAGE_AI_PROVIDER",
        "PATCHTRIAGE_AI_BASE_URL",
        "PATCHTRIAGE_AI_MODEL",
        "OPENAI_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)
    cfg.save({
        "PATCHTRIAGE_AI_PROVIDER": "openai-compatible",
        "PATCHTRIAGE_AI_BASE_URL": "https://inference.example/v1",
        "PATCHTRIAGE_AI_MODEL": "security-model",
        "OPENAI_API_KEY": "provider-key",
    })
    cfg.apply_to_env()
    assert os.environ["PATCHTRIAGE_AI_PROVIDER"] == "openai-compatible"
    assert os.environ["PATCHTRIAGE_AI_BASE_URL"] == (
        "https://inference.example/v1"
    )
    assert os.environ["PATCHTRIAGE_AI_MODEL"] == "security-model"
    assert os.environ["OPENAI_API_KEY"] == "provider-key"
    for key in (
        "PATCHTRIAGE_AI_PROVIDER",
        "PATCHTRIAGE_AI_BASE_URL",
        "PATCHTRIAGE_AI_MODEL",
        "OPENAI_API_KEY",
    ):
        os.environ.pop(key, None)


def test_load_survives_corrupt_file(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path))
    cfg.config_dir().mkdir(parents=True, exist_ok=True)
    cfg.config_path().write_text("{not json", encoding="utf-8")
    assert cfg.load() == {}


def test_mask_hides_middle():
    assert cfg.mask("sk-ant-api03-abcdefgh1234") == "sk-ant-...1234"
    assert cfg.mask("short") == "*****"
