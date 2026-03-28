from __future__ import annotations

from pathlib import Path

import pytest
import toml

from forge.api.config import ForgeConfig


class ExampleConfig(ForgeConfig):
    name = "Example"
    default_config = {
        "enabled": True,
        "path": "default.bin",
    }


def test_config_creates_default_section_and_persists_it(tmp_path, monkeypatch):
    monkeypatch.setattr("ida_diskio.get_user_idadir", lambda: str(tmp_path))

    config = ExampleConfig()

    assert config["enabled"] is True
    assert config["path"] == "default.bin"

    config_path = Path(tmp_path) / "cfg" / "forge.toml"
    assert config_path.exists()

    data = toml.loads(config_path.read_text(encoding="utf-8"))
    assert data["Example"]["enabled"] is True
    assert data["Example"]["path"] == "default.bin"


def test_config_updates_and_reloads_from_disk(tmp_path, monkeypatch):
    monkeypatch.setattr("ida_diskio.get_user_idadir", lambda: str(tmp_path))

    config = ExampleConfig()
    config["enabled"] = False
    config["path"] = "updated.bin"

    reloaded = ExampleConfig()

    assert reloaded["enabled"] is False
    assert reloaded["path"] == "updated.bin"


def test_config_contains_checks_declared_options_only(tmp_path, monkeypatch):
    monkeypatch.setattr("ida_diskio.get_user_idadir", lambda: str(tmp_path))

    config = ExampleConfig()

    assert "enabled" in config
    assert "missing" not in config


def test_config_recovers_from_malformed_toml(tmp_path, monkeypatch):
    monkeypatch.setattr("ida_diskio.get_user_idadir", lambda: str(tmp_path))
    config_path = Path(tmp_path) / "cfg" / "forge.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("[Example\nenabled = true\n", encoding="utf-8")

    config = ExampleConfig()

    assert config["enabled"] is True
    repaired = toml.loads(config_path.read_text(encoding="utf-8"))
    assert repaired["Example"]["enabled"] is True



def test_get_missing_option_raises_value_error(tmp_path, monkeypatch):
    monkeypatch.setattr("ida_diskio.get_user_idadir", lambda: str(tmp_path))

    config = ExampleConfig()

    with pytest.raises(ValueError, match="Option missing not found"):
        config.get_option(ExampleConfig, "missing")



def test_save_failure_propagates(tmp_path, monkeypatch):
    monkeypatch.setattr("ida_diskio.get_user_idadir", lambda: str(tmp_path))
    config = ExampleConfig()
    original_open = Path.open

    def fail_open(path_obj, *args, **kwargs):
        if path_obj == config._config_path:
            raise OSError("disk full")
        return original_open(path_obj, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_open)

    with pytest.raises(OSError, match="disk full"):
        config["enabled"] = False
