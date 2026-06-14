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



def test_config_backfills_new_default_keys_from_legacy_file(tmp_path, monkeypatch):
    """A class adding new keys to ``default_config`` must not break
    users who already have a saved file with the old schema."""
    monkeypatch.setattr("ida_diskio.get_user_idadir", lambda: str(tmp_path))

    class _LegacyConfig(ForgeConfig):
        name = "LegacyExample"
        default_config = {
            "existing": 1,
            "nested": {"old": True},
        }

    # Persist a file as if from an older version of the schema.
    config_path = Path(tmp_path) / "cfg" / "forge.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        '[LegacyExample]\nexisting = 7\n'
        + '[LegacyExample.nested]\nold = false\n',
        encoding="utf-8",
    )

    # Simulate an upgrade: extend the class default with new keys.
    _LegacyConfig.default_config = {
        "existing": 1,
        "added_top_level": "fresh",
        "nested": {"old": True, "added_nested": ["x", "y"]},
    }

    config = _LegacyConfig()

    # User-customized values are preserved.
    assert config["existing"] == 7
    assert config.get_class_config(_LegacyConfig)["nested"]["old"] is False
    # New keys from the upgraded defaults are filled in.
    assert config["added_top_level"] == "fresh"
    assert config.get_class_config(_LegacyConfig)["nested"]["added_nested"] == [
        "x",
        "y"
    ]

    # The fill-in is persisted, so the next read sees the merged file.
    reloaded = _LegacyConfig()
    assert reloaded["added_top_level"] == "fresh"