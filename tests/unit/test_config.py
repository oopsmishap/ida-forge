from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest
import toml

from forge.api.config import ForgeConfig


class ExampleConfig(ForgeConfig):
    name = "Example"
    default_config: ClassVar[dict] = {
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


def test_config_forward_fills_missing_nested_form_keys(tmp_path, monkeypatch):
    """A persisted file missing a newly added *nested* key must pick it up
    on read and persist the merge.

    Regression: the structure builder crashed with
    ``KeyError: 'collision_foreground_color'`` when a legacy forge.toml
    (or one written before the dark-theme rework) lacked the key, while the
    key was also missing from the class defaults.
    """
    from forge.features.structure_builder.config import StructureBuilderConfig

    monkeypatch.setattr("ida_diskio.get_user_idadir", lambda: str(tmp_path))
    config_path = Path(tmp_path) / "cfg" / "forge.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        '[StructureBuilder]\n'
        'enabled = true\n'
        '[StructureBuilder.form]\n'
        'cell_background_color = "#2A2A2A"\n'
        'cell_foreground_color = "#E0E0E0"\n'
        'origin_color = "#006699"\n'
        'origin_foreground_color = "#FFFFFF"\n'
        'disabled_color = "#3D3D3D"\n'
        'disabled_foreground_color = "#D0D0D0"\n'
        'collision_background_color = "#CC4B4B"\n',
        encoding="utf-8",
    )

    config = StructureBuilderConfig()

    # The exact access that crashed in update_structure_fields.
    assert config["form"]["collision_foreground_color"] == "#F0DB2B"

    # The merge must have been written back to disk.
    data = toml.loads(config_path.read_text(encoding="utf-8"))
    assert data["StructureBuilder"]["form"]["collision_foreground_color"] == "#F0DB2B"


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
        default_config: ClassVar[dict] = {
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

def test_config_uses_domain_metadata_user_directory(monkeypatch, tmp_path):
    from forge.api import config as config_module

    domain_dir = tmp_path / "domain-user"
    monkeypatch.setattr(
        config_module,
        "current_database",
        lambda required=False: type(
            "Database", (), {"metadata": type("Metadata", (), {"user_idadir": str(domain_dir)})()}
        )(),
    )
    monkeypatch.setattr("ida_diskio.get_user_idadir", lambda: str(tmp_path / "sdk-user"))
    config = ExampleConfig()
    assert config._config_path == domain_dir / "cfg" / "forge.toml"