from __future__ import annotations

import importlib
import sys
import types

import pytest

from forge.feature_manager import FeatureManager


def test_iter_feature_module_names_is_sorted_and_skips_pycache(tmp_path):
    (tmp_path / "zeta").mkdir()
    (tmp_path / "alpha").mkdir()
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "not_a_feature.py").write_text("x = 1", encoding="utf-8")

    manager = FeatureManager(root=tmp_path)

    assert list(manager.iter_feature_module_names()) == [
        "forge.features.alpha",
        "forge.features.zeta",
    ]


def test_load_reload_and_unload_feature(monkeypatch):
    manager = FeatureManager()
    feature_name = "forge.features.fake_feature"
    first_module = types.ModuleType(feature_name)
    second_module = types.ModuleType(feature_name)

    def fake_import_module(name: str):
        assert name == feature_name
        sys.modules[name] = first_module
        return first_module

    def fake_reload(module):
        assert module is first_module
        sys.modules[module.__name__] = second_module
        return second_module

    monkeypatch.setattr(importlib, "import_module", fake_import_module)
    monkeypatch.setattr(importlib, "reload", fake_reload)

    manager.load_feature(feature_name)
    assert manager.get_feature(feature_name) is first_module

    with pytest.raises(ValueError, match="already loaded"):
        manager.load_feature(feature_name)

    manager.reload_feature(feature_name)
    assert manager.get_feature(feature_name) is second_module

    manager.unload_feature(feature_name)
    assert feature_name not in sys.modules

    with pytest.raises(ValueError, match="not loaded"):
        manager.get_feature(feature_name)


def test_unload_missing_feature_raises():
    manager = FeatureManager()

    with pytest.raises(ValueError, match="not loaded"):
        manager.unload_feature("forge.features.missing")



def test_load_feature_propagates_import_errors(monkeypatch):
    manager = FeatureManager()

    def fail_import(name: str):
        raise ImportError(f"cannot import {name}")

    monkeypatch.setattr(importlib, "import_module", fail_import)

    with pytest.raises(ImportError, match="cannot import forge.features.broken"):
        manager.load_feature("forge.features.broken")
