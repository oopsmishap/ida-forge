from __future__ import annotations

import sys
import types

from forge.util import reload as reload_util


def test_recursive_reload_processes_modules_in_sorted_order(monkeypatch):
    loaded = []

    monkeypatch.setattr(reload_util, "reload_module", lambda module: loaded.append(module.__name__))

    root = types.ModuleType("samplepkg")
    first = types.ModuleType("samplepkg.alpha")
    second = types.ModuleType("samplepkg.beta")

    monkeypatch.setitem(sys.modules, "samplepkg", root)
    monkeypatch.setitem(sys.modules, "samplepkg.beta", second)
    monkeypatch.setitem(sys.modules, "samplepkg.alpha", first)

    reload_util.recursive_reload(root)

    assert loaded == ["samplepkg", "samplepkg.alpha", "samplepkg.beta"]


def test_recursive_reload_skips_excluded_prefixes(monkeypatch):
    loaded = []
    monkeypatch.setattr(reload_util, "reload_module", lambda module: loaded.append(module.__name__))

    root = types.ModuleType("samplepkg")
    first = types.ModuleType("samplepkg.alpha")
    second = types.ModuleType("samplepkg.beta")

    monkeypatch.setitem(sys.modules, "samplepkg", root)
    monkeypatch.setitem(sys.modules, "samplepkg.beta", second)
    monkeypatch.setitem(sys.modules, "samplepkg.alpha", first)

    reload_util.recursive_reload(root, exclude_prefixes=("samplepkg.beta",))

    assert loaded == ["samplepkg", "samplepkg.alpha"]
