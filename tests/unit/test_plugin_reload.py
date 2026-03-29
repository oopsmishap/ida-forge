from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path

import idaapi


if not hasattr(idaapi, "plugin_t"):
    idaapi.plugin_t = type("plugin_t", (), {})

_PLUGIN_ENTRY = Path(__file__).resolve().parents[2] / "src" / "forge.py"
_SPEC = importlib.util.spec_from_file_location("forge_plugin_entry", _PLUGIN_ENTRY)
assert _SPEC is not None and _SPEC.loader is not None
forge_module = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(forge_module)
forge_core_module = importlib.import_module("forge.core")




class _OldCore:
    def __init__(self, calls):
        self._calls = calls

    def unload(self, keep_menu=False):
        self._calls.append(keep_menu)


class _NewCore:
    instances = []

    def __init__(self):
        self.loaded = False
        _NewCore.instances.append(self)

    def load(self):
        self.loaded = True


def test_plugin_reload_rebuilds_core_and_shows_menu(monkeypatch):
    unload_calls = []
    reload_calls = []
    menu_calls = []
    timer_clears = []

    plugin = forge_module.ForgePlugin()
    plugin._core = _OldCore(unload_calls)

    monkeypatch.setattr(forge_module, "recursive_reload", lambda module, exclude_prefixes=(): reload_calls.append((module, exclude_prefixes)))
    monkeypatch.setattr(forge_core_module, "ForgeCore", _NewCore)
    monkeypatch.setattr(forge_module.ForgePlugin, "_show_menu_async", lambda self: menu_calls.append(self))
    monkeypatch.setattr(forge_module.ForgePlugin, "_clear_menu_timer", lambda self: timer_clears.append(self))

    plugin.reload()

    assert timer_clears == [plugin]
    assert unload_calls == [True]
    assert reload_calls == [(forge_module.forge, ("forge.api.ui_actions",))]
    assert len(_NewCore.instances) == 1
    assert plugin.core is _NewCore.instances[0]
    assert plugin.core.loaded is True
    assert menu_calls == [plugin]


