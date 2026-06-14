from __future__ import annotations

import importlib
import importlib.util
import sys
import types
from pathlib import Path

import ida_idaapi


_PLUG_ENTRY = Path(__file__).resolve().parents[2] / "src" / "ida_forge_plugin.py"
_SPEC = importlib.util.spec_from_file_location("forge_plugin_entry", _PLUG_ENTRY)
assert _SPEC is not None and _SPEC.loader is not None
forge_entry = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(forge_entry)
plugmod_module = importlib.import_module("forge.forge_plugmod_t")
forge_core_module = importlib.import_module("forge.core")
forge_module = importlib.import_module("forge")


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


def _make_plugin(monkeypatch, *, core: _OldCore):
    plugin = plugmod_module.ForgePlugin.__new__(plugmod_module.ForgePlugin)
    plugin._core = core
    plugin._ready_hook = None
    plugin._state_log = []
    plugin._plugmod = None
    return plugin


def test_plugin_reload_rebuilds_core_and_shows_menu(monkeypatch):
    unload_calls = []
    reload_calls = []
    menu_calls = []
    queued = []

    plugin = _make_plugin(monkeypatch, core=_OldCore(unload_calls))

    monkeypatch.setattr(plugmod_module, "recursive_reload", lambda module, exclude_prefixes=(): reload_calls.append((module, exclude_prefixes)))
    monkeypatch.setattr(forge_core_module, "ForgeCore", _NewCore)
    monkeypatch.setattr(plugmod_module.ida_kernwin, "execute_ui_requests", lambda callbacks: queued.append(callbacks) or True)

    real_ready_hook = plugmod_module._ReadyHook

    def _fake_hook_init(self, owner):
        self._owner = owner

    monkeypatch.setattr(real_ready_hook, "__init__", _fake_hook_init)
    monkeypatch.setattr(real_ready_hook, "hook", lambda self: menu_calls.append("hook"))
    monkeypatch.setattr(real_ready_hook, "unhook", lambda self: menu_calls.append("unhook"))

    plugin.reload()

    assert len(queued) == 1
    queued[0][0]()

    assert unload_calls == [True]
    assert reload_calls == [(forge_module, ("forge.api.ui_actions",))]
    assert len(_NewCore.instances) == 1
    assert plugin.core is _NewCore.instances[0]
    assert plugin.core.loaded is True
    assert "hook" in menu_calls


def test_plugmod_teardown_unloads_core_and_unhooks(monkeypatch):
    import gc

    unload_calls = []
    menu_calls = []

    plugin = plugmod_module.ForgePlugin.__new__(plugmod_module.ForgePlugin)
    plugin._core = _OldCore(unload_calls)

    real_ready_hook = plugmod_module._ReadyHook

    def _fake_hook_init(self, owner):
        self._owner = owner

    monkeypatch.setattr(real_ready_hook, "__init__", _fake_hook_init)
    monkeypatch.setattr(real_ready_hook, "unhook", lambda self: menu_calls.append("unhook"))

    plugin._ready_hook = real_ready_hook(plugin)

    # Build the plugmod and drop it; __del__ must call _teardown().
    plugmod = plugmod_module.forge_plugmod_t(plugin)
    plugmod_ref = plugmod
    plugmod = None
    del plugmod_ref
    gc.collect()

    assert menu_calls == ["unhook"]
    # _OldCore.unload is called with the default keep_menu=False.
    assert unload_calls == [False]
    assert plugin._core is None
    assert plugin._ready_hook is None
