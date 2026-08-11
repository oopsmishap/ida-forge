from __future__ import annotations

import importlib
import sys
import types

from forge.api import ui_actions

MODULE_NAME = "forge.menu.reload"


def _load_reload_module(monkeypatch):
    registered_actions = []
    fake_manager = types.SimpleNamespace(register=lambda action: registered_actions.append(action))
    monkeypatch.setattr(ui_actions.UIActionManager, "get", lambda: fake_manager)
    sys.modules.pop(MODULE_NAME, None)
    module = importlib.import_module(MODULE_NAME)
    return module, registered_actions


def test_reload_action_registers_under_forge_menu(monkeypatch):
    module, registered_actions = _load_reload_module(monkeypatch)

    assert len(registered_actions) == 1
    action = registered_actions[0]

    assert isinstance(action, module.ReloadAction)
    assert action.name == "Reload Forge"
    assert action.tooltip == "Hot-reload Forge without restarting IDA"
    assert action.menu_path == "Forge/Actions"



def test_reload_action_calls_active_plugin_reload(monkeypatch):
    _module, registered_actions = _load_reload_module(monkeypatch)
    action = registered_actions[0]

    reload_calls = []
    plugmod = types.SimpleNamespace(reload=lambda: reload_calls.append("reloaded"))
    monkeypatch.setattr(sys.modules["__main__"], "forge", plugmod, raising=False)

    assert action.activate(None) == 0
    assert reload_calls == ["reloaded"]



def test_reload_action_warns_when_plugin_instance_is_missing(monkeypatch):
    module, registered_actions = _load_reload_module(monkeypatch)
    action = registered_actions[0]

    warnings = []
    monkeypatch.setattr(module, "log_warning", lambda message, *args, **kwargs: warnings.append(message))
    monkeypatch.delattr(sys.modules["__main__"], "forge", raising=False)

    assert action.activate(None) == 0
    assert warnings == ["Forge plugin instance is not available; cannot reload."]
