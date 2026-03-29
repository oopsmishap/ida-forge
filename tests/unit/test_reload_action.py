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
    module, registered_actions = _load_reload_module(monkeypatch)
    action = registered_actions[0]

    reload_calls = []
    queued = []
    plugin = types.SimpleNamespace(reload=lambda: reload_calls.append("reloaded"))
    monkeypatch.setattr(sys.modules["__main__"], "forge", plugin, raising=False)
    monkeypatch.setattr(module.ida_kernwin, "execute_ui_requests", lambda callbacks: queued.append(callbacks) or True)

    assert action.activate(None) == 0
    assert reload_calls == []
    assert len(queued) == 1
    assert queued[0][0]() == 0
    assert reload_calls == ["reloaded"]



def test_reload_action_warns_when_plugin_instance_is_missing(monkeypatch):
    module, registered_actions = _load_reload_module(monkeypatch)
    action = registered_actions[0]

    warnings = []
    queued = []
    monkeypatch.setattr(module, "log_warning", lambda message: warnings.append(message))
    monkeypatch.setattr(module.ida_kernwin, "execute_ui_requests", lambda callbacks: queued.append(callbacks) or True)
    monkeypatch.delattr(sys.modules["__main__"], "forge", raising=False)

    assert action.activate(None) == 0
    assert warnings == ["Forge plugin instance is not available; cannot reload."]
    assert queued == []


