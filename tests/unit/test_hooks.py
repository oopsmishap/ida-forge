from __future__ import annotations

import pytest

from forge.api import hooks


class DummyHook(hooks.HexRaysHook):
    name = "dummy"

    def __init__(self):
        super().__init__()
        self.hook_calls = 0
        self.unhook_calls = 0

    def hook(self):
        self.hook_calls += 1
        return True

    def unhook(self):
        self.unhook_calls += 1
        return True


@pytest.fixture
def manager():
    hooks.HexRaysHookManager._instance = None
    manager = hooks.HexRaysHookManager.get()
    yield manager
    hooks.HexRaysHookManager._instance = None


def test_register_requires_named_hook(manager):
    unnamed = hooks.HexRaysHook()

    with pytest.raises(ValueError, match="must define a name"):
        manager.register(unnamed)



def test_initialize_finalize_enable_disable(manager):
    hook = DummyHook()
    manager.register(hook)

    manager.initialize()
    manager.disable("dummy")
    manager.enable("dummy")
    manager.finalize()

    assert hook.hook_calls == 2
    assert hook.unhook_calls == 2



def test_enable_disable_unknown_hook_raises(manager):
    with pytest.raises(KeyError):
        manager.enable("missing")
    with pytest.raises(KeyError):
        manager.disable("missing")



def test_register_hook_decorator_registers_instance(monkeypatch):
    hooks.HexRaysHookManager._instance = None
    manager = hooks.HexRaysHookManager.get()
    registered = []
    monkeypatch.setattr(manager, "register", lambda hook: registered.append(hook))

    @hooks.register_hook
    class DecoratedHook(hooks.HexRaysHook):
        name = "decorated"

    assert DecoratedHook.__name__ == "DecoratedHook"
    assert len(registered) == 1
    assert registered[0].name == "decorated"
