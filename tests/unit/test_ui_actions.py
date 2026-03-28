from __future__ import annotations

import pytest

from forge.api import ui_actions


class DummyMenuAction(ui_actions.UIMenuAction):
    name = "Do Thing"
    tooltip = "tooltip"
    menu_path = "Extras"
    hotkey = "Ctrl+D"

    def activate(self, ctx):
        return 0


class DummyPlainAction(ui_actions.UIAction):
    description = "plain"
    hotkey = "P"

    def activate(self, ctx):
        return 0

    def check(self, hx_view):
        return True

    def update(self, ctx):
        return 0


class DummyPopupAction(ui_actions.HexRaysPopupAction):
    description = "popup"
    hotkey = "H"

    def __init__(self, should_attach=True):
        super().__init__()
        self.should_attach = should_attach

    def activate(self, ctx):
        return 0

    def check(self, hx_view):
        return self.should_attach


@pytest.fixture
def manager():
    ui_actions.UIActionManager._instance = None
    manager = ui_actions.UIActionManager.get()
    yield manager
    ui_actions.UIActionManager._instance = None


def test_register_sorts_action_types_into_correct_buckets(manager):
    menu = DummyMenuAction()
    plain = DummyPlainAction()
    popup = DummyPopupAction()

    manager.register(menu)
    manager.register(plain)
    manager.register(popup)

    assert manager._menu_actions == [menu]
    assert plain in manager._actions
    assert popup in manager._actions
    assert len(manager._popup_actions) == 1



def test_register_rejects_unsupported_action_type(manager):
    with pytest.raises(TypeError, match="Unsupported action type"):
        manager.register(object())



def test_initialize_and_finalize_register_and_unregister_actions(manager, monkeypatch):
    menu = DummyMenuAction()
    plain = DummyPlainAction()
    popup = DummyPopupAction()
    manager.register(menu)
    manager.register(plain)
    manager.register(popup)

    registered = []
    unregistered = []
    monkeypatch.setattr(ui_actions.ida_kernwin, "register_action", lambda desc: registered.append(desc) or True)
    monkeypatch.setattr(ui_actions.ida_kernwin, "unregister_action", lambda name: unregistered.append(name) or True)

    manager.initialize()
    manager.finalize()

    assert len(registered) == 3
    assert plain.name in unregistered
    assert popup.name in unregistered
    assert menu.id in unregistered



def test_show_menu_creates_menu_and_attaches_actions_only_once(manager, monkeypatch):
    menu = DummyMenuAction()
    manager.register(menu)
    created = []
    attached = []
    monkeypatch.setattr(ui_actions.ida_kernwin, "create_menu", lambda name, title: created.append((name, title)) or True)
    monkeypatch.setattr(ui_actions.ida_kernwin, "attach_action_to_menu", lambda path, action_id, flags: attached.append((path, action_id, flags)) or True)

    assert manager.show_menu() is True
    assert manager.show_menu() is True

    assert len(created) == 1
    assert attached == [(menu.menu_path, menu.id, 0)]



def test_show_menu_returns_false_when_menu_creation_fails(manager, monkeypatch):
    monkeypatch.setattr(ui_actions.ida_kernwin, "create_menu", lambda *_args: False)

    assert manager.show_menu() is False



def test_show_menu_returns_false_when_menu_creation_raises(manager, monkeypatch):
    monkeypatch.setattr(ui_actions.ida_kernwin, "create_menu", lambda *_args: (_ for _ in ()).throw(RuntimeError("boom")))

    assert manager.show_menu() is False



def test_attach_menu_action_handles_attach_failure(manager, monkeypatch):
    menu = DummyMenuAction()
    manager.register(menu)
    monkeypatch.setattr(ui_actions.ida_kernwin, "create_menu", lambda *_args: True)
    monkeypatch.setattr(ui_actions.ida_kernwin, "attach_action_to_menu", lambda *_args: False)

    assert manager.show_menu() is True
    assert manager._attached_menu_actions == set()



def test_register_action_decorator_instantiates_and_registers(monkeypatch):
    ui_actions.UIActionManager._instance = None
    manager = ui_actions.UIActionManager.get()
    registered = []
    monkeypatch.setattr(manager, "register", lambda action: registered.append(action))

    @ui_actions.register_action
    class DecoratedAction(ui_actions.UIMenuAction):
        name = "Decorated Action"

        def activate(self, ctx):
            return 0

    assert DecoratedAction.__name__ == "DecoratedAction"
    assert len(registered) == 1
    assert isinstance(registered[0], ui_actions.UIMenuAction)



def test_menu_action_id_is_sanitized():
    action = DummyMenuAction()
    assert action.id.endswith("Do_Thing")
    assert action.menu_path == "Forge/Extras"



def test_popup_request_handler_only_attaches_when_action_matches(monkeypatch):
    calls = []
    monkeypatch.setattr(ui_actions.ida_kernwin, "attach_action_to_popup", lambda *args: calls.append(args) or True)

    handler = ui_actions.HexraysPopupRequestHandler(DummyPopupAction(True))
    handler.populating_popup("widget", "popup", object())
    assert len(calls) == 1

    handler = ui_actions.HexraysPopupRequestHandler(DummyPopupAction(False))
    handler.populating_popup("widget", "popup", object())
    assert len(calls) == 1



def test_xref_and_popup_update_respect_widget_type():
    xref_action = ui_actions.HexRaysXrefAction()
    popup_action = DummyPopupAction()
    pseudocode_ctx = type("Ctx", (), {"widget_type": ui_actions.ida_kernwin.BWN_PSEUDOCODE})()
    struct_ctx = type("Ctx", (), {"widget_type": ui_actions.ida_kernwin.BWN_STRUCTS})()
    other_ctx = type("Ctx", (), {"widget_type": 999})()

    assert xref_action.update(pseudocode_ctx) == ui_actions.ida_kernwin.AST_ENABLE_FOR_WIDGET
    assert xref_action.update(struct_ctx) == ui_actions.ida_kernwin.AST_ENABLE_FOR_WIDGET
    assert xref_action.update(other_ctx) == ui_actions.ida_kernwin.AST_DISABLE_FOR_WIDGET
    assert popup_action.update(pseudocode_ctx) == ui_actions.ida_kernwin.AST_ENABLE_FOR_WIDGET
    assert popup_action.update(other_ctx) == ui_actions.ida_kernwin.AST_DISABLE_FOR_WIDGET
