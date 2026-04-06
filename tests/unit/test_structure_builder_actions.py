from __future__ import annotations

from importlib import import_module
from types import SimpleNamespace

import pytest

from forge.api.structure import Structure

hexrays_api = import_module("forge.api.hexrays")
scanner_api = import_module("forge.api.scanner")
setattr(hexrays_api, "decompile", lambda *_args, **_kwargs: None)
setattr(hexrays_api, "get_funcs_referencing_address", lambda *_args, **_kwargs: [])
setattr(hexrays_api, "is_legal_type", lambda *_args, **_kwargs: True)
setattr(scanner_api, "NewShallowScanVisitor", type("NewShallowScanVisitor", (), {}))

actions_module = import_module("forge.features.structure_builder.actions")


class _FakeVisitor:
    calls = []

    def __init__(self, *args):
        self.args = args
        type(self).calls.append(args)

    def process(self):
        return None


@pytest.fixture(autouse=True)
def reset_structure_form(monkeypatch):
    actions_module.structure_form.structures = {}
    actions_module.structure_form.current_structure = None
    monkeypatch.setattr(actions_module.structure_form, "update_structure_fields", lambda: None)
    monkeypatch.setattr(actions_module.structure_form, "show", lambda: True)
    monkeypatch.setattr(actions_module.structure_form, "prompt_create_structure", lambda: None)
    _FakeVisitor.calls = []


def test_ensure_structure_selected_rehydrates_existing_form_ui(monkeypatch):
    structure = Structure("Selected")
    actions_module.structure_form.current_structure = structure
    ensure_calls = []
    show_calls = []

    monkeypatch.setattr(
        actions_module.structure_form,
        "ensure_ui",
        lambda: ensure_calls.append("ensure") or True,
    )
    monkeypatch.setattr(
        actions_module.structure_form,
        "show",
        lambda: show_calls.append("show") or True,
    )

    assert actions_module.StructureBuilderAction._ensure_structure_selected() is True
    assert ensure_calls == ["ensure"]
    assert show_calls == []


def test_shallow_scan_sets_confirmed_root_provenance(monkeypatch):
    structure = Structure("Selected")
    actions_module.structure_form.current_structure = structure
    monkeypatch.setattr(
        actions_module.ida_hexrays,
        "get_widget_vdui",
        lambda _widget: SimpleNamespace(cfunc=SimpleNamespace(entry_ea=0x401000), item=object()),
        raising=False,
    )
    monkeypatch.setattr(actions_module, "NewShallowScanVisitor", _FakeVisitor)

    action = actions_module.ShallowScanAction()
    action.create_scan_object = lambda *_args: SimpleNamespace(
        id=actions_module.ObjectType.local_variable,
        name="player",
        ea=0x5000,
        tinfo=object(),
    )
    action.activate(SimpleNamespace(widget="widget"))

    assert structure.provenance.kind == "confirmed_root"
    assert structure.provenance.root_object_name == "player"
    assert structure.provenance.root_object_ea == 0x5000
    assert structure.provenance.root_function_ea == 0x401000
    assert structure.provenance.has_multiple_roots is False
    assert len(_FakeVisitor.calls) == 1


def test_deep_scan_sets_upward_resolved_root_provenance(monkeypatch):
    structure = Structure("Selected")
    actions_module.structure_form.current_structure = structure
    refresh_calls = []
    cfunc = SimpleNamespace(entry_ea=0x401000)
    hx_view = SimpleNamespace(cfunc=cfunc, item=object(), refresh_view=lambda refresh: refresh_calls.append(refresh))
    monkeypatch.setattr(actions_module.ida_hexrays, "get_widget_vdui", lambda _widget: hx_view, raising=False)
    monkeypatch.setattr(actions_module, "NewDeepScanVisitor", _FakeVisitor)
    monkeypatch.setattr(
        actions_module.DeepScanAction,
        "_prepare_function",
        staticmethod(lambda current: current),
    )

    action = actions_module.DeepScanAction()
    action.create_scan_object = lambda *_args: SimpleNamespace(
        id=actions_module.ObjectType.structure_pointer,
        name="inventory_ptr",
        ea=0x6000,
        tinfo=object(),
    )
    action.activate(SimpleNamespace(widget="widget"))

    assert structure.provenance.kind == "upward_resolved_root"
    assert structure.provenance.root_object_name == "inventory_ptr"
    assert structure.provenance.root_object_ea == 0x6000
    assert structure.provenance.root_function_ea == 0x401000
    assert refresh_calls == [True]
    assert len(_FakeVisitor.calls) == 1


def test_deep_scan_global_path_sets_global_root_provenance(monkeypatch):
    structure = Structure("Selected")
    actions_module.structure_form.current_structure = structure
    monkeypatch.setattr(
        actions_module.ida_hexrays,
        "get_widget_vdui",
        lambda _widget: SimpleNamespace(cfunc=SimpleNamespace(entry_ea=0x401000), item=object(), refresh_view=lambda _refresh: None),
        raising=False,
    )
    monkeypatch.setattr(actions_module, "NewDeepScanVisitor", _FakeVisitor)
    monkeypatch.setattr(
        actions_module.DeepScanAction,
        "_prepare_function",
        staticmethod(lambda current: current),
    )
    monkeypatch.setattr(actions_module, "get_funcs_referencing_address", lambda _ea: {0x402000, 0x401000})
    monkeypatch.setattr(actions_module, "decompile", lambda ea: SimpleNamespace(entry_ea=ea))

    action = actions_module.DeepScanAction()
    global_obj = SimpleNamespace(
        id=actions_module.ObjectType.global_object,
        name="g_player",
        object_ea=0x7000,
        tinfo=object(),
    )
    action.create_scan_object = lambda *_args: global_obj
    action.activate(SimpleNamespace(widget="widget"))

    assert structure.provenance.kind == "global_root"
    assert structure.provenance.root_object_name == "g_player"
    assert structure.provenance.root_object_ea == 0x7000
    assert structure.provenance.root_function_ea is None
    assert structure.provenance.has_multiple_roots is True
    assert len(_FakeVisitor.calls) == 2
    assert all(call[2] is not global_obj for call in _FakeVisitor.calls)


def test_root_scan_does_not_overwrite_existing_non_manual_provenance(monkeypatch):
    structure = Structure("Selected")
    structure.set_provenance(kind="child_scan", root_object_name="Parent.child_ptr")
    actions_module.structure_form.current_structure = structure
    monkeypatch.setattr(
        actions_module.ida_hexrays,
        "get_widget_vdui",
        lambda _widget: SimpleNamespace(cfunc=SimpleNamespace(entry_ea=0x401000), item=object()),
        raising=False,
    )
    monkeypatch.setattr(actions_module, "NewShallowScanVisitor", _FakeVisitor)

    action = actions_module.ShallowScanAction()
    action.create_scan_object = lambda *_args: SimpleNamespace(
        id=actions_module.ObjectType.local_variable,
        name="player",
        ea=0x5000,
        tinfo=object(),
    )
    action.activate(SimpleNamespace(widget="widget"))

    assert structure.provenance.kind == "child_scan"
    assert structure.provenance.root_object_name == "Parent.child_ptr"
