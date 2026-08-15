from __future__ import annotations

from importlib import import_module
from types import SimpleNamespace
from typing import ClassVar

import pytest

from forge.api.structure import Structure

hexrays_api = import_module("forge.api.hexrays")
scanner_api = import_module("forge.api.scanner")
hexrays_api.decompile = lambda *_args, **_kwargs: None
hexrays_api.get_funcs_referencing_address = lambda *_args, **_kwargs: []
hexrays_api.is_legal_type = lambda *_args, **_kwargs: True
scanner_api.NewShallowScanVisitor = type("NewShallowScanVisitor", (), {})

actions_module = import_module("forge.features.structure_builder.actions")


class _FakeVisitor:
    calls: ClassVar[list] = []

    def __init__(self, *args, **kwargs):
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
    monkeypatch.setattr(actions_module.DeepScanAction, "_prompt_scan_depth", staticmethod(lambda: -1))

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
    monkeypatch.setattr(actions_module.DeepScanAction, "_prompt_scan_depth", staticmethod(lambda: -1))
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


# ---------------------------------------------------------------------------
# T3.5 G-gap tests (actions)
# ---------------------------------------------------------------------------


def test_ensure_structure_selected_no_selection_prompts_and_warns(monkeypatch):
    """G19: no current structure -> show + prompt; declined prompt warns and
    reports failure, accepted prompt succeeds."""
    form = actions_module.structure_form
    form.current_structure = None
    warnings = []
    monkeypatch.setattr(actions_module, "log_warning", lambda m, *a, **k: warnings.append(m), raising=False)

    created = []

    def prompt():
        structure = form.create_structure("Prompted")
        created.append(structure)
        return structure

    monkeypatch.setattr(form, "prompt_create_structure", prompt)
    assert actions_module.StructureBuilderAction._ensure_structure_selected() is True
    assert created and form.current_structure is created[0]

    form.current_structure = None
    monkeypatch.setattr(form, "prompt_create_structure", lambda: None)
    assert actions_module.StructureBuilderAction._ensure_structure_selected() is False
    assert any("No structure selected" in w for w in warnings)


def test_scan_global_references_empty_xref_set_warns(monkeypatch):
    """G16: a global with no referencing functions warns and does nothing."""
    calls = {"warned": [], "visited": []}

    class _Obj:
        object_ea = 0x140001000
        name = "g_obj"
        tinfo = None
        id = 1

    monkeypatch.setattr(actions_module, "get_funcs_referencing_address", lambda ea: [])
    monkeypatch.setattr(
        actions_module, "log_warning",
        lambda m, *a, **k: calls["warned"].append(m), raising=False,
    )
    monkeypatch.setattr(
        actions_module, "NewDeepScanVisitor",
        lambda *a, **k: calls["visited"].append(a) or SimpleNamespace(process=lambda: None),
        raising=False,
    )

    action = actions_module.DeepScanAction()
    action._scan_global_references(_Obj(), origin=0, max_depth=0)

    assert any("No function references" in w for w in calls["warned"])
    assert calls["visited"] == []


def test_prompt_scan_depth_parses_input(monkeypatch):
    """G17: None cancels; empty means unlimited; garbage falls back to the
    configured default; valid integers parse."""
    import ida_kernwin

    monkeypatch.setattr(ida_kernwin, "HIST_TYPE", 1, raising=False)
    action = actions_module.DeepScanAction()

    monkeypatch.setattr(ida_kernwin, "ask_str", lambda dflt, hist, title: None)
    assert action._prompt_scan_depth() is None

    monkeypatch.setattr(ida_kernwin, "ask_str", lambda dflt, hist, title: "   ")
    assert action._prompt_scan_depth() == 0

    monkeypatch.setattr(ida_kernwin, "ask_str", lambda dflt, hist, title: "not-a-number")
    from forge.features.structure_builder.config import StructureBuilderConfig

    default_depth = StructureBuilderConfig()["default_deep_scan_depth"]
    assert action._prompt_scan_depth() == default_depth  # falls back to the config

    monkeypatch.setattr(ida_kernwin, "ask_str", lambda dflt, hist, title: "7")
    assert action._prompt_scan_depth() == 7


def test_provenance_kind_for_object_mapping():
    """G18: provenance kinds follow the scan-object id."""
    class _Obj:
        def __init__(self, id_):
            self.id = id_

    from forge.api.scan_object import ObjectType

    assert actions_module.StructureBuilderAction._provenance_kind_for_object(_Obj(ObjectType.global_object)) == "global_root"
    assert actions_module.StructureBuilderAction._provenance_kind_for_object(_Obj(ObjectType.structure_pointer)) == "upward_resolved_root"
    assert actions_module.StructureBuilderAction._provenance_kind_for_object(_Obj(ObjectType.structure_reference)) == "upward_resolved_root"
    assert actions_module.StructureBuilderAction._provenance_kind_for_object(_Obj(ObjectType.local_variable)) == "confirmed_root"
