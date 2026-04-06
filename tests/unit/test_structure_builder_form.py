from __future__ import annotations

import csv
import io
from importlib import import_module
from types import SimpleNamespace

from forge.api.structure import Structure

hexrays_api = import_module("forge.api.hexrays")
scanner_api = import_module("forge.api.scanner")
setattr(hexrays_api, "get_funcs_referencing_address", lambda *_args, **_kwargs: [])
setattr(hexrays_api, "is_legal_type", lambda *_args, **_kwargs: True)
setattr(scanner_api, "NewShallowScanVisitor", type("NewShallowScanVisitor", (), {}))

form_module = import_module("forge.features.structure_builder.form")
child_scan_module = import_module("forge.features.structure_builder.child_scan")
structure_module = import_module("forge.api.structure")


class _FakeLineEdit:
    def __init__(self, value: str = ""):
        self._value = value

    def text(self) -> str:
        return self._value


class _FakeFilter:
    def __init__(self):
        self.cleared = False

    def clear(self) -> None:
        self.cleared = True

class _Recorder:
    def __init__(self):
        self.enabled = None
        self.text = None

    def setEnabled(self, value):
        self.enabled = value

    def setText(self, value):
        self.text = value

    def selectedIndexes(self):
        return []

    def currentRow(self):
        return -1

    def currentColumn(self):
        return -1


class _FakeMember:
    def __init__(
        self,
        offset: int,
        size: int,
        *,
        type_name: str = "u8",
        name: str = "field_0",
        comment: str = "",
        score: int = 0,
        origin: int = 0,
    ):
        self.offset = offset
        self.size = size
        self.type_name = type_name
        self.name = name
        self.comment = comment
        self.score = score
        self.origin = origin
        self.enabled = True
        self.is_array = False
        self.scanned_variables = set()

    def __lt__(self, other):
        return (self.offset, self.type_name) < (other.offset, other.type_name)

    def __eq__(self, other):
        return (self.offset, self.type_name) == (other.offset, other.type_name)


class _FakeScanObject:
    def __init__(
        self,
        *,
        func_ea: int,
        ea: int,
        name: str,
        function_name: str,
        root_func_ea: int | None = None,
        root_ea: int | None = None,
        root_function_name: str | None = None,
    ):
        self.func_ea = func_ea
        self.ea = ea
        self.name = name
        self.function_name = function_name
        self.scan_root_function_ea = func_ea if root_func_ea is None else root_func_ea
        self.scan_root_ea = ea if root_ea is None else root_ea
        self.scan_root_function_name = (
            function_name if root_function_name is None else root_function_name
        )

    def __hash__(self):
        return hash((self.func_ea, self.ea, self.name))

    def __eq__(self, other):
        return (
            isinstance(other, _FakeScanObject)
            and self.func_ea == other.func_ea
            and self.ea == other.ea
            and self.name == other.name
        )




def _make_descendant_member_evidence(
    target_offset: int,
    leaf_offset: int,
    *,
    entry_ea: int = 0x401000,
    evidence_ea: int = 0x401030,
    anchor_ea: int = 0x401020,
    parent_ea: int = 0x401010,
 ) -> SimpleNamespace:
    for op_name in ("var", "num", "add", "cast", "ptr"):
        if not hasattr(child_scan_module.ctype, op_name):
            setattr(child_scan_module.ctype, op_name, op_name)
    ctype = child_scan_module.ctype
    parent_expr = SimpleNamespace(op=ctype.var, ea=parent_ea)
    anchor_add = SimpleNamespace(
        op=ctype.add,
        x=parent_expr,
        y=SimpleNamespace(op=ctype.num, numval=lambda: target_offset),
        ea=anchor_ea - 0xC,
    )
    anchor_cast = SimpleNamespace(op=ctype.cast, x=anchor_add, ea=anchor_ea - 4)
    anchor_expr = SimpleNamespace(
        op=ctype.ptr,
        x=anchor_cast,
        type=SimpleNamespace(get_ptrarr_objsize=lambda: 1),
        ea=anchor_ea,
    )
    descendant_add = SimpleNamespace(
        op=ctype.add,
        x=anchor_expr,
        y=SimpleNamespace(op=ctype.num, numval=lambda: leaf_offset),
        ea=evidence_ea - 4,
    )
    descendant_expr = SimpleNamespace(
        op=ctype.ptr,
        x=descendant_add,
        type=SimpleNamespace(get_ptrarr_objsize=lambda: 1),
        ea=evidence_ea,
    )
    parent_map = {
        id(anchor_add): anchor_cast,
        id(anchor_cast): anchor_expr,
        id(anchor_expr): descendant_add,
        id(descendant_add): descendant_expr,
    }
    cfunc = SimpleNamespace(
        entry_ea=entry_ea,
        treeitems=[descendant_expr],
        eamap={evidence_ea: [descendant_expr]},
        body=SimpleNamespace(
            find_parent_of=lambda expr: parent_map.get(id(expr)),
            find_closest_addr=lambda _ea: descendant_expr,
        ),
    )
    return SimpleNamespace(
        cfunc=cfunc,
        parent_expr=parent_expr,
        anchor_expr=anchor_expr,
        descendant_expr=descendant_expr,
    )


def _make_form(monkeypatch) -> form_module.StructureBuilderForm:
    structure_form = form_module.StructureBuilderForm()
    monkeypatch.setattr(structure_form, "update_action_states", lambda: None)
    monkeypatch.setattr(structure_form, "update_structure_fields", lambda: None)
    monkeypatch.setattr(structure_form, "reload_structure_list", lambda: None)
    monkeypatch.setattr(structure_form, "_select_structure_in_tree", lambda _name: False)
    monkeypatch.setattr(
        structure_form,
        "set_structure",
        lambda name: setattr(structure_form, "current_structure", structure_form.structures[name]),
    )
    return structure_form

def test_on_close_resets_cached_ui_state(monkeypatch):
    structure_form = _make_form(monkeypatch)
    structure_form.parent = object()
    structure_form.ui = SimpleNamespace(tbl_structure=object(), tree_structures=object())
    structure_form.layout = object()
    structure_form._shortcut_actions = [object(), object()]

    structure_form.OnClose(None)

    assert structure_form.parent is None
    assert structure_form.ui is None
    assert structure_form.layout is None
    assert structure_form._shortcut_actions == []


def test_get_selected_rows_handles_stale_table_after_reload(monkeypatch):
    structure_form = _make_form(monkeypatch)
    structure_form.parent = object()
    structure_form.layout = object()

    class _StaleTable:
        def selectedIndexes(self):
            raise RuntimeError("wrapped C/C++ object of type QTableWidget has been deleted")

    structure_form.ui = SimpleNamespace(tbl_structure=_StaleTable())

    assert structure_form.get_selected_rows() == []
    assert structure_form.ui is None
    assert structure_form.parent is None
    assert structure_form.layout is None


def test_update_structure_fields_returns_when_table_selection_is_stale(monkeypatch):
    structure_form = _make_form(monkeypatch)
    monkeypatch.setattr(
        structure_form,
        "update_structure_fields",
        form_module.StructureBuilderForm.update_structure_fields.__get__(structure_form),
    )
    structure_form.parent = object()
    structure_form.layout = object()

    class _StaleTable:
        def selectedIndexes(self):
            raise RuntimeError("wrapped C/C++ object of type QTableWidget has been deleted")

    structure_form.ui = SimpleNamespace(tbl_structure=_StaleTable())
    structure_form.current_structure = Structure("Selected")

    structure_form.update_structure_fields()

    assert structure_form.ui is None
    assert structure_form.parent is None
    assert structure_form.layout is None




def test_make_table_item_uses_shared_qt_flag_helper(monkeypatch):
    calls = []

    class _FakeItem:
        def __init__(self, text):
            self.text = text
            self.flags = None

        def setFlags(self, flags):
            self.flags = flags

    monkeypatch.setattr(form_module, "QTableWidgetItem", _FakeItem)
    monkeypatch.setattr(
        form_module,
        "qt_item_flags",
        lambda *flags: calls.append(flags) or 0xD,
    )

    item = form_module.StructureBuilderForm._make_table_item("field", editable=True)

    assert item.text == "field"
    assert item.flags == 0xD
    assert calls == [
        (form_module.Qt.ItemIsSelectable, form_module.Qt.ItemIsEnabled),
        (0xD, form_module.Qt.ItemIsEditable),
    ]

def test_create_structure_treats_none_as_cancel(monkeypatch):
    structure_form = _make_form(monkeypatch)

    created = structure_form.create_structure(None)

    assert created is None
    assert structure_form.structures == {}
    assert structure_form.current_structure is None


def test_create_structure_rejects_duplicate_explicit_names(monkeypatch):
    structure_form = _make_form(monkeypatch)

    first = structure_form.create_structure("manual")
    duplicate = structure_form.create_structure("manual")

    assert first is not None
    assert first.is_auto_named is False
    assert duplicate is None
    assert list(structure_form.structures) == ["manual"]


def test_prompt_create_structure_treats_none_as_cancel(monkeypatch):
    structure_form = _make_form(monkeypatch)
    monkeypatch.setattr(form_module.ida_kernwin, "HIST_IDENT", 0, raising=False)
    monkeypatch.setattr(form_module.ida_kernwin, "ask_str", lambda *_args, **_kwargs: None)

    created = structure_form.prompt_create_structure()

    assert created is None
    assert structure_form.structures == {}
    assert structure_form.current_structure is None


def test_prompt_create_structure_auto_names_blank_and_whitespace(monkeypatch):
    structure_form = _make_form(monkeypatch)
    prompts = iter(["   ", "\t"])
    monkeypatch.setattr(form_module.ida_kernwin, "HIST_IDENT", 0, raising=False)
    monkeypatch.setattr(form_module.ida_kernwin, "ask_str", lambda *_args, **_kwargs: next(prompts))

    first = structure_form.prompt_create_structure()
    second = structure_form.prompt_create_structure()

    assert first is not None
    assert first.name == "auto_struct_001"
    assert first.is_auto_named is True
    assert second is not None
    assert second.name == "auto_struct_002"
    assert second.is_auto_named is True
    assert list(structure_form.structures) == ["auto_struct_001", "auto_struct_002"]
    assert structure_form.current_structure is second


def test_create_structure_skips_taken_auto_names_deterministically(monkeypatch):
    structure_form = _make_form(monkeypatch)
    structure_form.create_structure("auto_struct_001")
    structure_form.create_structure("manual")

    created = structure_form.create_structure("  ")

    assert created is not None
    assert created.name == "auto_struct_002"
    assert created.is_auto_named is True
    assert structure_form.structures["manual"].is_auto_named is False


def test_structure_renamed_clears_auto_named_flag(monkeypatch):
    structure_form = _make_form(monkeypatch)
    auto_named = structure_form.create_structure(" ")
    assert auto_named is not None

    fake_filter = _FakeFilter()
    structure_form.ui = SimpleNamespace(
        input_name=_FakeLineEdit("Inventory"),
        input_filter=fake_filter,
    )
    structure_form.current_structure = auto_named

    structure_form.structure_renamed()

    assert auto_named.name == "Inventory"
    assert auto_named.is_auto_named is False
    assert "auto_struct_001" not in structure_form.structures
    assert structure_form.structures["Inventory"] is auto_named
    assert fake_filter.cleared is True

def test_structure_renamed_syncs_created_type_name_when_canonical(monkeypatch):
    structure_form = _make_form(monkeypatch)
    structure = structure_form.create_structure("manual")
    assert structure is not None

    structure.created_type_name = "manual"
    rename_calls = []

    def fake_rename_created_type(old_name, new_name):
        rename_calls.append((old_name, new_name))
        structure.created_type_name = new_name
        return True

    monkeypatch.setattr(structure, "rename_created_type", fake_rename_created_type)

    fake_filter = _FakeFilter()
    structure_form.ui = SimpleNamespace(
        input_name=_FakeLineEdit("Inventory"),
        input_filter=fake_filter,
    )
    structure_form.current_structure = structure

    structure_form.structure_renamed()

    assert rename_calls == [("manual", "Inventory")]
    assert structure.name == "Inventory"
    assert structure.created_type_name == "Inventory"
    assert structure_form.structures["Inventory"] is structure
    assert fake_filter.cleared is True




def test_duplicate_structure_copies_provenance_and_outbound_relationships(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure("Child")

    assert parent is not None
    assert child is not None

    parent.set_provenance(
        kind="confirmed_root",
        root_object_name="player",
        source_member_offset=0x30,
    )
    parent.created_type_name = "Parent_t"
    member = _FakeMember(0x30, 8, type_name="Child *", name="inventory_ptr")
    parent.add_member(member)
    member.linked_child_structure_name = "Child"
    member.child_relation_kind = "pointer"

    relationship = parent.add_child_relationship(
        child_structure_name="Child",
        parent_member_offset=0x30,
        parent_member_name="inventory_ptr",
    )
    child.add_parent_relationship(relationship)
    structure_form.current_structure = parent

    structure_form.duplicate_structure()

    duplicate = structure_form.structures["Parent Copy"]
    assert duplicate.provenance == parent.provenance
    assert duplicate.provenance is not parent.provenance
    assert duplicate.is_auto_named is True
    assert duplicate.created_type_name is None
    assert duplicate.parent_relationships == []
    assert len(duplicate.child_relationships) == 1
    assert duplicate.child_relationships[0].parent_structure_name == "Parent Copy"
    assert duplicate.child_relationships[0].child_structure_name == "Child"
    assert duplicate.members[0].linked_child_structure_name == "Child"
    assert duplicate.members[0].child_relation_kind == "pointer"
    assert sorted(
        rel.parent_structure_name for rel in child.parent_relationships
    ) == ["Parent", "Parent Copy"]


def test_duplicate_structure_clears_orphaned_member_links_and_inbound_parents(
    monkeypatch,
):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure("Child")

    assert parent is not None
    assert child is not None

    relationship = parent.add_child_relationship(
        child_structure_name="Child",
        parent_member_offset=0x20,
        parent_member_name="child_ptr",
    )
    child.add_parent_relationship(relationship)

    orphan_member = _FakeMember(0x30, 8, type_name="Ghost *", name="ghost_ptr")
    child.add_member(orphan_member)
    orphan_member.linked_child_structure_name = "Ghost"
    orphan_member.child_relation_kind = "pointer"
    structure_form.current_structure = child

    structure_form.duplicate_structure()

    duplicate = structure_form.structures["Child Copy"]
    assert duplicate.parent_relationships == []
    assert duplicate.members[0].linked_child_structure_name is None
    assert duplicate.members[0].child_relation_kind is None


def test_format_type_status_reports_created_structures_with_unresolved_children(
    monkeypatch,
):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure("Child")

    assert parent is not None
    assert child is not None

    parent.add_child_relationship(
        child_structure_name="Child",
        parent_member_offset=0x30,
        parent_member_name="inventory_ptr",
    )
    parent.created_type_name = "Parent_t"

    assert (
        structure_form._format_type_status(parent)
        == "created as Parent_t | unresolved children: Child"
    )

    child.created_type_name = "Child_t"

    assert structure_form._format_type_status(parent) == "created as Parent_t | child links ready"


def test_structure_table_finalize_blocks_unresolved_children(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure("Child")

    assert parent is not None
    assert child is not None

    parent.add_child_relationship(
        child_structure_name="Child",
        parent_member_offset=0x30,
        parent_member_name="child_ptr",
    )
    structure_form.current_structure = parent

    warnings: list[str] = []
    monkeypatch.setattr(
        structure_module,
        "log_warning",
        lambda message, *args, **kwargs: warnings.append(message),
    )

    pack_calls: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        parent,
        "pack_structure",
        lambda *args, **kwargs: pack_calls.append((args, kwargs)) or object(),
    )

    structure_form.structure_table_finalize()

    assert pack_calls == []
    assert warnings == [
        "Cannot create type for Parent: unresolved child structures: Child"
    ]


def test_structure_table_resolve_clears_stale_selection_after_refresh(monkeypatch):
    structure_form = _make_form(monkeypatch)

    class _TableSelectionRecorder:
        def __init__(self):
            self.clear_selection_calls = 0
            self.current_cells = []

        def clearSelection(self):
            self.clear_selection_calls += 1

        def setCurrentCell(self, row, column):
            self.current_cells.append((row, column))

    calls: list[str] = []
    table = _TableSelectionRecorder()
    structure_form.ui = SimpleNamespace(tbl_structure=table)
    structure_form.current_structure = SimpleNamespace(
        auto_resolve=lambda: calls.append("resolve")
    )
    monkeypatch.setattr(
        structure_form, "update_structure_fields", lambda: calls.append("fields")
    )
    monkeypatch.setattr(
        structure_form, "update_action_states", lambda: calls.append("actions")
    )

    structure_form.structure_table_resolve()

    assert calls == ["resolve", "fields", "actions"]
    assert table.clear_selection_calls == 1
    assert table.current_cells == [(-1, -1)]


def test_create_child_types_creates_direct_children_in_offset_order(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child_a = structure_form.create_structure("ChildA")
    child_b = structure_form.create_structure("ChildB")

    assert parent is not None
    assert child_a is not None
    assert child_b is not None

    parent.add_child_relationship(
        child_structure_name="Missing",
        parent_member_offset=0x08,
        parent_member_name="missing_ptr",
    )
    parent.add_child_relationship(
        child_structure_name="ChildB",
        parent_member_offset=0x20,
        parent_member_name="child_b_ptr",
    )
    parent.add_child_relationship(
        child_structure_name="ChildA",
        parent_member_offset=0x10,
        parent_member_name="child_a_ptr",
    )
    structure_form.current_structure = parent

    warnings: list[str] = []
    monkeypatch.setattr(
        form_module,
        "log_warning",
        lambda message, *args, **kwargs: warnings.append(message),
    )

    created: list[str] = []
    monkeypatch.setattr(
        child_a,
        "create_type_if_ready",
        lambda structures_by_name, **kwargs: created.append("ChildA") or object(),
    )
    monkeypatch.setattr(
        child_b,
        "create_type_if_ready",
        lambda structures_by_name, **kwargs: created.append("ChildB") or object(),
    )

    structure_form.create_child_types()

    assert created == ["ChildA", "ChildB"]
    assert warnings == [
        "Linked child structure Missing does not exist."
    ]


def test_create_type_subtree_creates_children_before_parent(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child_b = structure_form.create_structure("ChildB")
    child_c = structure_form.create_structure("ChildC")
    grandchild = structure_form.create_structure("Grandchild")

    assert parent is not None
    assert child_b is not None
    assert child_c is not None
    assert grandchild is not None

    parent.add_child_relationship(
        child_structure_name="ChildB",
        parent_member_offset=0x10,
        parent_member_name="child_b_ptr",
    )
    parent.add_child_relationship(
        child_structure_name="ChildC",
        parent_member_offset=0x20,
        parent_member_name="child_c_ptr",
    )
    child_b.add_child_relationship(
        child_structure_name="Grandchild",
        parent_member_offset=0x08,
        parent_member_name="grandchild_ptr",
    )
    structure_form.current_structure = parent

    created: list[str] = []
    monkeypatch.setattr(
        structure_module.Structure,
        "create_type_if_ready",
        lambda self, structures_by_name, **kwargs: created.append(self.name) or object(),
    )

    structure_form.create_type_subtree()

    assert created == ["Grandchild", "ChildB", "ChildC", "Parent"]


def test_update_action_states_enables_child_type_actions_for_child_relationships(
    monkeypatch,
):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure("Child")

    assert parent is not None
    assert child is not None

    parent.add_child_relationship(
        child_structure_name="Child",
        parent_member_offset=0x30,
        parent_member_name="child_ptr",
    )
    structure_form.current_structure = parent

    structure_form.ui = SimpleNamespace(
        btn_remove=_Recorder(),
        btn_duplicate_structure=_Recorder(),
        btn_apply_name=_Recorder(),
        input_name=_Recorder(),
        input_filter=_Recorder(),
        tbl_structure=_Recorder(),
        btn_auto_resolve=_Recorder(),
        btn_create_type=_Recorder(),
        btn_enable_rows=_Recorder(),
        btn_disable_rows=_Recorder(),
        btn_toggle_array=_Recorder(),
        btn_set_origin=_Recorder(),
        btn_remove_rows=_Recorder(),
        btn_clear_rows=_Recorder(),
        btn_view_scanned_uses=_Recorder(),
        btn_recognize_vtable=_Recorder(),
        btn_add_row=_Recorder(),
        btn_duplicate_row=_Recorder(),
        btn_edit_row=_Recorder(),
        btn_scan_child=_Recorder(),
        btn_open_child=_Recorder(),
        btn_create_child_types=_Recorder(),
        btn_create_subtree_types=_Recorder(),
        action_enable=_Recorder(),
        action_disable=_Recorder(),
        action_resolve=_Recorder(),
        action_finalize=_Recorder(),
        action_edit=_Recorder(),
        action_add_row=_Recorder(),
        action_duplicate_row=_Recorder(),
        action_scan_child=_Recorder(),
        action_create_child_types=_Recorder(),
        action_create_subtree_types=_Recorder(),
    )
    monkeypatch.setattr(structure_form, "get_selected_rows", lambda: [])
    monkeypatch.setattr(structure_form, "get_selected_member", lambda: None)
    monkeypatch.setattr(structure_form, "_build_child_scan_plan", lambda _member: None)
    monkeypatch.setattr(structure_form, "_update_summary_label", lambda: None)
    monkeypatch.setattr(
        structure_form,
        "_update_inspector_panel",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        structure_form,
        "update_action_states",
        form_module.StructureBuilderForm.update_action_states.__get__(structure_form),
    )

    structure_form.update_action_states()

    assert structure_form.ui.btn_create_child_types.enabled is True
    assert structure_form.ui.btn_create_subtree_types.enabled is True
    assert structure_form.ui.action_create_child_types.enabled is True
    assert structure_form.ui.action_create_subtree_types.enabled is True
    assert structure_form.ui.btn_scan_child.enabled is False
    assert structure_form.ui.action_scan_child.enabled is False



def test_scan_child_structure_auto_creates_child_and_records_metadata(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(0x30, 8, type_name="u64", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: False, is_udt=lambda: False)
    member.scanned_variables = [
        SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root"),
    ]
    parent.created_type_name = "Parent_t"
    parent.add_member(member)
    structure_form.current_structure = parent

    plan = form_module.ChildScanPlan(
        scan_object=SimpleNamespace(name="child_ptr"),
        function_eas=(0x401000,),
        relation_kind="embedded",
        root_object_name="Parent.child_ptr",
        root_object_ea=0x402000,
        root_function_ea=0x401000,
        has_multiple_roots=False,
    )
    monkeypatch.setattr(structure_form, "get_selected_member", lambda: member)
    monkeypatch.setattr(
        structure_form,
        "_build_child_scan_plan",
        lambda _member, show_warnings=False: plan,
    )

    def fake_execute(child_structure, built_plan):
        assert built_plan is plan
        assert child_structure.main_offset == member.offset
        child_structure.add_member(_FakeMember(0, 4, type_name="u32", name="value"))
        return True

    monkeypatch.setattr(structure_form, "_execute_child_scan_plan", fake_execute)

    structure_form.scan_child_structure()

    child = structure_form.structures["auto_struct_001"]
    assert structure_form.current_structure is child
    assert child.is_auto_named is True
    assert child.main_offset == 0x30
    assert child.provenance.kind == "child_scan"
    assert child.provenance.root_object_name == "Parent.child_ptr"
    assert child.provenance.source_member_offset == 0x30
    assert member.linked_child_structure_name == child.name
    assert member.child_relation_kind == "embedded"
    assert parent.child_relationships[0].child_structure_name == child.name
    assert child.parent_relationships[0].parent_structure_name == "Parent"



def test_scan_child_structure_reuses_existing_linked_child(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure("Child")
    assert parent is not None
    assert child is not None

    member = _FakeMember(0x30, 8, type_name="Child *", name="child_ptr")
    member.linked_child_structure_name = "Child"
    parent.add_member(member)
    structure_form.current_structure = parent

    plan = form_module.ChildScanPlan(
        scan_object=SimpleNamespace(name="child_ptr"),
        function_eas=(0x401000,),
        relation_kind="pointer",
        root_object_name="Parent.child_ptr",
        root_object_ea=0x402000,
        root_function_ea=0x401000,
        has_multiple_roots=False,
    )
    monkeypatch.setattr(structure_form, "get_selected_member", lambda: member)
    monkeypatch.setattr(
        structure_form,
        "_build_child_scan_plan",
        lambda _member, show_warnings=False: plan,
    )
    monkeypatch.setattr(
        structure_form,
        "_execute_child_scan_plan",
        lambda child_structure, _plan: child_structure.add_member(
            _FakeMember(0, 4, type_name="u32", name="value")
        )
        or True,
    )

    structure_form.scan_child_structure()

    assert list(structure_form.structures) == ["Parent", "Child"]
    assert structure_form.current_structure is child
    assert member.linked_child_structure_name == "Child"
    assert parent.child_relationships[0].child_structure_name == "Child"
    assert child.parent_relationships[0].parent_structure_name == "Parent"

def test_show_scanned_variables_dedupes_duplicate_selected_member_evidence(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    class _DuplicateScanObject:
        def __init__(self, *, func_ea: int, ea: int, name: str, origin: int = 0x20):
            self.func_ea = func_ea
            self.ea = ea
            self.name = name
            self.origin = origin

        def to_list(self):
            return [f"0x{self.origin:04X}", "child_func", self.name, hex(self.ea)]

    member = _FakeMember(0x30, 8, type_name="Child *", name="child_ptr")
    scan_a = _DuplicateScanObject(func_ea=0x401000, ea=0x401234, name="child_ptr_scan")
    scan_b = _DuplicateScanObject(func_ea=0x401000, ea=0x401234, name="child_ptr_scan")
    member.scanned_variables = {scan_a, scan_b}
    parent.add_member(member)
    structure_form.current_structure = parent
    monkeypatch.setattr(structure_form, "get_selected_members", lambda rows=None: [member])

    captured = {}

    class _ChooserRecorder:
        def __init__(self, scanned_variables):
            captured["scanned_variables"] = list(scanned_variables)

        def Show(self):
            captured["shown"] = True

    monkeypatch.setattr(child_scan_module, "ScannedVariableChooser", _ChooserRecorder)

    structure_form.show_scanned_variables()

    assert captured["shown"] is True
    assert len(captured["scanned_variables"]) == 1
    assert captured["scanned_variables"][0].name == "child_ptr_scan"


def test_build_structure_table_debug_csv_includes_scan_metadata(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(
        0x30,
        8,
        type_name="Child *",
        name="child_ptr",
        comment="linked",
        score=13,
        origin=0x20,
    )
    scan_object = _FakeScanObject(
        func_ea=0x401000,
        ea=0x401234,
        name="child_ptr_scan",
        function_name="child_func",
        root_func_ea=0x400800,
        root_ea=0x400ABC,
        root_function_name="root_func",
    )

    member.scanned_variables = {scan_object}
    parent.add_member(member)
    structure_form.current_structure = parent
    monkeypatch.setattr(structure_form, "get_selected_members", lambda rows=None: [])

    fake_cfunc = SimpleNamespace(
        treeitems=[SimpleNamespace(ea=0x401234), SimpleNamespace(ea=0x400ABC)],
        find_item_coords=lambda _item: (2, 0) if getattr(_item, "ea", None) == 0x401234 else (1, 0),
        get_pseudocode=lambda: [
            "if (ok) {",
            "    parent->child = value;",
        ],
    )
    monkeypatch.setattr(form_module, "decompile", lambda func_ea: fake_cfunc if func_ea in (0x401000, 0x400800) else None)
    csv_text = structure_form._build_structure_table_debug_csv()
    rows = list(csv.reader(io.StringIO(csv_text)))



    assert rows[0] == [
        "structure_name",
        "row",
        "offset",
        "type",
        "name",
        "score",
        "comment",
        "enabled",
        "array",
        "origin",
        "scan_location_count",
        "scan_locations",
        "scan_lines",
        "scan_root_location_count",
        "scan_root_locations",
        "scan_root_lines",
    ]
    assert rows[1] == [
        "Parent",
        "0",
        "0x0030 [0x8]",
        "Child *",
        "child_ptr",
        "13",
        "linked",
        "yes",
        "no",
        "0x20",
        "1",
        f"child_func@{hex(0x401234)}",
        "parent->child = value;",
        "1",
        f"root_func@{hex(0x400ABC)}",
        "if (ok) {",
    ]





def test_build_structure_table_debug_csv_falls_back_for_root_labels_and_lines(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(
        0x30,
        8,
        type_name="Child *",
        name="child_ptr",
        comment="linked",
        score=13,
        origin=0x20,
    )
    scan_object = _FakeScanObject(
        func_ea=0x401000,
        ea=0x401234,
        name="child_ptr_scan",
        function_name="child_func",
        root_func_ea=0x400800,
        root_ea=0x400ABC,
        root_function_name=None,
    )
    scan_object.scan_root_function_name = None
    member.scanned_variables = {scan_object}
    parent.add_member(member)
    structure_form.current_structure = parent
    monkeypatch.setattr(structure_form, "get_selected_members", lambda rows=None: [])
    monkeypatch.setattr(
        form_module.ida_funcs,
        "get_func_name",
        lambda ea: {0x401000: "child_func", 0x400800: "root_func"}.get(ea, f"sub_{ea:x}"),
        raising=False,
    )

    root_item = SimpleNamespace(ea=0x400ABC)
    fake_cfunc = SimpleNamespace(
        treeitems=[SimpleNamespace(ea=0x401234)],
        eamap={0x400ABC: [root_item]},
        find_item_coords=lambda item: (2, 0) if getattr(item, "ea", None) == 0x401234 else (1, 0),
        get_pseudocode=lambda: [
            "if (ok) {",
            "    parent->child = value;",
        ],
    )
    monkeypatch.setattr(form_module, "decompile", lambda func_ea: fake_cfunc if func_ea in (0x401000, 0x400800) else None)
    csv_text = structure_form._build_structure_table_debug_csv()
    rows = list(csv.reader(io.StringIO(csv_text)))

    row = dict(zip(rows[0], rows[1]))

    assert row["scan_location_count"] == "1"
    assert row["scan_locations"] == "child_func@0x401234"
    assert row["scan_lines"] == "parent->child = value;"
    assert row["scan_root_location_count"] == "1"
    assert row["scan_root_locations"] == "root_func@0x400abc"
    assert row["scan_root_lines"] == "if (ok) {"

def test_build_structure_table_debug_csv_reads_simpleline_line_text(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(
        0x30,
        8,
        type_name="Child *",
        name="child_ptr",
        comment="linked",
        score=13,
        origin=0x20,
    )
    scan_object = _FakeScanObject(
        func_ea=0x401000,
        ea=0x401234,
        name="child_ptr_scan",
        function_name="child_func",
        root_func_ea=0x400800,
        root_ea=0x400ABC,
        root_function_name="root_func",
    )
    member.scanned_variables = {scan_object}
    parent.add_member(member)
    structure_form.current_structure = parent
    monkeypatch.setattr(structure_form, "get_selected_members", lambda rows=None: [])

    class _FakeSimpleLine:
        def __init__(self, line: str):
            self.line = line

        def __str__(self) -> str:
            return "<ida_kernwin.simpleline_t proxy>"

    fake_cfunc = SimpleNamespace(
        treeitems=[SimpleNamespace(ea=0x401234), SimpleNamespace(ea=0x400ABC)],
        find_item_coords=lambda _item: (2, 0) if getattr(_item, "ea", None) == 0x401234 else (1, 0),
        get_pseudocode=lambda: [
            _FakeSimpleLine("if (ok) {"),
            _FakeSimpleLine("    parent->child = value;"),
        ],
    )
    monkeypatch.setattr(form_module, "decompile", lambda func_ea: fake_cfunc if func_ea in (0x401000, 0x400800) else None)

    csv_text = structure_form._build_structure_table_debug_csv()
    rows = list(csv.reader(io.StringIO(csv_text)))
    row = dict(zip(rows[0], rows[1]))

    assert row["scan_lines"] == "parent->child = value;"
    assert row["scan_root_lines"] == "if (ok) {"


def test_copy_structure_table_debug_csv_writes_clipboard(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(0x30, 8, type_name="Child *", name="child_ptr")
    member.scanned_variables = {
        _FakeScanObject(
            func_ea=0x401000,
            ea=0x401234,
            name="child_ptr_scan",
            function_name="child_func",
            root_func_ea=0x400800,
            root_ea=0x400ABC,
            root_function_name="root_func",
        )
    }
    parent.add_member(member)
    structure_form.current_structure = parent
    monkeypatch.setattr(structure_form, "get_selected_members", lambda rows=None: [])
    monkeypatch.setattr(form_module, "decompile", lambda *_args, **_kwargs: None)




    fake_clipboard = SimpleNamespace(text=None, setText=lambda value: setattr(fake_clipboard, "text", value))
    monkeypatch.setattr(form_module.ida_kernwin, "copy_to_clipboard", lambda value: fake_clipboard.setText(value), raising=False)

    structure_form.copy_structure_table_debug_csv()

    assert fake_clipboard.text is not None
    assert fake_clipboard.text.startswith("structure_name,row,offset,type,name,score,comment,enabled,array,origin")




def test_scan_child_structure_rolls_back_new_child_when_scan_finds_nothing(
    monkeypatch,
):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(0x30, 8, type_name="Child *", name="child_ptr")
    parent.add_member(member)
    structure_form.current_structure = parent

    plan = form_module.ChildScanPlan(
        scan_object=SimpleNamespace(name="child_ptr"),
        function_eas=(0x401000,),
        relation_kind="pointer",
        root_object_name="Parent.child_ptr",
        root_object_ea=0x402000,
        root_function_ea=0x401000,
        has_multiple_roots=False,
    )
    monkeypatch.setattr(structure_form, "get_selected_member", lambda: member)
    monkeypatch.setattr(
        structure_form,
        "_build_child_scan_plan",
        lambda _member, show_warnings=False: plan,
    )
    monkeypatch.setattr(
        structure_form,
        "_execute_child_scan_plan",
        lambda _child_structure, _plan: True,
    )

    structure_form.scan_child_structure()

    assert "auto_struct_001" not in structure_form.structures
    assert structure_form.current_structure is parent
    assert parent.child_relationships == []
    assert member.linked_child_structure_name is None


def test_build_child_scan_plan_uses_created_parent_type(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    parent.created_type_name = "Parent_t"
    member = _FakeMember(0x30, 8, type_name="u64", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: False, is_udt=lambda: False)
    member.scanned_variables = [
        SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root"),
    ]
    structure_form.current_structure = parent
    monkeypatch.setattr(form_module, "is_legal_type", lambda _tinfo: True)

    plan = structure_form._build_child_scan_plan(member)

    assert plan is not None
    assert plan.relation_kind == "embedded"
    assert plan.function_eas == (0x401000,)
    assert plan.root_object_name == "Parent.child_ptr"
    assert plan.scan_object.struct_name == "Parent_t"
    assert plan.scan_object.offset == 0x30




def test_build_child_scan_plan_preserves_distinct_scan_locations(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    parent.created_type_name = "Parent_t"
    member = _FakeMember(0x30, 8, type_name="u64", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: False, is_udt=lambda: False)
    member.scanned_variables = {
        _FakeScanObject(
            func_ea=0x401000,
            ea=0x402000,
            name="root",
            function_name="root_func",
        ),
        _FakeScanObject(
            func_ea=0x401000,
            ea=0x402010,
            name="root",
            function_name="root_func",
        ),
    }
    parent.add_member(member)
    structure_form.current_structure = parent
    monkeypatch.setattr(form_module, "is_legal_type", lambda _tinfo: True)

    plan = structure_form._build_child_scan_plan(member)

    assert plan is not None
    assert plan.function_eas == (0x401000,)
    assert plan.has_multiple_roots is True
    assert plan.root_object_ea in {0x402000, 0x402010}
    assert len(plan.scan_variables) == 2
    assert {scan_variable.ea for scan_variable in plan.scan_variables} == {0x402000, 0x402010}


def test_build_child_scan_plan_accepts_inferred_primitive_member(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("auto_struct_001")
    assert parent is not None

    member = _FakeMember(0xCD8, 8, type_name="u64", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: False, is_udt=lambda: False)
    member.scanned_variables = [
        SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root", _name="auto_struct_001"),
    ]
    structure_form.current_structure = parent
    monkeypatch.setattr(form_module, "is_legal_type", lambda _tinfo: True)

    plan = structure_form._build_child_scan_plan(member)

    assert plan is not None
    assert plan.relation_kind == "embedded"
    assert plan.scan_object.struct_name == "auto_struct_001"
    assert plan.scan_object.offset == 0xCD8



def test_build_child_scan_plan_uses_structure_name_when_untyped(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("auto_struct_001")
    assert parent is not None

    member = _FakeMember(0xCD8, 8, type_name="u64", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: False, is_udt=lambda: False)
    member.scanned_variables = [
        SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root"),
    ]
    structure_form.current_structure = parent
    monkeypatch.setattr(form_module, "is_legal_type", lambda _tinfo: True)

    plan = structure_form._build_child_scan_plan(member)

    assert plan is not None
    assert plan.scan_object.struct_name == "auto_struct_001"
    assert plan.scan_object.offset == 0xCD8


def test_build_child_scan_plan_allows_ambiguous_member_evidence_when_parent_named(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(0x30, 8, type_name="Child *", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: True, is_udt=lambda: False)
    member.scanned_variables = [
        SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root_a", _name="TypeA"),
        SimpleNamespace(func_ea=0x401100, ea=0x402100, name="root_b", _name="TypeB"),
    ]
    structure_form.current_structure = parent
    monkeypatch.setattr(form_module, "is_legal_type", lambda _tinfo: True)

    plan = structure_form._build_child_scan_plan(member)

    assert plan is not None
    assert plan.scan_object.struct_name == "Parent"
    assert plan.has_multiple_roots is True

def test_build_child_scan_plan_prefers_scan_root_evidence(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    parent.created_type_name = "Parent_t"
    member = _FakeMember(0x30, 8, type_name="u64", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: False, is_udt=lambda: False)
    member.scanned_variables = [
        _FakeScanObject(
            func_ea=0x401000,
            ea=0x402000,
            name="root",
            function_name="use_func",
            root_func_ea=0x400800,
            root_ea=0x400ABC,
            root_function_name="seed_func",
        ),
    ]
    structure_form.current_structure = parent
    monkeypatch.setattr(form_module, "is_legal_type", lambda _tinfo: True)

    plan = structure_form._build_child_scan_plan(member)

    assert plan is not None
    assert plan.function_eas == (0x400800,)
    assert plan.root_object_ea == 0x400ABC
    assert plan.root_function_ea == 0x400800
    assert len(plan.scan_variables) == 1
    assert plan.scan_variables[0].ea == 0x400ABC
    assert plan.scan_variables[0].func_ea == 0x400800



def test_handle_structure_table_selection_change_coalesces_duplicate_signals(monkeypatch):
    structure_form = _make_form(monkeypatch)
    structure_form.current_structure = Structure("Parent")

    class _FakeIndex:
        def __init__(self, row):
            self._row = row

        def row(self):
            return self._row

    class _FakeTable:
        def __init__(self):
            self._row = 1
            self._column = 0

        def selectedIndexes(self):
            return [_FakeIndex(self._row)]

        def currentRow(self):
            return self._row

        def currentColumn(self):
            return self._column

    calls = []
    structure_form.ui = SimpleNamespace(tbl_structure=_FakeTable())
    monkeypatch.setattr(
        structure_form,
        "update_action_states",
        lambda: calls.append(structure_form._structure_table_selection_signature()),
    )

    structure_form._handle_structure_table_selection_change()
    structure_form._handle_structure_table_selection_change()
    structure_form._handle_structure_table_selection_change()

    assert len(calls) == 1
    assert calls[0] == ("Parent", (1,), 1, 0)

    structure_form.ui.tbl_structure._row = 2
    structure_form._handle_structure_table_selection_change()

    assert len(calls) == 2
    assert calls[1] == ("Parent", (2,), 2, 0)


def test_update_action_states_builds_child_scan_plan_once_per_refresh(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(0x30, 8, type_name="u64", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: False, is_udt=lambda: False)
    member.scanned_variables = [SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root")]
    parent.add_member(member)
    structure_form.current_structure = parent

    plan = SimpleNamespace(function_eas=(0x401000,), relation_kind="embedded")
    plan_calls = []

    structure_form.ui = SimpleNamespace(
        btn_remove=_Recorder(),
        btn_duplicate_structure=_Recorder(),
        btn_apply_name=_Recorder(),
        input_name=_Recorder(),
        input_filter=_Recorder(),
        tbl_structure=_Recorder(),
        btn_auto_resolve=_Recorder(),
        btn_create_type=_Recorder(),
        btn_enable_rows=_Recorder(),
        btn_disable_rows=_Recorder(),
        btn_toggle_array=_Recorder(),
        btn_set_origin=_Recorder(),
        btn_remove_rows=_Recorder(),
        btn_clear_rows=_Recorder(),
        btn_view_scanned_uses=_Recorder(),
        btn_recognize_vtable=_Recorder(),
        btn_add_row=_Recorder(),
        btn_duplicate_row=_Recorder(),
        btn_edit_row=_Recorder(),
        btn_scan_child=_Recorder(),
        btn_open_child=_Recorder(),
        btn_create_child_types=_Recorder(),
        btn_create_subtree_types=_Recorder(),
        action_enable=_Recorder(),
        action_disable=_Recorder(),
        action_resolve=_Recorder(),
        action_finalize=_Recorder(),
        action_edit=_Recorder(),
        action_add_row=_Recorder(),
        action_duplicate_row=_Recorder(),
        action_scan_child=_Recorder(),
        action_create_child_types=_Recorder(),
        action_create_subtree_types=_Recorder(),
        lbl_summary=_Recorder(),
        lbl_provenance=_Recorder(),
        lbl_root_info=_Recorder(),
        lbl_parent_links=_Recorder(),
        lbl_child_links=_Recorder(),
        lbl_selected_member_info=_Recorder(),
        lbl_type_status=_Recorder(),
    )
    monkeypatch.setattr(structure_form, "get_selected_rows", lambda: [0])
    monkeypatch.setattr(structure_form, "get_selected_member", lambda: member)
    monkeypatch.setattr(
        structure_form,
        "_build_child_scan_plan",
        lambda _member, show_warnings=False: plan_calls.append((_member, show_warnings)) or plan,
    )
    monkeypatch.setattr(structure_form, "_update_summary_label", lambda: None)
    monkeypatch.setattr(structure_form, "_format_structure_provenance", lambda _structure: "manual")
    monkeypatch.setattr(structure_form, "_format_root_info", lambda _structure: "root")
    monkeypatch.setattr(
        structure_form,
        "_format_relationships",
        lambda _relationships, direction: direction,
    )
    monkeypatch.setattr(
        structure_form,
        "_format_selected_member_info",
        lambda _member, *, child_scan_ready=False: "child scan ready" if child_scan_ready else "selected",
    )
    monkeypatch.setattr(structure_form, "_format_type_status", lambda _structure: "status")
    monkeypatch.setattr(
        structure_form,
        "update_action_states",
        form_module.StructureBuilderForm.update_action_states.__get__(structure_form),
    )

    structure_form.update_action_states()

    assert plan_calls == [(member, False)]
    assert structure_form.ui.btn_scan_child.enabled is True
    assert structure_form.ui.lbl_selected_member_info.text == "Selected Row: child scan ready"


def test_update_action_states_enables_child_scan_actions_for_scannable_member(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(0x30, 8, type_name="u64", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: False, is_udt=lambda: False)
    member.scanned_variables = [SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root")]
    parent.created_type_name = "Parent_t"
    parent.add_member(member)
    structure_form.current_structure = parent

    plan = SimpleNamespace(function_eas=(0x401000,), relation_kind="embedded")

    structure_form.ui = SimpleNamespace(
        btn_remove=_Recorder(),
        btn_duplicate_structure=_Recorder(),
        btn_apply_name=_Recorder(),
        input_name=_Recorder(),
        input_filter=_Recorder(),
        tbl_structure=_Recorder(),
        btn_auto_resolve=_Recorder(),
        btn_create_type=_Recorder(),
        btn_enable_rows=_Recorder(),
        btn_disable_rows=_Recorder(),
        btn_toggle_array=_Recorder(),
        btn_set_origin=_Recorder(),
        btn_remove_rows=_Recorder(),
        btn_clear_rows=_Recorder(),
        btn_view_scanned_uses=_Recorder(),
        btn_recognize_vtable=_Recorder(),
        btn_add_row=_Recorder(),
        btn_duplicate_row=_Recorder(),
        btn_edit_row=_Recorder(),
        btn_scan_child=_Recorder(),
        btn_open_child=_Recorder(),
        btn_create_child_types=_Recorder(),
        btn_create_subtree_types=_Recorder(),
        action_enable=_Recorder(),
        action_disable=_Recorder(),
        action_resolve=_Recorder(),
        action_finalize=_Recorder(),
        action_edit=_Recorder(),
        action_add_row=_Recorder(),
        action_duplicate_row=_Recorder(),
        action_scan_child=_Recorder(),
        action_create_child_types=_Recorder(),
        action_create_subtree_types=_Recorder(),
    )
    monkeypatch.setattr(structure_form, "get_selected_rows", lambda: [member])
    monkeypatch.setattr(structure_form, "get_selected_member", lambda: member)
    monkeypatch.setattr(structure_form, "_build_child_scan_plan", lambda _member, show_warnings=False: plan)
    monkeypatch.setattr(structure_form, "_update_summary_label", lambda: None)
    monkeypatch.setattr(
        structure_form,
        "_update_inspector_panel",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        structure_form,
        "update_action_states",
        form_module.StructureBuilderForm.update_action_states.__get__(structure_form),
    )

    structure_form.update_action_states()

    assert structure_form.ui.btn_scan_child.enabled is True
    assert structure_form.ui.action_scan_child.enabled is True
    assert (
        "child scan ready"
        in structure_form._format_selected_member_info(member, child_scan_ready=True)
    )



def test_execute_child_scan_plan_enables_recursive_child_traversal(monkeypatch):
    structure_form = _make_form(monkeypatch)
    child = structure_form.create_structure("Child")
    assert child is not None
    child.main_offset = 0x30

    plan = SimpleNamespace(
        function_eas=(0x401000,),
        scan_object=SimpleNamespace(name="child_ptr", id="member"),
        scan_variables=(SimpleNamespace(func_ea=0x401000, ea=0x402000),),
    )
    captured = {}

    monkeypatch.setattr(
        structure_form,
        "_prepare_scan_cfunc",
        lambda _ea: SimpleNamespace(entry_ea=0x401000),
    )

    class FakeVisitor:
        def __init__(self, cfunc, origin, obj, structure, recurse_calls=False):
            captured["args"] = (
                cfunc.entry_ea,
                origin,
                obj.name,
                obj.ea,
                structure.name,
                recurse_calls,
            )

        def process(self):
            return None

    monkeypatch.setattr(form_module, "NewDeepScanVisitor", FakeVisitor)

    assert structure_form._execute_child_scan_plan(child, plan) is True
    assert captured["args"] == (0x401000, 0x30, "child_ptr", 0x402000, "Child", True)


def test_execute_child_scan_plan_runs_for_each_scan_location(monkeypatch):
    structure_form = _make_form(monkeypatch)
    child = structure_form.create_structure("Child")
    assert child is not None
    child.main_offset = 0x30

    plan = SimpleNamespace(
        function_eas=(0x401000,),
        scan_object=SimpleNamespace(name="child_ptr", id="member"),
        scan_variables=(
            SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root_a"),
            SimpleNamespace(func_ea=0x401000, ea=0x402010, name="root_b"),
        ),
    )

    monkeypatch.setattr(
        structure_form,
        "_prepare_scan_cfunc",
        lambda _ea: SimpleNamespace(
            entry_ea=0x401000,
            treeitems=[
                SimpleNamespace(ea=0x402000),
                SimpleNamespace(ea=0x402010),
            ],
            eamap={},
            body=None,
        ),
    )

    captured = []

    class FakeVisitor:
        def __init__(self, cfunc, origin, obj, structure, recurse_calls=False):
            captured.append(
                (
                    cfunc.entry_ea,
                    origin,
                    obj.ea,
                    obj.func_ea,
                    obj.name,
                    structure.name,
                    recurse_calls,
                )
            )

        def process(self):
            return None

    monkeypatch.setattr(form_module, "NewDeepScanVisitor", FakeVisitor)

    assert structure_form._execute_child_scan_plan(child, plan) is True
    assert captured == [
        (0x401000, 0x30, 0x402000, 0x401000, "child_ptr", "Child", True),
        (0x401000, 0x30, 0x402010, 0x401000, "child_ptr", "Child", True),
    ]


def test_execute_child_scan_plan_normalizes_legacy_scan_variables(monkeypatch):
    structure_form = _make_form(monkeypatch)
    child = structure_form.create_structure("Child")
    assert child is not None
    child.main_offset = 0x30

    legacy_lvar = SimpleNamespace(location="stack", defea=0x1234)
    legacy_scan_variable = SimpleNamespace(
        name="root_a",
        ea=0x402000,
        func_ea=0x401000,
        _ScannedVariableObject__lvar=legacy_lvar,
    )
    plan = SimpleNamespace(
        function_eas=(0x401000,),
        scan_object=SimpleNamespace(
            name="child_ptr",
            id=import_module("forge.api.scan_object").ObjectType.structure_reference,
        ),
        scan_variables=(legacy_scan_variable,),
    )

    monkeypatch.setattr(
        structure_form,
        "_prepare_scan_cfunc",
        lambda _ea: SimpleNamespace(entry_ea=0x401000, treeitems=[], eamap={}, body=None),
    )

    captured = {}

    class FakeVisitor:
        def __init__(self, cfunc, origin, obj, structure, recurse_calls=False):
            captured["args"] = (
                cfunc.entry_ea,
                origin,
                getattr(obj, "name", None),
                getattr(obj, "ea", None),
                getattr(obj, "id", None),
                getattr(obj, "lvar", None),
                structure.name,
                recurse_calls,
            )

        def process(self):
            return None

    monkeypatch.setattr(form_module, "NewDeepScanVisitor", FakeVisitor)

    assert structure_form._execute_child_scan_plan(child, plan) is True
    assert captured["args"][0:4] == (0x401000, 0x30, "child_ptr", 0x402000)
    assert captured["args"][4] == import_module("forge.api.scan_object").ObjectType.structure_reference
    assert captured["args"][5] is None
    assert captured["args"][6:] == ("Child", True)

def test_execute_child_scan_plan_prefers_inferred_child_roots(monkeypatch):
    structure_form = _make_form(monkeypatch)
    child = structure_form.create_structure("Child")
    assert child is not None
    child.main_offset = 0x30

    inferred_root = SimpleNamespace(name="child_var", ea=0x500123, func_ea=0x402000)
    plan = SimpleNamespace(
        function_eas=(0x401000,),
        scan_object=SimpleNamespace(name="child_ptr", id="member"),
        scan_variables=(SimpleNamespace(func_ea=0x401000, ea=0x402000),),
    )

    monkeypatch.setattr(
        structure_form,
        "_prepare_scan_cfunc",
        lambda ea: SimpleNamespace(entry_ea=ea),
    )
    monkeypatch.setattr(
        structure_form,
        "_infer_child_scan_roots",
        lambda cfunc, scan_object: (inferred_root,),
    )

    captured = {}

    class FakeVisitor:
        def __init__(self, cfunc, origin, obj, structure, recurse_calls=False):
            captured["args"] = (
                cfunc.entry_ea,
                origin,
                obj.name,
                obj.ea,
                structure.name,
                recurse_calls,
            )

        def process(self):
            return None

    monkeypatch.setattr(form_module, "NewDeepScanVisitor", FakeVisitor)

    assert structure_form._execute_child_scan_plan(child, plan) is True
    assert captured["args"] == (0x402000, 0x30, "child_var", 0x500123, "Child", True)









def test_build_child_scan_inference_seed_recovers_descendant_parent_member_anchors(
    monkeypatch,
 ):
    structure_form = _make_form(monkeypatch)
    offset_10 = _make_descendant_member_evidence(
        0x10, 4, evidence_ea=0x401030, anchor_ea=0x401020, parent_ea=0x401010
    )
    offset_18 = _make_descendant_member_evidence(
        0x18, 0x10, evidence_ea=0x401130, anchor_ea=0x401120, parent_ea=0x401110
    )
    parent_10 = SimpleNamespace(name="v1_parent")
    parent_18 = SimpleNamespace(name="v0_parent")

    monkeypatch.setattr(
        child_scan_module.ChildScanMixin,
        "_create_scan_object_from_expr",
        classmethod(
            lambda cls, _cfunc, expr: (
                parent_10
                if expr is offset_10.parent_expr
                else parent_18 if expr is offset_18.parent_expr else None
            )
        ),
    )

    seed_10 = structure_form._build_child_scan_inference_seed(
        offset_10.cfunc,
        SimpleNamespace(offset=0x10, ea=offset_10.descendant_expr.ea, name="field_10"),
    )
    seed_18 = structure_form._build_child_scan_inference_seed(
        offset_18.cfunc,
        SimpleNamespace(offset=0x18, ea=offset_18.descendant_expr.ea, name="field_18"),
    )

    assert seed_10 is not None
    assert seed_18 is not None
    assert seed_10.parent_object is parent_10
    assert seed_18.parent_object is parent_18
    assert seed_10.evidence_ea == offset_10.anchor_expr.ea
    assert seed_18.evidence_ea == offset_18.anchor_expr.ea
    assert seed_10.scan_object.ea == offset_10.anchor_expr.ea
    assert seed_18.scan_object.ea == offset_18.anchor_expr.ea


def test_infer_child_scan_roots_recovers_descendant_seed_before_walking_callers(
    monkeypatch,
 ):
    structure_form = _make_form(monkeypatch)
    evidence = _make_descendant_member_evidence(0x10, 4)
    scan_object = SimpleNamespace(
        offset=0x10,
        ea=evidence.descendant_expr.ea,
        name="child_ptr",
    )
    parent_object = SimpleNamespace(
        id=import_module("forge.api.scan_object").ObjectType.local_variable,
        index=0,
        lvar=SimpleNamespace(is_arg_var=True),
        name="a1",
    )
    caller_seed = child_scan_module.ChildScanInferenceSeed(
        function_ea=0x400800,
        evidence_ea=0x400880,
        scan_object=scan_object,
        parent_object=SimpleNamespace(name="caller_parent"),
        caller_path=(0x401000,),
    )
    inferred_root = SimpleNamespace(name="child_var", ea=0x500123, func_ea=0x400800)
    caller_candidate = child_scan_module.ChildScanRootCandidate(
        function_ea=0x400800,
        evidence_ea=0x4008A0,
        root=inferred_root,
        caller_path=(0x401000,),
    )
    caller_cfunc = SimpleNamespace(entry_ea=0x400800)
    seen = []

    monkeypatch.setattr(
        child_scan_module.ChildScanMixin,
        "_create_scan_object_from_expr",
        classmethod(
            lambda cls, _cfunc, expr: parent_object if expr is evidence.parent_expr else None
        ),
    )

    def fake_infer_direct(cfunc, seed):
        seen.append((cfunc.entry_ea, seed.parent_object, seed.evidence_ea))
        if cfunc.entry_ea == evidence.cfunc.entry_ea:
            assert seed.parent_object is parent_object
            assert seed.evidence_ea == evidence.anchor_expr.ea
            return ()
        assert seed is caller_seed
        return (caller_candidate,)

    monkeypatch.setattr(structure_form, "_infer_direct_child_roots", fake_infer_direct)
    monkeypatch.setattr(
        structure_form,
        "_propagate_child_scan_seed",
        lambda cfunc, seed: (caller_seed,) if seed.parent_object is parent_object else (),
    )
    monkeypatch.setattr(
        structure_form,
        "_prepare_scan_cfunc",
        lambda ea: caller_cfunc if ea == 0x400800 else None,
    )

    roots = structure_form._infer_child_scan_roots(evidence.cfunc, scan_object)

    assert roots == (inferred_root,)
    assert seen == [
        (0x401000, parent_object, evidence.anchor_expr.ea),
        (0x400800, caller_seed.parent_object, 0x400880),
    ]


def test_infer_child_scan_roots_walks_callers_for_assignment_sources(monkeypatch):
    structure_form = _make_form(monkeypatch)
    scan_object = SimpleNamespace(offset=0x18, name="child_ptr")
    initial_seed = child_scan_module.ChildScanInferenceSeed(
        function_ea=0x401000,
        evidence_ea=0x402000,
        scan_object=scan_object,
        parent_object=SimpleNamespace(name="arg_parent"),
    )
    caller_seed = child_scan_module.ChildScanInferenceSeed(
        function_ea=0x400800,
        evidence_ea=0x400880,
        scan_object=scan_object,
        parent_object=SimpleNamespace(name="caller_parent"),
        caller_path=(0x401000,),
    )
    inferred_root = SimpleNamespace(name="child_var", ea=0x500123, func_ea=0x400800)
    caller_candidate = child_scan_module.ChildScanRootCandidate(
        function_ea=0x400800,
        evidence_ea=0x4008A0,
        root=inferred_root,
        caller_path=(0x401000,),
    )
    callee_cfunc = SimpleNamespace(entry_ea=0x401000)
    caller_cfunc = SimpleNamespace(entry_ea=0x400800)
    seen = []

    monkeypatch.setattr(
        structure_form,
        "_build_child_scan_inference_seed",
        lambda cfunc, _scan_object, **_kwargs: initial_seed,
    )

    def fake_infer_direct(cfunc, seed):
        seen.append((cfunc.entry_ea, seed.function_ea))
        if cfunc.entry_ea == 0x401000:
            return ()
        return (caller_candidate,)

    monkeypatch.setattr(structure_form, "_infer_direct_child_roots", fake_infer_direct)
    monkeypatch.setattr(
        structure_form,
        "_propagate_child_scan_seed",
        lambda cfunc, seed: (caller_seed,) if seed is initial_seed else (),
    )
    monkeypatch.setattr(
        structure_form,
        "_prepare_scan_cfunc",
        lambda ea: caller_cfunc if ea == 0x400800 else None,
    )

    roots = structure_form._infer_child_scan_roots(callee_cfunc, scan_object)

    assert roots == (inferred_root,)
    assert seen == [(0x401000, 0x401000), (0x400800, 0x400800)]


def test_infer_direct_child_roots_matches_pointer_arithmetic_assignment(monkeypatch):
    structure_form = _make_form(monkeypatch)
    ctype = child_scan_module.ctype
    monkeypatch.setattr(child_scan_module.ctype, "ptr", "ptr", raising=False)
    monkeypatch.setattr(child_scan_module.ctype, "asg", "asg", raising=False)
    parent_expr = SimpleNamespace(op=ctype.var, ea=0x401050)
    rhs_expr = SimpleNamespace(op=ctype.var, ea=0x401060)
    index_expr = SimpleNamespace(op=ctype.num, numval=lambda: 3)
    idx_expr = SimpleNamespace(
        op=ctype.idx,
        x=SimpleNamespace(op=ctype.cast, x=parent_expr),
        y=index_expr,
        type=SimpleNamespace(get_ptrarr_objsize=lambda: 8),
    )
    lhs_expr = SimpleNamespace(
        op=ctype.ptr,
        x=idx_expr,
        type=SimpleNamespace(get_ptrarr_objsize=lambda: 8),
    )
    assignment = SimpleNamespace(op=ctype.asg, x=lhs_expr, y=rhs_expr, ea=0x401070)
    cfunc = SimpleNamespace(entry_ea=0x401000, treeitems=[assignment])
    parent_object = SimpleNamespace(name="parent")
    root_object = SimpleNamespace(name="child_var", ea=0x500123, func_ea=0x401000)
    seed = child_scan_module.ChildScanInferenceSeed(
        function_ea=0x401000,
        evidence_ea=0x402000,
        scan_object=SimpleNamespace(offset=24),
        parent_object=parent_object,
    )

    monkeypatch.setattr(
        child_scan_module.ChildScanMixin,
        "_scan_object_matches_expr",
        staticmethod(lambda obj, expr: obj is parent_object and expr is parent_expr),
    )
    monkeypatch.setattr(
        child_scan_module.ChildScanMixin,
        "_create_scan_object_from_expr",
        classmethod(lambda cls, _cfunc, expr: root_object if expr is rhs_expr else None),
    )

    candidates = structure_form._infer_direct_child_roots(cfunc, seed)

    assert len(candidates) == 1
    assert candidates[0].root is root_object
    assert candidates[0].function_ea == 0x401000


def test_create_scan_object_from_expr_unwraps_casted_offset_expression(monkeypatch):
    ctype = child_scan_module.ctype
    cfunc = SimpleNamespace(entry_ea=0x401000)
    base_expr = SimpleNamespace(op=ctype.var, ea=0x401020)
    offset_expr = SimpleNamespace(op=ctype.num, numval=lambda: 0x20)
    wrapped_expr = SimpleNamespace(
        op=ctype.cast,
        x=SimpleNamespace(op=ctype.add, x=base_expr, y=offset_expr),
    )
    base_object = SimpleNamespace(name="child_base")
    derived_object = SimpleNamespace(name="child_offset")

    monkeypatch.setattr(
        child_scan_module.ScanObject,
        "create",
        staticmethod(lambda _cfunc, expr: base_object if expr is base_expr else None),
    )
    monkeypatch.setattr(
        child_scan_module,
        "_make_offset_scan_object",
        lambda obj, offset: derived_object if obj is base_object and offset == 0x20 else None,
    )

    result = child_scan_module.ChildScanMixin._create_scan_object_from_expr(cfunc, wrapped_expr)

    assert result is derived_object
    assert result.func_ea == 0x401000


def test_execute_child_scan_plan_falls_back_to_seeded_member_when_inference_fails(monkeypatch):
    structure_form = _make_form(monkeypatch)
    child = structure_form.create_structure("Child")
    assert child is not None
    child.main_offset = 0x30

    plan = SimpleNamespace(
        function_eas=(0x401000,),
        scan_object=SimpleNamespace(name="child_ptr", id="member"),
        scan_variables=(SimpleNamespace(func_ea=0x401000, ea=0x402000),),
    )
    warnings = []

    monkeypatch.setattr(
        structure_form,
        "_prepare_scan_cfunc",
        lambda ea: SimpleNamespace(entry_ea=ea),
    )
    monkeypatch.setattr(
        structure_form,
        "_infer_child_scan_roots",
        lambda cfunc, scan_object: (),
    )
    monkeypatch.setattr(
        child_scan_module,
        "log_warning",
        lambda message=None, display_messagebox=False: warnings.append((message, display_messagebox)),
    )

    captured = {}

    class FakeVisitor:
        def __init__(self, cfunc, origin, obj, structure, recurse_calls=False):
            captured["args"] = (
                cfunc.entry_ea,
                origin,
                obj.name,
                obj.ea,
                structure.name,
                recurse_calls,
            )

        def process(self):
            return None

    monkeypatch.setattr(form_module, "NewDeepScanVisitor", FakeVisitor)

    assert structure_form._execute_child_scan_plan(child, plan) is True
    assert captured["args"] == (0x401000, 0x30, "child_ptr", 0x402000, "Child", True)
    assert any(
        "fell back to seeded member evidence" in message
        for message, _display in warnings
        if message is not None
    )



def test_scan_child_structure_uses_absolute_member_origin(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(0xCD8, 8, type_name="u64", name="child_ptr", origin=0x30)
    member.tinfo = SimpleNamespace(is_ptr=lambda: False, is_udt=lambda: False)
    member.scanned_variables = [SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root")]
    structure_form.current_structure = parent
    monkeypatch.setattr(form_module, "is_legal_type", lambda _tinfo: True)

    plan = form_module.ChildScanPlan(
        scan_object=SimpleNamespace(name="child_ptr"),
        function_eas=(0x401000,),
        relation_kind="embedded",
        root_object_name="Parent.child_ptr",
        root_object_ea=0x402000,
        root_function_ea=0x401000,
        has_multiple_roots=False,
    )
    monkeypatch.setattr(structure_form, "get_selected_member", lambda: member)
    monkeypatch.setattr(structure_form, "_build_child_scan_plan", lambda _member, show_warnings=False: plan)
    def fake_execute(child_structure, _plan):
        child_structure.add_member(_FakeMember(0, 4, type_name="u32", name="value"))
        return True

    monkeypatch.setattr(structure_form, "_execute_child_scan_plan", fake_execute)

    structure_form.scan_child_structure()

    child = structure_form.structures["auto_struct_001"]
    assert child.main_offset == 0xD08



def test_link_child_structure_materializes_pointer_and_inline_member_types(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure("Child")
    assert parent is not None
    assert child is not None
    child.created_type_name = "ChildType"

    member_pointer = _FakeMember(0x30, 8, type_name="u64", name="child_ptr")
    member_inline = _FakeMember(0x40, 8, type_name="u64", name="child_inline")

    parent.add_member(member_pointer)
    parent.add_member(member_inline)

    sentinel = SimpleNamespace(
        dstr=lambda: "ChildType",
        get_size=lambda: 8,
        is_funcptr=lambda: False,
    )
    seen: list[tuple[str, str, str]] = []

    def fake_materialize(member, child_type_name, relation_kind):
        seen.append((member.name, child_type_name, relation_kind))
        member.tinfo = sentinel
        return True

    monkeypatch.setattr(
        child_scan_module,
        "materialize_linked_child_member_type",
        fake_materialize,
    )

    form_module.StructureBuilderForm._link_child_structure(parent, child, member_pointer, "pointer")
    form_module.StructureBuilderForm._link_child_structure(parent, child, member_inline, "embedded")

    assert ("child_ptr", "ChildType", "pointer") in seen
    assert ("child_inline", "ChildType", "embedded") in seen
    assert member_pointer.tinfo is sentinel
    assert member_inline.tinfo is sentinel
    assert member_pointer.child_relation_kind == "pointer"
    assert member_inline.child_relation_kind == "embedded"


def test_link_child_structure_defers_materialization_for_untyped_auto_child(
    monkeypatch,
 ):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure(" ")
    assert parent is not None
    assert child is not None

    member = _FakeMember(0x30, 8, type_name="u64", name="child_ptr")
    original_tinfo = SimpleNamespace(
        dstr=lambda: "u64",
        get_size=lambda: 8,
        is_funcptr=lambda: False,
    )
    member.tinfo = original_tinfo
    parent.add_member(member)
    seen = []

    monkeypatch.setattr(
        child_scan_module,
        "materialize_linked_child_member_type",
        lambda *_args: seen.append(_args) or True,
    )

    form_module.StructureBuilderForm._link_child_structure(parent, child, member, "pointer")

    assert seen == []
    assert member.tinfo is original_tinfo
    assert member.linked_child_structure_name == child.name
    assert member.child_relation_kind == "pointer"


def test_refresh_all_linked_member_types_materializes_deferred_child_links(
    monkeypatch,
 ):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure("Child")
    assert parent is not None
    assert child is not None
    child.created_type_name = "ChildType"

    member = _FakeMember(0x30, 8, type_name="u64", name="child_ptr")
    original_tinfo = SimpleNamespace(
        dstr=lambda: "u64",
        get_size=lambda: 8,
        is_funcptr=lambda: False,
    )
    sentinel = SimpleNamespace(
        dstr=lambda: "ChildType",
        get_size=lambda: 8,
        is_funcptr=lambda: False,
    )
    member.tinfo = original_tinfo
    parent.add_member(member)
    relationship = parent.add_child_relationship(
        child_structure_name="Child",
        parent_member_offset=0x30,
        parent_member_name="child_ptr",
        relation_kind="pointer",
    )
    child.add_parent_relationship(relationship)
    member.linked_child_structure_name = "Child"
    member.child_relation_kind = "pointer"
    seen = []

    def fake_materialize(member, child_type_name, relation_kind):
        seen.append((member.name, child_type_name, relation_kind))
        member.tinfo = sentinel
        return True

    monkeypatch.setattr(
        structure_module,
        "materialize_linked_child_member_type",
        fake_materialize,
    )

    structure_form._refresh_all_linked_member_types()

    assert seen == [("child_ptr", "ChildType", "pointer")]
    assert member.tinfo is sentinel
