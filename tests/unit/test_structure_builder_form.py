from __future__ import annotations

from importlib import import_module
from types import SimpleNamespace

from forge.api.structure import Structure

hexrays_api = import_module("forge.api.hexrays")
scanner_api = import_module("forge.api.scanner")
setattr(hexrays_api, "get_funcs_referencing_address", lambda *_args, **_kwargs: [])
setattr(hexrays_api, "is_legal_type", lambda *_args, **_kwargs: True)
setattr(scanner_api, "NewShallowScanVisitor", type("NewShallowScanVisitor", (), {}))

form_module = import_module("forge.features.structure_builder.form")
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
    monkeypatch.setattr(structure_form, "_update_inspector_panel", lambda: None)
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
    assert child.provenance.kind == "child_scan"


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
    monkeypatch.setattr(structure_form, "_update_inspector_panel", lambda: None)
    monkeypatch.setattr(
        structure_form,
        "update_action_states",
        form_module.StructureBuilderForm.update_action_states.__get__(structure_form),
    )

    structure_form.update_action_states()

    assert structure_form.ui.btn_scan_child.enabled is True
    assert structure_form.ui.action_scan_child.enabled is True
    assert "child scan ready" in structure_form._format_selected_member_info(member)

