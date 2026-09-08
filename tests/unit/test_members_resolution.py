"""Dependency-aware authored-declaration resolution and provenance-safe
member merge (recovery-eval gaps #8/#9, 2026-08-30)."""

from __future__ import annotations

import pytest

from forge.api import members


class FakeTinfo:
    def __init__(self, name: str):
        self._name = name

    def dstr(self):
        return self._name

    def get_size(self):
        return 4

    def is_floating(self):
        return False

    def is_integral(self):
        return True

    def is_signed(self):
        return False

    def is_ptr(self):
        return False

    def is_funcptr(self):
        return False

    def is_udt(self):
        return False

    def is_void(self):
        return False

    def equals_to(self, other):
        return self.dstr() == getattr(other, "dstr", lambda: "")()


@pytest.fixture(autouse=True)
def _stub_parse(monkeypatch):
    """``parse_user_tinfo`` resolves plain scalars but fails on decls that
    name ``Uncommitted`` (or are malformed); ``named_type_exists`` agrees."""

    def fake_parse(declaration):
        declaration = (declaration or "").strip()
        if "Uncommitted" in declaration or "??" in declaration:
            return None
        return FakeTinfo(declaration or "u64")

    def fake_named_exists(name):
        return "Uncommitted" not in (name or "")

    monkeypatch.setattr(members, "parse_user_tinfo", fake_parse)
    monkeypatch.setattr(members, "named_type_exists", fake_named_exists)


def _member(decl=None, name=None, offset=0x10, tinfo_name="u64", scan="v1", origin=0):
    member = members.Member(
        offset, FakeTinfo(tinfo_name), scan, origin
    )
    if decl is not None:
        member.decl_src = decl
    if name is not None:
        member.name = name
    return member


# -- declaration_type_references ---------------------------------------------


def test_declaration_type_references_extracts_named_types():
    assert members.declaration_type_references("fixture_Quest *") == ["fixture_Quest"]


def test_declaration_type_references_skips_keywords_and_builtins():
    assert members.declaration_type_references("const char *") == []
    assert members.declaration_type_references("unsigned __int64") == []
    assert members.declaration_type_references("u32[16]") == []
    assert members.declaration_type_references("struct _DWORD *") == []


def test_declaration_type_references_function_pointer_shape():
    refs = members.declaration_type_references("int (__stdcall *)(World *, int)")
    assert refs == ["World"]


def test_declaration_type_references_pointer_declarator_excluded():
    # the identifiers after the stars name the declarator, never a type
    refs = members.declaration_type_references("Uncommitted_World *a1, *b2")
    assert refs == ["Uncommitted_World"]


def test_declaration_type_references_array_declarator_excluded():
    # the identifier directly preceding the subscript names the declarator,
    # never a type (reviewer nit: 'World players[8]' was ['World', 'players'])
    assert members.declaration_type_references("World players[8]") == ["World"]
    assert members.declaration_type_references(
        "Uncommitted_World players[8], extra[4]"
    ) == ["Uncommitted_World"]


def test_declaration_type_references_dedupes_and_orders():
    refs = members.declaration_type_references("B *, A *, B *")
    assert refs == ["B", "A"]


def test_declaration_type_references_empty_for_empty_decl():
    assert members.declaration_type_references(None) == []
    assert members.declaration_type_references("") == []


# -- resolve_member_pack_type -------------------------------------------------


def test_resolve_pack_type_resolved_from_authored_declaration():
    member = _member(decl="u32", name="count")
    resolution = members.resolve_member_pack_type(member)
    assert resolution.status == members.RESOLVED
    assert resolution.ok
    assert resolution.tinfo is not None
    assert resolution.error() is None


def test_resolve_pack_type_reports_unresolved_references():
    member = _member(decl="Uncommitted_Target *", name="next")
    resolution = members.resolve_member_pack_type(member)
    assert resolution.status == members.UNRESOLVED_REFERENCE
    assert not resolution.ok
    assert resolution.unresolved == ("Uncommitted_Target",)
    # the structured error names the member, the offset, and the missing type
    message = resolution.error()
    assert "next" in message and "0x10" in message and "Uncommitted_Target" in message
    # and it exposes the placeholder a silent pack would have degraded to
    assert resolution.degraded_tinfo is not None


def test_resolve_pack_type_malformed_when_every_reference_exists():
    member = _member(decl="u32 ?? ?? bogus", name="broken")
    resolution = members.resolve_member_pack_type(member)
    assert resolution.status == members.MALFORMED
    assert not resolution.ok
    assert resolution.unresolved == ()
    assert "malformed" in resolution.error()


def test_resolve_pack_type_stored_shape_without_authored_decl():
    member = _member(tinfo_name="u64")
    resolution = members.resolve_member_pack_type(member)
    assert resolution.status in (members.RESOLVED, members.STORED)
    assert resolution.ok


def test_resolve_pack_type_untyped_member():
    member = members.Member(0, None, None, 0)
    resolution = members.resolve_member_pack_type(member)
    assert resolution.status == members.UNTYPED
    # untyped members are skipped by build_cdecl, so they do not block
    assert resolution.ok


def test_to_dict_shape_round_trip():
    member = _member(decl="Uncommitted_Target *", name="next")
    payload = members.resolve_member_pack_type(member).to_dict()
    assert payload["status"] == "unresolved_reference"
    assert payload["unresolved"] == ["Uncommitted_Target"]
    assert payload["ok"] is False
    assert payload["offset"] == 0x10


# -- resolve_pack_readiness ---------------------------------------------------


def test_pack_readiness_ok_when_all_declarations_resolve():
    structure_members = [
        _member(decl="u32", name="a"),
        _member(decl="u64", name="b", offset=0x18),
    ]
    readiness = members.resolve_pack_readiness(structure_members, "S")
    assert readiness.ok
    assert readiness.error is None
    assert readiness.to_dict()["blocked"] == []


def test_pack_readiness_blocks_with_structured_error():
    structure_members = [
        _member(decl="u32", name="ok_field", offset=0),
        _member(decl="Uncommitted_A *", name="next", offset=8),
        _member(decl="Uncommitted_B", name="value", offset=0x10),
    ]
    readiness = members.resolve_pack_readiness(structure_members, "World")
    assert not readiness.ok
    assert {entry.unresolved[0] for entry in readiness.blocked} == {
        "Uncommitted_A",
        "Uncommitted_B",
    }
    payload = readiness.to_dict()
    assert payload["ok"] is False
    assert payload["structure"] == "World"
    assert set(payload["unresolved_types"]) == {"Uncommitted_A", "Uncommitted_B"}
    assert "World" in readiness.error and "Uncommitted_A" in readiness.error


def test_pack_readiness_skips_disabled_and_vtable_members(monkeypatch):
    class FakeVTable:
        pass

    monkeypatch.setattr(members, "VirtualTable", FakeVTable, raising=False)
    disabled = _member(decl="Uncommitted_X *", name="disabled")
    disabled.set_enabled(False)
    vtable = FakeVTable()
    readiness = members.resolve_pack_readiness([disabled, vtable], "S")
    assert readiness.ok
    assert readiness.entries == ()


# -- merge_member_evidence (gap #8) -------------------------------------------


def test_is_authored_member_distinguishes_scan_built():
    authored = _member(decl="u32", name="count")
    scan_built = _member()  # auto name u32_10, no decl_src
    assert members.is_authored_member(authored)
    assert not members.is_authored_member(scan_built)
    # a human name alone counts as authored even without decl_src
    assert members.is_authored_member(_member(name="score"))


def test_merge_preserves_authored_identity_and_merges_evidence():
    authored = _member(decl="Uncommitted_Later *", name="next", offset=0x78)
    authored.comment = "authored comment"
    scan_built = _member(offset=0x78, scan="v9", origin=3)
    scan_built.scanned_variables = {"v9", "v10"}

    merged = members.merge_member_evidence(authored, scan_built)

    assert merged is authored
    assert merged.decl_src == "Uncommitted_Later *"
    assert merged.name == "next"
    assert merged.comment == "authored comment"
    # scan evidence flows INTO the authored member
    assert merged.scanned_variables == {"v1", "v9", "v10"}


def test_merge_authored_incoming_wins_and_keeps_existing_evidence():
    scan_built = _member(offset=0x20, scan="v1")
    authored = _member(decl="Fixture *", name="world", offset=0x20, scan="v2")
    authored.scanned_variables = {"v2"}

    merged = members.merge_member_evidence(scan_built, authored)

    assert merged is authored
    assert merged.name == "world"
    assert merged.scanned_variables == {"v1", "v2"}


def test_merge_scan_vs_scan_keeps_higher_score_member():
    weak = _member(offset=0x40, scan="v1")
    strong = _member(offset=0x40, scan="v1", tinfo_name="u64")
    strong.scanned_variables = {"s1", "s2", "s3", "s4", "s5", "s6"}

    merged = members.merge_member_evidence(weak, strong)

    assert merged is strong
    assert weak.scanned_variables <= strong.scanned_variables


def test_merge_refuses_different_offsets():
    a = _member(offset=0)
    b = _member(offset=8)
    assert members.merge_member_evidence(a, b) is None


def test_merge_none_handling_and_identity():
    member = _member()
    assert members.merge_member_evidence(None, None) is None
    assert members.merge_member_evidence(None, member) is member
    assert members.merge_member_evidence(member, None) is member
    assert members.merge_member_evidence(member, member) is member


def test_merge_carries_link_metadata_to_survivor():
    authored = _member(decl="u32", name="head", offset=0)
    scan_built = _member(offset=0, scan="v1")
    scan_built.linked_child_structure_name = "Child"
    scan_built.child_relation_kind = "pointer"

    merged = members.merge_member_evidence(authored, scan_built)

    assert merged is authored
    assert merged.linked_child_structure_name == "Child"
    assert merged.child_relation_kind == "pointer"


def test_merge_does_not_override_survivor_link_metadata():
    authored = _member(decl="u32", name="head", offset=0)
    authored.linked_child_structure_name = "Mine"
    scan_built = _member(offset=0, scan="v1")
    scan_built.linked_child_structure_name = "Theirs"

    merged = members.merge_member_evidence(authored, scan_built)

    assert merged is authored
    assert merged.linked_child_structure_name == "Mine"


# -- linked member readiness (unmaterialized children must block) -------------


def test_pack_readiness_blocks_unmaterialized_linked_member():
    linked = members.LinkedStructureMember(0x10, "Uncommitted_Child", 12, "child")
    resolution = members.resolve_member_pack_type(linked)
    assert resolution.status == members.UNRESOLVED_REFERENCE
    assert not resolution.ok
    assert resolution.unresolved == ("Uncommitted_Child",)

    readiness = members.resolve_pack_readiness([linked], "Root")
    assert not readiness.ok
    payload = readiness.to_dict()
    assert payload["ok"] is False
    assert payload["unresolved_types"] == ["Uncommitted_Child"]
    # the blocked row names the member and the missing child type
    assert "child" in payload["blocked"][0]["error"]
    assert "Uncommitted_Child" in readiness.error


def test_pack_readiness_ok_for_materialized_linked_member():
    linked = members.LinkedStructureMember(0x10, "Child", 12, "child")
    linked.tinfo = FakeTinfo("Child *")
    resolution = members.resolve_member_pack_type(linked)
    assert resolution.ok
    assert resolution.tinfo is not None
    assert members.resolve_pack_readiness([linked], "Root").ok


# -- VirtualTable is scan evidence, never authored (gap #8 follow-up) ---------


def _vtable(offset=0x20, name="_vftable_0x140006128"):
    vtable = members.VirtualTable.__new__(members.VirtualTable)
    vtable.offset = offset
    vtable.name = name
    vtable.vtable_name = "Cls_vtbl"
    vtable.virtual_functions = []
    vtable.scanned_variables = set()
    return vtable


def test_is_authored_member_excludes_virtual_table():
    # the generated _vftable_ name does not match the auto-name regex, so a
    # vtable masqueraded as authored identity and won same-offset merges
    assert not members.is_authored_member(_vtable())
    # a linked member still classifies by its (authored) name
    assert members.is_authored_member(
        members.LinkedStructureMember(0x10, "Child", 12, "child")
    )


def test_merge_vtable_does_not_overwrite_authored_member():
    authored = _member(decl="Fixture_World *", name="world", offset=0x20)
    merged = members.merge_member_evidence(_vtable(), authored)
    assert merged is authored
    assert merged.name == "world"
    assert merged.decl_src == "Fixture_World *"
    # and the same collision with the vtable as incoming scan evidence
    merged = members.merge_member_evidence(authored, _vtable())
    assert merged is authored
    assert merged.name == "world"
