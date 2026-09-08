"""Focused contracts for C++ recovery and pointer-flow facade APIs."""

from __future__ import annotations

from types import SimpleNamespace

import forge.api.members as members_api
import forge_api


class _PlanTinfo:
    def __init__(self, name="u32"):
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

    def equals_to(self, other):
        return self.dstr() == getattr(other, "dstr", lambda: "")()


def _plan_parse(_declaration):
    return _PlanTinfo()


def _install_plan_tinfo(monkeypatch):
    monkeypatch.setattr(members_api, "parse_user_tinfo", _plan_parse)

def test_recover_pointer_flow_forwards_replace_and_marks_verified(monkeypatch):
    calls = []

    def fake_set_lvar_types(ea, types, *, scope, replace):
        calls.append((ea, types, scope, replace))
        return {"ok": True, "updated": [{"name": "world", "ok": True}]}

    monkeypatch.setattr(forge_api, "set_lvar_types", fake_set_lvar_types)

    result = forge_api.recover_pointer_flow(
        0x140002750, {"world": "fixture_World *"}
    )

    assert result == {
        "ok": True,
        "updated": [{"name": "world", "ok": True}],
        "ea": 0x140002750,
        "verified": True,
    }
    assert calls == [
        (0x140002750, {"world": "fixture_World *"}, "all", True)
    ]


def test_recover_pointer_flow_marks_failed_application_unverified(monkeypatch):
    monkeypatch.setattr(
        forge_api,
        "set_lvar_types",
        lambda *args, **kwargs: {"ok": False, "error": "no lvar"},
    )

    result = forge_api.recover_pointer_flow(0x401000, {"arg": "Node *"})

    assert result == {
        "ok": False,
        "error": "no lvar",
        "ea": 0x401000,
        "verified": False,
    }


def test_synthesize_cpp_records_roots_and_provenance(monkeypatch):
    target = SimpleNamespace(
        provenance=SimpleNamespace(
            __dict__={"kind": "manual"},
            roots=[],
        ),
        set_provenance=lambda **kwargs: target.provenance.__dict__.update(kwargs),
    )
    monkeypatch.setattr(
        forge_api,
        "recover_abi_structure",
        lambda *args, **kwargs: {"ok": True, "structure": "Player"},
    )
    monkeypatch.setattr(forge_api, "_resolve_structure", lambda _name: target)
    monkeypatch.setattr(forge_api, "_mark_dirty", lambda: None)

    result = forge_api.synthesize_cpp(
        "Player",
        [{"offset": 0, "type": "u32", "name": "id"}],
        abi={"rtti_name": "fixture_Player"},
        roots=[
            {"object_ea": 0x14001000, "function_ea": 0x140002750},
            {"object_ea": 0x14002000, "function_ea": 0x140003BC0},
        ],
        commit=False,
    )

    assert result["ok"] is True
    assert result["provenance"]["kind"] == "cpp_synthesis"
    assert result["provenance"]["root_object_ea"] == 0x14001000
    assert result["provenance"]["root_function_ea"] == 0x140002750
    assert result["provenance"]["has_multiple_roots"] is True
    assert result["provenance"]["roots"] == [
        {"object_ea": 0x14001000, "function_ea": 0x140002750},
        {"object_ea": 0x14002000, "function_ea": 0x140003BC0},
    ]


def test_name_cpp_evidence_names_vptr_and_abi_slots(monkeypatch):
    renamed = []
    member = SimpleNamespace(name="field_0", offset=0, vtable_name="Player_vtbl")
    target = SimpleNamespace(
        members=[member],
        abi_metadata={
            "vtables": [
                {"slots": [{"ea": 0x1400055F8, "name": "Player_update"}]}
            ]
        },
    )
    monkeypatch.setattr(forge_api, "_resolve_structure", lambda _name: target)
    monkeypatch.setattr(
        forge_api,
        "rename_ea",
        lambda ea, name, **kwargs: renamed.append((ea, name)) or {"ok": True},
    )
    monkeypatch.setattr(forge_api, "_mark_dirty", lambda: None)

    result = forge_api.name_cpp_evidence("Player")

    assert result == {
        "ok": True,
        "structure": "Player",
        "renamed": [{"offset": 0, "name": "vptr"}],
    }
    assert renamed == [(0x1400055F8, "Player_update")]


def test_discover_global_slots_filters_invalid_span_and_writable_segments(monkeypatch):
    import ida_bytes
    import ida_segment
    monkeypatch.setattr(ida_segment, "SEGPERM_WRITE", 2, raising=False)
    class Segment:
        def __init__(self, start, end, perm):
            self.start_ea = start
            self.end_ea = end
            self.perm = perm

    WRITE = 2
    segments = [
        Segment(0x14001000, 0x14001018, WRITE),
        Segment(0x14002000, 0x14002010, 0),
    ]
    values = {
        0x14001000: 0x14003000,
        0x14001008: 0x14003000,
        0x14002000: 0x14003000,
    }
    monkeypatch.setattr(forge_api, "_require_ida", lambda: None)
    monkeypatch.setattr(ida_segment, "get_segm_qty", lambda: len(segments), raising=False)
    monkeypatch.setattr(ida_segment, "getnseg", lambda index: segments[index], raising=False)
    monkeypatch.setattr(ida_bytes, "get_qword", lambda ea: values.get(ea, 0), raising=False)

    result = forge_api.discover_global_slots(0x14003000, span=16)

    assert result == {
        "ok": True,
        "target_ea": 0x14003000,
        "candidates": [
            {"slot_ea": 0x14001000, "target_ea": 0x14003000, "span": 16},
            {"slot_ea": 0x14001008, "target_ea": 0x14003000, "span": 16},
        ],
    }

def test_plan_structure_is_detached_and_does_not_mutate_catalog(monkeypatch):
    _install_plan_tinfo(monkeypatch)
    monkeypatch.setattr(
        forge_api,
        "_to_member_dict",
        lambda member: {"offset": member.offset, "name": member.name, "type": "u32"},
    )
    monkeypatch.setattr(
        forge_api,
        "_member_type_str",
        lambda _member: "u32",
    )
    monkeypatch.setattr(forge_api, "_validate_pack", lambda _pack: None)

    before = dict(forge_api._structures)
    result = forge_api.plan_structure(
        "Planned",
        [{"offset": 0, "type": "u32", "name": "id"}],
    )

    assert result["ok"] is True
    assert result["name"] == "Planned"
    assert result["members"] == [{"offset": 0, "name": "id", "type": "u32"}]
    assert dict(forge_api._structures) == before


def test_plan_structure_returns_structured_validation_errors(monkeypatch):
    _install_plan_tinfo(monkeypatch)
    result = forge_api.plan_structure(
        "BadPlan",
        [{"offset": 0, "type": "u32"}, {"offset": 0, "type": "u64"}],
    )

    assert result["ok"] is False
    assert "duplicate member offset" in result["error"]
