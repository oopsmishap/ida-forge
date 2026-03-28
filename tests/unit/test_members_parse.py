from __future__ import annotations

from forge.api import members


def test_normalize_type_declaration_rewrites_known_aliases():
    assert members.normalize_type_declaration("_DWORD *") == "u32 *"
    assert members.normalize_type_declaration("unsigned __int64") == "u64"
    assert members.normalize_type_declaration("  BOOL  ") == "bool"


def test_parse_user_tinfo_uses_parse_decl_attempts_before_fallbacks(monkeypatch):
    attempts = []
    sentinel = object()

    def fake_parse_decl_attempt(declaration: str):
        attempts.append(declaration)
        return None

    monkeypatch.setattr(members, "_parse_decl_attempt", fake_parse_decl_attempt)
    monkeypatch.setattr(members, "_parse_named_like_type", lambda declaration: sentinel)
    monkeypatch.setattr(
        members,
        "_parse_idc_decl_attempt",
        lambda declaration: (_ for _ in ()).throw(AssertionError("IDC fallback should not be used")),
    )

    result = members.parse_user_tinfo(" _DWORD * ")

    assert result is sentinel
    assert attempts == ["u32 *", "u32 *;", "u32 * __forge_member;"]


def test_parse_user_tinfo_falls_back_to_idc_parser(monkeypatch):
    parse_attempts = []
    idc_attempts = []
    sentinel = object()

    monkeypatch.setattr(
        members,
        "_parse_decl_attempt",
        lambda declaration: parse_attempts.append(declaration) or None,
    )
    monkeypatch.setattr(members, "_parse_named_like_type", lambda declaration: None)
    monkeypatch.setattr(
        members,
        "_parse_idc_decl_attempt",
        lambda declaration: idc_attempts.append(declaration) or (sentinel if declaration.endswith(";") else None),
    )

    result = members.parse_user_tinfo("BOOL")

    assert result is sentinel
    assert parse_attempts == ["bool", "bool;", "bool __forge_member;"]
    assert idc_attempts == ["bool", "bool;"]


def test_parse_named_like_type_routes_arrays_and_pointers(monkeypatch):
    array_calls = []
    pointer_calls = []
    array_sentinel = object()
    pointer_sentinel = object()

    monkeypatch.setattr(
        members,
        "_build_array_tinfo",
        lambda base, count: array_calls.append((base, count)) or array_sentinel,
    )
    monkeypatch.setattr(
        members,
        "_build_pointer_tinfo",
        lambda base, depth: pointer_calls.append((base, depth)) or pointer_sentinel,
    )

    assert members._parse_named_like_type("Widget[0x10]") is array_sentinel
    assert members._parse_named_like_type("Thing **") is pointer_sentinel
    assert array_calls == [("Widget", 16)]
    assert pointer_calls == [("Thing", 2)]


def test_parse_named_like_type_returns_named_type_when_available(monkeypatch):
    class FakeNamedType:
        def __init__(self):
            self.requested_name = None

        def get_named_type(self, _idati, name):
            self.requested_name = name
            return name == "MyType"

    monkeypatch.setattr(members.ida_typeinf, "tinfo_t", FakeNamedType)
    result = members._parse_named_like_type("MyType")

    assert isinstance(result, FakeNamedType)
    assert result.requested_name == "MyType"



def test_parse_named_like_type_returns_none_when_type_cannot_be_resolved(monkeypatch):
    class FakeNamedType:
        def get_named_type(self, _idati, name):
            return False

    monkeypatch.setattr(members.ida_typeinf, "tinfo_t", FakeNamedType)

    assert members._parse_named_like_type("DefinitelyMissing") is None



def test_parse_user_tinfo_returns_none_when_all_strategies_fail(monkeypatch):
    monkeypatch.setattr(members, "_parse_decl_attempt", lambda declaration: None)
    monkeypatch.setattr(members, "_parse_named_like_type", lambda declaration: None)
    monkeypatch.setattr(members, "_parse_idc_decl_attempt", lambda declaration: None)

    assert members.parse_user_tinfo("MissingType") is None



def test_normalize_type_declaration_does_not_replace_partial_identifier_matches():
    assert members.normalize_type_declaration("BYTECODE") == "BYTECODE"
    assert members.normalize_type_declaration("myDWORDValue") == "myDWORDValue"
