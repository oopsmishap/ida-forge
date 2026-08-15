"""Display-name canonicalization for member types (O2: i8-vs-char consistency)."""

import pytest

from forge.api.members import normalize_type_declaration, normalize_type_display


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("char", "char"),
        ("char *", "char *"),
        ("i8", "char"),
        ("i8 *", "char *"),
        ("signed char", "char"),
        ("signed char *", "char *"),
        ("__int8", "char"),
        ("__int8 *", "char *"),
        ("signed __int8 *", "char *"),
        ("signed __int8 [4]", "char [4]"),
        ("u8", "u8"),
        ("unsigned __int8 *", "unsigned __int8 *"),
        ("u32", "u32"),
        ("_QWORD", "_QWORD"),
        ("", ""),
    ],
)
def test_normalize_type_display_signed8_canonicalizes(raw, expected):
    assert normalize_type_display(raw) == expected


def test_normalize_type_display_pointer_and_array_suffixes_preserved():
    assert normalize_type_display("i8 *") == "char *"
    assert normalize_type_display("signed __int8 *[2]") == "char *[2]"
    assert normalize_type_display("u64 const *") == "u64 const *"


def test_parse_user_tinfo_unions_use_member_suffix_branch_first(monkeypatch):
    """E28: an inline union body parses via the ``<union> __forge_member;``
    branch FIRST (the bare braceless union form fails on IDA). This file
    has no autouse parse stub, so the real parse_user_tinfo runs."""
    import forge.api.members as members_mod

    seen = []

    def _fake_parse(attempt):
        seen.append(attempt)
        return object()  # any non-None tinfo

    monkeypatch.setattr(members_mod, "_parse_decl_attempt", _fake_parse, raising=False)

    tinfo = members_mod.parse_user_tinfo(
        "union { unsigned __int32 as_u32; int as_i32; }"
    )

    assert tinfo is not None
    assert len(seen) == 1
    assert seen[0] == "union { unsigned __int32 as_u32; int as_i32; } __forge_member;"


def test_parse_user_tinfo_normalize_keeps_intN_aliases():
    """R2.5/R3.2: the normalize step rewrites intN/uintN to native tokens
    before the parse attempts; unknown tokens survive untouched (parse
    then fails loudly)."""
    assert normalize_type_declaration("uint32 [4]") == "unsigned __int32 [4]"
    assert normalize_type_declaration("int16 *") == "__int16 *"