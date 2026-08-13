"""Display-name canonicalization for member types (O2: i8-vs-char consistency)."""

import pytest

from forge.api.members import normalize_type_display


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