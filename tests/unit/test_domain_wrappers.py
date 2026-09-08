from types import SimpleNamespace

import pytest

from forge.api import domain


def test_function_wrappers_use_documented_namespace_methods():
    calls = []

    class Functions:
        def get_at(self, ea):
            calls.append(("get_at", ea))
            return "function"

        def get_name(self, function):
            calls.append(("get_name", function))
            return "named"

    database = SimpleNamespace(functions=Functions())
    assert domain.function_at(database, 0x401000) == "function"
    assert domain.function_name(database, "function") == "named"
    assert calls == [("get_at", 0x401000), ("get_name", "function")]


def test_type_and_declaration_wrappers_preserve_arguments():
    calls = []

    class Types:
        def get_by_name(self, name):
            calls.append(("get_by_name", name))
            return "type"

        def parse_one_declaration(self, *args):
            calls.append(("parse_one_declaration", args))
            return "tinfo"

        def apply_declaration_at(self, *args):
            calls.append(("apply_declaration_at", args))
            return True

    database = SimpleNamespace(types=Types())
    assert domain.type_by_name(database, "Node") == "type"
    assert domain.parse_declaration(database, "int x;") == "tinfo"
    assert domain.parse_declaration(database, "int x;", name="x") == "tinfo"
    assert domain.apply_declaration(database, 0x401000, "int x;") is True
    assert domain.apply_declaration(database, 0x401000, "int x;", flags=7) is True
    assert calls == [
        ("get_by_name", "Node"),
        ("parse_one_declaration", (None, "int x;", None)),
        ("parse_one_declaration", (None, "int x;", "x")),
        ("apply_declaration_at", (0x401000, "int x;")),
        ("apply_declaration_at", (0x401000, "int x;", 7)),
    ]

def test_parse_declaration_records_missing_domain_capability():
    domain.clear_fallback_records()

    with pytest.raises(domain.DomainUnavailable):
        domain.parse_declaration(SimpleNamespace(types=SimpleNamespace()), "int x;")

    assert domain.fallback_records() == (
        domain.SdkFallback(
            "types.parse_one_declaration",
            "ida-domain types handler lacks parse_one_declaration",
        ),
    )

@pytest.mark.parametrize(
    ("invoke", "capability", "reason", "message"),
    [
        (
            lambda db: domain.function_at(db, 0x401000),
            "functions.get_at",
            "ida-domain functions handler lacks get_at",
            "db.functions.get_at",
        ),
        (
            lambda db: domain.function_name(db, 0x401000),
            "functions.get_name",
            "ida-domain functions handler lacks get_name",
            "db.functions.get_name",
        ),
        (
            lambda db: domain.decompile(db, 0x401000),
            "pseudocode.decompile",
            "ida-domain pseudocode handler lacks decompile",
            "db.pseudocode.decompile",
        ),
        (
            lambda db: domain.type_by_name(db, "Node"),
            "types.get_by_name",
            "ida-domain types handler lacks get_by_name",
            "db.types.get_by_name",
        ),
        (
            lambda db: domain.parse_declaration(db, "int x;"),
            "types.parse_one_declaration",
            "ida-domain types handler lacks parse_one_declaration",
            "db.types.parse_one_declaration",
        ),
        (
            lambda db: domain.apply_declaration(db, 0x401000, "int x;"),
            "types.apply_declaration_at",
            "ida-domain types handler lacks apply_declaration_at",
            "db.types.apply_declaration_at",
        ),
    ],
)
def test_strict_wrappers_record_missing_capability(invoke, capability, reason, message):
    domain.clear_fallback_records()

    with pytest.raises(domain.DomainUnavailable, match=message):
        invoke(SimpleNamespace())

    assert domain.fallback_records() == (domain.SdkFallback(capability, reason),)


def test_decompile_result_extracts_lvars_and_object_calls():
    variable = SimpleNamespace(name="arg0", type_info=SimpleNamespace(dstr=lambda: "int"), is_arg=True)
    call = SimpleNamespace(x=SimpleNamespace(is_object=True, obj_ea=0x402000))
    function = SimpleNamespace(
        to_text=lambda remove_tags: ["int f()", "{"],
        local_variables=[variable],
        find_calls=lambda: [call],
    )
    database = SimpleNamespace(pseudocode=SimpleNamespace(decompile=lambda _ea: function))

    assert domain.decompile_result(database, 0x401000) == {
        "ea": 0x401000,
        "name": None,
        "pseudocode": "int f()\n{",
        "lvars": [{"index": 0, "name": "arg0", "type": "int", "is_arg": True}],
        "calls": [0x402000],
    }
