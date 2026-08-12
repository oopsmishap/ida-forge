"""Behavior tests for the flat, self-describing forge_api facade."""

from __future__ import annotations

import json

import pytest

import forge.api.members as members_mod
import forge_api


class FakeTinfo:
    """Minimal tinfo double that Member construction + display can use."""

    def __init__(self, name, size=4):
        self._name = name
        self._size = size

    def dstr(self):
        return self._name

    def get_size(self):
        return self._size

    def is_floating(self):
        return False

    def is_integral(self):
        return True

    def is_signed(self):
        return False

    def equals_to(self, other):
        return self.dstr() == getattr(other, "dstr", lambda: "")()

    def create_ptr(self, *args, **kwargs):
        return True


@pytest.fixture(autouse=True)
def _stub_member_tinfo(monkeypatch):
    """Route parse_user_tinfo -> FakeTinfo so members build without IDA."""

    def _fake_parse(declaration):
        name = (declaration or "u32").split()[0]
        return FakeTinfo(name)

    monkeypatch.setattr(members_mod, "parse_user_tinfo", _fake_parse)


@pytest.fixture(autouse=True)
def _reset_store():
    forge_api.clear_structures()
    yield
    forge_api.clear_structures()


def test_help_catalog_lists_every_api_function():
    catalog = forge_api.help()
    functions = catalog["functions"]
    assert set(functions) == set(forge_api.__all__)
    for entry in functions.values():
        assert entry["signature"]
        assert isinstance(entry["params"], list)
        assert entry["returns"]
        assert entry["example"]
        assert entry["group"]


def test_help_topic_scoped():
    entry = forge_api.help("deep_scan")["functions"]["deep_scan"]
    assert entry["group"] == "scan"
    with pytest.raises(forge_api.ForgeApiError):
        forge_api.help("does_not_exist")


def test_requires_ida_guard(monkeypatch):
    monkeypatch.setattr(forge_api, "_ida_available", lambda: False)
    with pytest.raises(forge_api.ForgeApiError, match="requires an IDA Pro session"):
        forge_api.decompile(1)


def test_to_hex_is_pure():
    assert forge_api.to_hex(0x401000) == "0x401000"


def test_store_create_and_members():
    forge_api.create_structure("S1")
    member = forge_api.add_member("S1", 0x10, "u32", name="count")
    assert member["offset"] == 0x10
    assert member["name"] == "count"
    assert member["type"] == "u32"
    assert member["size"] == 4
    assert member["enabled"] is True

    structure = forge_api.get_structure("S1")
    assert structure["name"] == "S1"
    assert len(structure["members"]) == 1

    # structure=None routes to the selected (current) structure
    assert forge_api.get_structure()["name"] == "S1"

    forge_api.add_member("S1", 0x18, "u64")
    assert len(forge_api.get_structure("S1")["members"]) == 2

    forge_api.remove_members("S1", [0x10])
    assert [m["offset"] for m in forge_api.get_structure("S1")["members"]] == [0x18]

    assert forge_api.remove_structure("S1") is True
    assert forge_api.structures() == []


def test_structure_duplicate_names():
    forge_api.create_structure("X")
    forge_api.create_structure("Y")
    # renaming onto an existing name fails without raising
    assert forge_api.rename_structure("X", "Y") is False
    # renaming to a free name works and drops the old key
    assert forge_api.rename_structure("X", "Z") is True
    assert "Z" in forge_api.structures()
    assert "X" not in forge_api.structures()

    first = forge_api.duplicate_structure("Z")
    second = forge_api.duplicate_structure("Z")
    assert first == "Z Copy"
    assert second == "Z Copy 2"


def test_create_type_guards_missing_members():
    forge_api.create_structure("EmptyStruct")
    result = forge_api.create_type("EmptyStruct")
    assert result["ok"] is False
    assert "error" in result


def test_api_returns_only_json_types():
    forge_api.create_structure("JsonSafe")
    forge_api.add_member("JsonSafe", 0x0, "u32", name="a")
    forge_api.add_member("JsonSafe", 0x4, "u64", name="b")
    serialized = json.dumps(forge_api.get_structure("JsonSafe"))
    data = json.loads(serialized)
    assert {m["name"] for m in data["members"]} == {"a", "b"}


def test_set_member_updates_fields_and_validates_offset():
    forge_api.create_structure("S")
    forge_api.add_member("S", 0x10, "u32", name="old")
    updated = forge_api.set_member(
        "S", 0x10, name="size", comment="the size", enabled=False
    )
    assert updated["name"] == "size"
    assert updated["comment"] == "the size"
    assert updated["enabled"] is False
    with pytest.raises(forge_api.ForgeApiError):
        forge_api.set_member("S", 0x20, name="nope")


def test_nudge_members_rejects_overlap_nondestructive():
    forge_api.create_structure("N")
    forge_api.add_member("N", 0x0, "u32")
    forge_api.add_member("N", 0x8, "u32")
    # A move that would collide with a non-moved member is rejected.
    result = forge_api.nudge_members("N", [0x0], 8)
    assert result["ok"] is False
    assert [m["offset"] for m in forge_api.get_structure("N")["members"]] == [0x0, 0x8]
    # A legal move lands and keeps the table non-overlapping.
    result = forge_api.nudge_members("N", [0x0], 4)
    assert result["ok"] is True
    assert [m["offset"] for m in forge_api.get_structure("N")["members"]] == [0x4, 0x8]
