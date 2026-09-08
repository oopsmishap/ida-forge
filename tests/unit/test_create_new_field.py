"""Behavior tests for forge.features.create_new_field.parse_declaration."""

from __future__ import annotations

import pytest

from forge.features.create_new_field.create_new_field import CreateNewField


class _FakeTInfo:
    def __init__(self, *args, **kwargs):
        self.array_size = None

    def deserialize(self, til, tp, fld, errbuf):
        self.type_buf = tp

    def create_array(self, tinfo, size):
        self.array_size = size


@pytest.fixture
def _stubs(monkeypatch):
    import ida_typeinf

    module_ida = CreateNewField.__module__
    import importlib

    target = importlib.import_module(module_ida)

    # E1: parse_declaration parses via idc.parse_decl (ida_idaapi's
    # idc_parse_decl does not exist on IDA 9.4).
    monkeypatch.setattr(
        ida_typeinf,
        "tinfo_t",
        _FakeTInfo,
        raising=False,
    )
    return target


def test_parse_declaration_happy_path(_stubs, monkeypatch):
    monkeypatch.setattr(
        "idc.parse_decl",
        lambda decl, flags: _FakeTInfo(),
        raising=False,
    )
    tinfo, name = CreateNewField.parse_declaration("int my_field")
    assert name == "my_field"
    assert isinstance(tinfo, _FakeTInfo)


def test_parse_declaration_array_size(_stubs, monkeypatch):
    monkeypatch.setattr(
        "idc.parse_decl",
        lambda decl, flags: _FakeTInfo(),
        raising=False,
    )
    _tinfo, name = CreateNewField.parse_declaration("char buffer[16]")
    assert name == "buffer"
    assert _tinfo.array_size == 16


def test_parse_declaration_array_optional(_stubs, monkeypatch):
    monkeypatch.setattr(
        "idc.parse_decl",
        lambda decl, flags: _FakeTInfo(),
        raising=False,
    )
    _tinfo, name = CreateNewField.parse_declaration("char *pointer")
    assert name == "pointer"


def test_parse_declaration_rejects_garbage(_stubs):
    assert CreateNewField.parse_declaration("not a declaration!") == (None, None)


def test_parse_declaration_rejects_digit_leading_name(_stubs):
    assert CreateNewField.parse_declaration("int 123abc") == (None, None)


def test_parse_declaration_handles_parse_failure(_stubs, monkeypatch):
    monkeypatch.setattr(
        "idc.parse_decl",
        lambda *args, **kwargs: None,
        raising=False,
    )
    assert CreateNewField.parse_declaration("int my_field") == (None, None)


# --- apply_new_field layout tests -----------------------------------------
#
# The GUI/SDK pieces are stubbed; these exercise the byte-offset member
# rebuild logic (gap consumption, user-member conflict, padding) with fakes.


def _member(offset, size, name=""):
    from types import SimpleNamespace

    return SimpleNamespace(offset=offset, size=size, name=name, type=None)


class _FakeFieldTInfo:
    def __init__(self, size):
        self._size = size

    def get_size(self):
        return self._size


class _FakeUdtData(list):
    def push_back(self, value):
        self.append(value)


class _FakeStructTInfo:
    def __init__(self, members):
        self._members = members
        self.rebuilt = None

    def get_udt_details(self, udt_data):
        udt_data.extend(self._members)
        return True

    def create_udt(self, udt_data, _flags):
        self.rebuilt = list(udt_data)
        return True

    def get_type_name(self):
        return "FakeStruct"

    def dstr(self):
        return "FakeStruct"


@pytest.fixture
def _apply_stubs(monkeypatch):
    import forge.features.create_new_field.create_new_field as cnf

    def fake_padding(offset, size):
        return _member(offset, size, f"gap_{offset:x}")

    monkeypatch.setattr(cnf, "create_udt_padding_member", fake_padding)
    return cnf


def test_apply_new_field_consumes_overlapping_autogen_gaps(_apply_stubs):
    struct = _FakeStructTInfo(
        [
            _member(0, 8, "gap_0"),
            _member(8, 8, "gap_8"),
            _member(16, 4, "count"),
        ]
    )
    cnf = _apply_stubs

    assert cnf.apply_new_field(
        struct, 0, 0, field_tinfo=_FakeFieldTInfo(16), field_name="blob"
    )

    layout = [(m.offset, m.size, m.name) for m in struct.rebuilt]
    assert layout == [(0, 16, "blob"), (16, 4, "count")]


def test_apply_new_field_refuses_user_member_overlap(_apply_stubs):
    struct = _FakeStructTInfo([_member(0, 8, "count")])
    cnf = _apply_stubs

    assert not cnf.apply_new_field(
        struct, 0, 0, field_tinfo=_FakeFieldTInfo(8), field_name="blob"
    )
    assert struct.rebuilt is None


def test_apply_new_field_splits_gap_with_padding(_apply_stubs):
    struct = _FakeStructTInfo([_member(0, 16, "gap_0")])
    cnf = _apply_stubs

    assert cnf.apply_new_field(
        struct, 0, 4, field_tinfo=_FakeFieldTInfo(4), field_name="inner"
    )

    layout = [(m.offset, m.size, m.name) for m in struct.rebuilt]
    assert layout == [
        (0, 4, "gap_0"),
        (4, 4, "inner"),
        (8, 8, "gap_8"),
    ]


def test_apply_new_field_refiles_in_place_without_delete(_apply_stubs, monkeypatch):
    """The updated struct replaces the existing IDB type in place: the old
    type must never be deleted while the re-file can still fail."""
    import idaapi

    cnf = _apply_stubs
    deleted = []
    refiled_at = []
    monkeypatch.setattr(idaapi, "get_type_ordinal", lambda *_args, **_kwargs: 7)
    monkeypatch.setattr(
        idaapi,
        "idc_set_local_type",
        lambda ordinal, _decl, _flags: refiled_at.append(ordinal) or 1,
    )
    monkeypatch.setattr(
        idaapi,
        "del_numbered_type",
        lambda _til, ordinal: deleted.append(ordinal) or True,
    )
    struct = _FakeStructTInfo([_member(0, 8, "gap_0")])

    assert cnf.apply_new_field(
        struct, 0, 0, field_tinfo=_FakeFieldTInfo(8), field_name="blob"
    )

    assert refiled_at == [7]
    assert deleted == []


def test_apply_new_field_falls_back_to_delete_and_refile_on_failure(
    _apply_stubs, monkeypatch
):
    """When the in-place replace fails, the live-proven delete+re-create
    path is used as fallback: drop the stale entry, then re-file fresh."""
    import idaapi

    cnf = _apply_stubs
    deleted = []
    refiled_at = []
    monkeypatch.setattr(idaapi, "get_type_ordinal", lambda *_args, **_kwargs: 7)

    def fake_set_local_type(ordinal, _decl, _flags):
        refiled_at.append(ordinal)
        return 1 if ordinal == -1 else 0  # in-place replace fails

    monkeypatch.setattr(idaapi, "idc_set_local_type", fake_set_local_type)
    monkeypatch.setattr(
        idaapi,
        "del_numbered_type",
        lambda _til, ordinal: deleted.append(ordinal) or True,
    )
    struct = _FakeStructTInfo([_member(0, 8, "gap_0")])

    assert cnf.apply_new_field(
        struct, 0, 0, field_tinfo=_FakeFieldTInfo(8), field_name="blob"
    )

    assert refiled_at == [7, -1]
    assert deleted == [7]