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
        lambda til, decl, flags: _FakeTInfo(),
        raising=False,
    )
    tinfo, name = CreateNewField.parse_declaration("int my_field")
    assert name == "my_field"
    assert isinstance(tinfo, _FakeTInfo)


def test_parse_declaration_array_size(_stubs, monkeypatch):
    monkeypatch.setattr(
        "idc.parse_decl",
        lambda til, decl, flags: _FakeTInfo(),
        raising=False,
    )
    _tinfo, name = CreateNewField.parse_declaration("char buffer[16]")
    assert name == "buffer"
    assert _tinfo.array_size == 16


def test_parse_declaration_array_optional(_stubs, monkeypatch):
    monkeypatch.setattr(
        "idc.parse_decl",
        lambda til, decl, flags: _FakeTInfo(),
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