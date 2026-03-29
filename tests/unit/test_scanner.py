from __future__ import annotations

from importlib import util
from pathlib import Path
from types import ModuleType, SimpleNamespace

import ida_hexrays
import pytest

if not hasattr(ida_hexrays, "ctree_parentee_t"):
    ida_hexrays.ctree_parentee_t = type("ctree_parentee_t", (), {})

import sys

if "ida_idaapi" not in sys.modules:
    sys.modules["ida_idaapi"] = ModuleType("ida_idaapi")
import ida_idaapi
ida_idaapi.BADADDR = -1

from importlib import import_module

hexrays_api = import_module("forge.api.hexrays")
setattr(hexrays_api, "ctype_to_str", lambda *_args, **_kwargs: "")
setattr(hexrays_api, "decompile", lambda *_args, **_kwargs: None)
setattr(hexrays_api, "find_expr_address", lambda *_args, **_kwargs: 0)
setattr(hexrays_api, "get_func_argument_info", lambda *_args, **_kwargs: (0, None))
setattr(hexrays_api, "get_funcs_calling_address", lambda *_args, **_kwargs: set())
setattr(hexrays_api, "is_code", lambda *_args, **_kwargs: False)
setattr(hexrays_api, "is_legal_type", lambda *_args, **_kwargs: True)
setattr(hexrays_api, "to_hex", lambda value: hex(value))
import_module("forge.api.visitor")




def _load_scanner_module():
    visitor_path = Path(__file__).resolve().parents[2] / "src" / "forge" / "api" / "visitor.py"
    visitor_spec = util.spec_from_file_location("forge.api.visitor", visitor_path)
    assert visitor_spec is not None and visitor_spec.loader is not None
    visitor_module = util.module_from_spec(visitor_spec)
    sys.modules["forge.api.visitor"] = visitor_module
    visitor_spec.loader.exec_module(visitor_module)

    scanner_path = Path(__file__).resolve().parents[2] / "src" / "forge" / "api" / "scanner.py"
    spec = util.spec_from_file_location("forge.api.scanner", scanner_path)
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    sys.modules["forge.api.scanner"] = module
    spec.loader.exec_module(module)
    return module




class FakeType:
    def __init__(self, name: str, *, ptr: bool = False, udt: bool = False):
        self._name = name
        self._ptr = ptr
        self._udt = udt

    def dstr(self):
        return self._name

    def is_ptr(self):
        return self._ptr

    def is_udt(self):
        return self._udt


@pytest.mark.parametrize(
    "obj_tinfo, call_tinfo, expected_name",
    [
        (FakeType("FixtureScene *", ptr=True), FakeType("__int64"), "FixtureScene *"),
        (FakeType("FixtureScene", udt=True), FakeType("__int64"), "FixtureScene"),
        (FakeType("FixtureScene *", ptr=True), FakeType("Other *", ptr=True), "Other *"),
    ],
)
def test_prefer_object_tinfo_keeps_structure_like_members(obj_tinfo, call_tinfo, expected_name):
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    obj = SimpleNamespace(tinfo=obj_tinfo)

    preferred = visitor._prefer_object_tinfo(obj, call_tinfo)

    assert preferred.dstr() == expected_name
