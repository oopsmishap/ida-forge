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


def test_scanned_object_create_inherits_scan_root_metadata(monkeypatch):
    scanner_module = _load_scanner_module()
    scan_object_module = import_module("forge.api.scan_object")
    import ida_funcs

    monkeypatch.setattr(ida_funcs, "get_func", lambda _ea: SimpleNamespace(start_ea=0x401000), raising=False)

    source = SimpleNamespace(
        id=scan_object_module.ObjectType.global_object,
        object_ea=0x5000,
        name="g_root",
        scan_root_function_ea=0x401000,
        scan_root_ea=0x401234,
        scan_root_function_name="sub_401000",
    )

    scanned = scanner_module.ScannedObject.create(source, 0x401234, 0x0)

    assert scanned.scan_root_function_ea == 0x401000
    assert scanned.scan_root_ea == 0x401234
    assert scanned.scan_root_function_name == "sub_401000"

