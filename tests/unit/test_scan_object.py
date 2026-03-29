from __future__ import annotations

from types import SimpleNamespace

from forge.api.hexrays import ctype
from forge.api.scan_object import (
    CallArgumentObject,
    GlobalVariableObject,
    MemoryAllocationObject,
    ObjectType,
    ScanObject,
    StructurePointerObject,
    StructureReferenceObject,
    VariableObject,
)


class FakeType:
    def __init__(self, name: str, pointed=None, array_element=None):
        self._name = name
        self._pointed = pointed
        self._array_element = array_element

    def dstr(self):
        return self._name

    def is_ptr(self):
        return self._pointed is not None

    def is_array(self):
        return self._array_element is not None

    def get_pointed_object(self):
        return self._pointed

    def get_array_element(self):
        return self._array_element


class FakeLvar:
    def __init__(self, name: str, type_name: str = "int"):
        self.name = name
        self._type = FakeType(type_name)

    def type(self):
        return self._type


class FakeCfunc:
    def __init__(self, lvars, entry_ea=0x1000, argidx=None):
        self._lvars = lvars
        self.entry_ea = entry_ea
        self.argidx = list(range(len(lvars))) if argidx is None else list(argidx)
        self.body = SimpleNamespace(find_parent_of=lambda expr: None)

    def get_lvars(self):
        return self._lvars


class FakeCtreeItem:
    def __init__(self, lvar=None, e=None, citype=0):
        self._lvar = lvar
        self.e = e
        self.citype = citype

    def get_lvar(self):
        return self._lvar


class FakeExpr:
    def __init__(self, op, **kwargs):
        self.op = op
        self.ea = kwargs.pop("ea", 0x401000)
        self.to_specific_type = kwargs.pop("to_specific_type", None)
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeNumberExpr(FakeExpr):
    def __init__(self, value: int):
        super().__init__(ctype.num)
        self._value = value

    def numval(self):
        return self._value



def test_variable_object_matches_lvar_index():
    lvar = FakeLvar("local", "int")
    obj = VariableObject(lvar, 3)
    expr = FakeExpr(ctype.var, v=SimpleNamespace(idx=3))

    assert obj.id == ObjectType.local_variable
    assert obj.is_target(expr) is True
    assert repr(obj) == "local"



def test_structure_pointer_and_reference_targets_match_type_and_offset():
    pointed = FakeType("MyStruct")
    ptr_expr = FakeExpr(ctype.memptr, m=8, x=SimpleNamespace(type=FakeType("MyStruct *", pointed=pointed)))
    ref_expr = FakeExpr(ctype.memref, m=4, x=SimpleNamespace(type=FakeType("MyStruct")))

    assert StructurePointerObject("MyStruct", 8).is_target(ptr_expr) is True
    assert StructureReferenceObject("MyStruct", 4).is_target(ref_expr) is True


def test_structure_pointer_and_reference_targets_ignore_type_wrappers():
    pointed = FakeType("const struct MyStruct")
    ptr_expr = FakeExpr(
        ctype.memptr,
        m=8,
        x=SimpleNamespace(type=FakeType("const struct MyStruct *", pointed=pointed)),
    )
    double_ptr_expr = FakeExpr(
        ctype.memptr,
        m=8,
        x=SimpleNamespace(
            type=FakeType(
                "MyStruct **",
                pointed=FakeType("MyStruct *", pointed=FakeType("MyStruct")),
            )
        ),
    )
    ref_expr = FakeExpr(
        ctype.memref,
        m=4,
        x=SimpleNamespace(type=FakeType("MyStruct[4]", array_element=pointed)),
    )

    assert StructurePointerObject("MyStruct", 8).is_target(ptr_expr) is True
    assert StructurePointerObject("MyStruct", 8).is_target(double_ptr_expr) is False
    assert StructureReferenceObject("MyStruct", 4).is_target(ref_expr) is True



def test_global_variable_and_call_argument_targets_match_expected_expression():
    global_expr = FakeExpr(ctype.obj, obj_ea=0x1234)
    call_expr = FakeExpr(ctype.call, x=SimpleNamespace(obj_ea=0x5678))

    assert GlobalVariableObject(0x1234).is_target(global_expr) is True
    assert CallArgumentObject(0x5678, 0).is_target(call_expr) is True



def test_scan_object_create_handles_var_obj_memptr_and_memref(monkeypatch):
    cfunc = FakeCfunc([FakeLvar("arg0")])
    monkeypatch.setattr(ScanObject, "get_expression_address", staticmethod(lambda _cfunc, expr: expr.ea))

    var_expr = FakeExpr(ctype.var, v=SimpleNamespace(idx=0), ea=0x10)
    var_obj = ScanObject.create(cfunc, var_expr)
    assert isinstance(var_obj, VariableObject)
    assert var_obj.ea == 0x10

    obj_expr = FakeExpr(ctype.obj, obj_ea=0x2000, type=FakeType("int"), ea=0x20)
    obj = ScanObject.create(cfunc, obj_expr)
    assert isinstance(obj, GlobalVariableObject)
    assert obj.name == "name_2000"

    ptr_expr = FakeExpr(
        ctype.memptr,
        m=8,
        x=SimpleNamespace(type=FakeType("MyStruct *", pointed=FakeType("MyStruct"))),
        type=FakeType("field_t"),
        ea=0x30,
    )
    ptr = ScanObject.create(cfunc, ptr_expr)
    assert isinstance(ptr, StructurePointerObject)
    assert ptr.name == "member_name"

    ref_expr = FakeExpr(
        ctype.memref,
        m=4,
        x=SimpleNamespace(type=FakeType("MyStruct")),
        type=FakeType("field_t"),
        ea=0x40,
    )
    ref = ScanObject.create(cfunc, ref_expr)
    assert isinstance(ref, StructureReferenceObject)
    assert ref.name == "member_name"



def test_scan_object_create_returns_none_for_unsupported_expression(monkeypatch):
    cfunc = FakeCfunc([])
    monkeypatch.setattr(ScanObject, "get_expression_address", staticmethod(lambda _cfunc, expr: expr.ea))

    assert ScanObject.create(cfunc, FakeExpr(999)) is None



def test_scan_object_create_from_ctree_item_uses_local_variable(monkeypatch):
    import ida_hexrays

    cfunc = FakeCfunc([FakeLvar("local")])
    expr = FakeExpr(ctype.var, ea=0x55)
    monkeypatch.setattr(ScanObject, "get_expression_address", staticmethod(lambda _cfunc, expr: expr.ea))
    item = ida_hexrays.ctree_item_t()
    item.get_lvar = lambda: cfunc.get_lvars()[0]
    item.e = expr
    item.citype = 0

    obj = ScanObject.create(cfunc, item)

    assert isinstance(obj, VariableObject)
    assert obj.ea == 0x55



def test_call_argument_object_create_scan_object_walks_wrappers(monkeypatch):
    monkeypatch.setattr(ScanObject, "create", staticmethod(lambda _cfunc, expr: expr))
    inner = FakeExpr(ctype.var)
    wrapped = FakeExpr(ctype.cast, x=FakeExpr(ctype.ref, x=FakeExpr(ctype.add, x=inner)))
    call = FakeExpr(ctype.call, a=[wrapped])
    obj = CallArgumentObject(0x1000, 0)

    assert obj.create_scan_object(FakeCfunc([]), call) is inner

def test_call_argument_object_create_scan_object_preserves_numeric_offset(monkeypatch):
    base = SimpleNamespace(
        tinfo=FakeType("FixtureScene *", pointed=FakeType("FixtureScene")),
        name="this",
        ea=0x10,
    )
    monkeypatch.setattr(ScanObject, "create", staticmethod(lambda _cfunc, expr: base if expr is not None else None))

    inner = FakeExpr(
        ctype.cast,
        x=FakeExpr(ctype.add, x=FakeExpr(ctype.var), y=FakeNumberExpr(0x538)),
    )
    call = FakeExpr(ctype.call, a=[inner])
    obj = CallArgumentObject(0x1000, 0)

    derived = obj.create_scan_object(FakeCfunc([]), call)

    assert isinstance(derived, StructureReferenceObject)
    assert derived.struct_name == "FixtureScene"
    assert derived.offset == 0x538
    assert derived.ea == 0x10




def test_call_argument_object_create_populates_name_and_tinfo():
    cfunc = FakeCfunc([FakeLvar("arg0")], entry_ea=0x1234)
    obj = CallArgumentObject.create(cfunc, 0)

    assert obj.func_ea == 0x1234
    assert obj.name == "arg0"



def test_memory_allocation_object_create_handles_direct_and_casted_calls(monkeypatch):
    import ida_name

    monkeypatch.setattr(ida_name, "get_short_name", lambda _ea: "malloc")
    monkeypatch.setattr(ScanObject, "get_expression_address", staticmethod(lambda _cfunc, expr: expr.ea))
    size_expr = FakeNumberExpr(64)
    call = FakeExpr(ctype.call, x=SimpleNamespace(obj_ea=0x5000), a=[size_expr], ea=0x88)
    casted = FakeExpr(ctype.cast, x=call)

    direct = MemoryAllocationObject.create(FakeCfunc([]), call)
    via_cast = MemoryAllocationObject.create(FakeCfunc([]), casted)

    assert direct.name == "malloc"
    assert direct.size == 64
    assert direct.ea == 0x88
    assert via_cast.size == 64



def test_memory_allocation_object_create_returns_zero_for_non_numeric_size(monkeypatch):
    import ida_name

    monkeypatch.setattr(ida_name, "get_short_name", lambda _ea: "malloc")
    call = FakeExpr(ctype.call, x=SimpleNamespace(obj_ea=0x5000), a=[FakeExpr(ctype.var)], ea=0x99)
    obj = MemoryAllocationObject.create(FakeCfunc([]), call)

    assert obj.size == 0



def test_memory_allocation_object_create_returns_none_for_non_allocator_name(monkeypatch):
    import ida_name

    monkeypatch.setattr(ida_name, "get_short_name", lambda _ea: "memcpy")
    call = FakeExpr(ctype.call, x=SimpleNamespace(obj_ea=0x5000), a=[FakeNumberExpr(8)], ea=0x99)

    assert MemoryAllocationObject.create(FakeCfunc([]), call) is None

def test_call_argument_object_create_uses_formal_argument_order():
    cfunc = FakeCfunc(
        [FakeLvar("local"), FakeLvar("first"), FakeLvar("second")],
        entry_ea=0x1234,
        argidx=[1, 2],
    )
    obj = CallArgumentObject.create(cfunc, 1)

    assert obj is not None
    assert obj.func_ea == 0x1234
    assert obj.name == "second"
    assert obj.arg_idx == 1


def test_call_argument_object_create_scan_object_returns_none_for_missing_argument():
    call = FakeExpr(ctype.call, a=[FakeExpr(ctype.var)])
    obj = CallArgumentObject(0x1000, 1)

    assert obj.create_scan_object(FakeCfunc([]), call) is None


def test_memory_allocation_object_create_handles_missing_size_argument(monkeypatch):
    import ida_name
    monkeypatch.setattr(ida_name, "get_short_name", lambda _ea: "malloc")
    monkeypatch.setattr(ScanObject, "get_expression_address", staticmethod(lambda _cfunc, expr: expr.ea))
    call = FakeExpr(ctype.call, x=SimpleNamespace(obj_ea=0x5000), a=[], ea=0x99)

    obj = MemoryAllocationObject.create(FakeCfunc([]), call)

    assert obj is not None
    assert obj.size == 0

def test_get_argument_index_resolves_formal_argument_ordinals():
    import importlib.util
    from pathlib import Path
    import ida_hexrays
    if not hasattr(ida_hexrays, "ctree_parentee_t"):
        ida_hexrays.ctree_parentee_t = type("ctree_parentee_t", (), {})

    hexrays_path = Path(__file__).resolve().parents[2] / "src" / "forge" / "api" / "hexrays.py"
    spec = importlib.util.spec_from_file_location("forge.api.hexrays_real", hexrays_path)
    assert spec is not None and spec.loader is not None
    hexrays_real = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hexrays_real)

    cfunc = SimpleNamespace(
        argidx=[1, 3],
        get_lvars=lambda: [
            FakeLvar("local"),
            FakeLvar("first"),
            FakeLvar("ignored"),
            FakeLvar("second"),
        ],
    )

    assert hexrays_real.get_argument_index(cfunc, 3) == 1
    assert hexrays_real.get_argument_index(cfunc, 2) is None


