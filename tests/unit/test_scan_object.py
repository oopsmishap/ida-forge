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
    def __init__(self, name: str, pointed=None):
        self._name = name
        self._pointed = pointed

    def dstr(self):
        return self._name

    def get_pointed_object(self):
        return self._pointed


class FakeLvar:
    def __init__(self, name: str, type_name: str = "int"):
        self.name = name
        self._type = FakeType(type_name)

    def type(self):
        return self._type


class FakeCfunc:
    def __init__(self, lvars, entry_ea=0x1000):
        self._lvars = lvars
        self.entry_ea = entry_ea
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
