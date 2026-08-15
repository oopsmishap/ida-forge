from __future__ import annotations

from types import SimpleNamespace

from forge.api.hexrays import ctype
from forge.api.scan_object import (
    CallArgumentObject,
    GlobalVariableObject,
    MemoryAllocationObject,
    ObjectType,
    ReturnedObject,
    ScanObject,
    StructurePointerObject,
    StructureReferenceObject,
    VariableObject,
    _extract_offset_expression,
    _make_offset_scan_object,
    _safe_struct_name,
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
        self.type = kwargs.pop("type", FakeType("int"))
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


def test_structure_reference_targets_match_pointer_arithmetic_expression():
    expr = FakeExpr(
        ctype.add,
        x=SimpleNamespace(type=FakeType("MyStruct")),
        y=FakeNumberExpr(0xCD8),
    )

    assert StructureReferenceObject("MyStruct", 0xCD8).is_target(expr) is True


def test_structure_member_targets_ignore_incomplete_expressions():
    ptr_expr = FakeExpr(ctype.memptr, m=8)
    ref_expr = FakeExpr(ctype.memref, m=4)
    call_expr = FakeExpr(ctype.call)

    assert StructurePointerObject("MyStruct", 8).is_target(ptr_expr) is False
    assert StructureReferenceObject("MyStruct", 4).is_target(ref_expr) is False
    assert CallArgumentObject(0x1000, 0).is_target(call_expr) is False
    assert ReturnedObject(0x1000).is_target(call_expr) is False



def test_global_variable_and_call_argument_targets_match_expected_expression():
    global_expr = FakeExpr(ctype.obj, obj_ea=0x1234)
    call_expr = FakeExpr(ctype.call, x=SimpleNamespace(obj_ea=0x5678))

    assert GlobalVariableObject(0x1234).is_target(global_expr) is True
    assert CallArgumentObject(0x5678, 0).is_target(call_expr) is True

def test_safe_struct_name_rejects_void_and_integral_aliases():
    # Hexrays' dstr() of a void-pointer pointee, a void lvar, or any
    # integral scalar returns these strings. Treating them as struct names
    # produces "struct void { ... }" downstream and triggers "Void type is
    # forbidden here" from the parser per affected site.
    assert _safe_struct_name(FakeType("void")) is None
    assert _safe_struct_name(FakeType("void *", pointed=FakeType("void"))) is None
    assert _safe_struct_name(FakeType("void[N]")) is None
    assert _safe_struct_name(FakeType("const void *", pointed=FakeType("void"))) is None
    assert _safe_struct_name(FakeType("nullptr")) is None
    assert _safe_struct_name(FakeType("_DWORD")) is None
    assert _safe_struct_name(FakeType("_QWORD[4]")) is None
    # real struct names survive untouched
    assert _safe_struct_name(FakeType("MyStruct")) == "MyStruct"
    assert _safe_struct_name(FakeType("MyStruct *", pointed=FakeType("MyStruct"))) == "MyStruct *"
    # defensive defaults
    assert _safe_struct_name(None) is None
    assert _safe_struct_name(SimpleNamespace(dstr=lambda: "")) is None


def test_scan_object_create_returns_none_for_void_memptr_and_memref(monkeypatch):
    """A ``void *`` access must not be turned into a StructureReferenceObject
    carrying the literal struct name ``"void"`` — that gets fed to the parser
    later and produces "Void type is forbidden here" + dialog spam per row.
    """
    cfunc = FakeCfunc([FakeLvar("arg0")])
    monkeypatch.setattr(ScanObject, "get_expression_address", staticmethod(lambda _cfunc, expr: expr.ea))

    ptr_expr = FakeExpr(
        ctype.memptr,
        m=8,
        x=SimpleNamespace(type=FakeType("void *", pointed=FakeType("void"))),
        type=FakeType("field_t"),
        ea=0x30,
    )
    assert ScanObject.create(cfunc, ptr_expr) is None

    ref_expr = FakeExpr(
        ctype.memref,
        m=4,
        x=SimpleNamespace(type=FakeType("void")),
        type=FakeType("field_t"),
        ea=0x40,
    )
    assert ScanObject.create(cfunc, ref_expr) is None


def test_make_offset_scan_object_skips_void_base(monkeypatch):
    base = SimpleNamespace(tinfo=FakeType("void *", pointed=FakeType("void")), name="x", ea=0x100)
    assert _make_offset_scan_object(base, 0x10) is base
    # integral alias as the base must also yield no reference object
    base2 = SimpleNamespace(tinfo=FakeType("_QWORD"), name="y", ea=0x200)
    assert _make_offset_scan_object(base2, 0x8) is base2



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


def test_extract_offset_expression_handles_cast_ref_add_and_subtraction():
    add_expr = FakeExpr(
        ctype.cast,
        x=FakeExpr(ctype.ref, x=FakeExpr(ctype.add, x=FakeExpr(ctype.var), y=FakeNumberExpr(8))),
    )
    sub_expr = FakeExpr(ctype.sub, x=FakeExpr(ctype.var), y=FakeNumberExpr(8))

    add_base, add_offset = _extract_offset_expression(add_expr)
    sub_base, sub_offset = _extract_offset_expression(sub_expr)

    assert add_base.op == ctype.var
    assert add_offset == 8
    assert sub_base.op == ctype.var
    assert sub_offset == -8


def test_extract_offset_expression_handles_scaled_index_and_direct_members():
    idx_expr = FakeExpr(
        ctype.idx,
        x=FakeExpr(ctype.var),
        y=FakeNumberExpr(2),
        type=SimpleNamespace(get_ptrarr_objsize=lambda: 8),
    )
    memptr_expr = FakeExpr(ctype.memptr, m=4, x=FakeExpr(ctype.var))
    memref_expr = FakeExpr(ctype.memref, m=12, x=FakeExpr(ctype.var))

    idx_base, idx_offset = _extract_offset_expression(idx_expr)
    ptr_base, ptr_offset = _extract_offset_expression(memptr_expr)
    ref_base, ref_offset = _extract_offset_expression(memref_expr)

    assert idx_base.op == ctype.var
    assert idx_offset == 16
    assert ptr_base.op == ctype.var
    assert ptr_offset == 4
    assert ref_base.op == ctype.var
    assert ref_offset == 12


def test_call_argument_object_create_scan_object_handles_pointer_wrapped_offset(monkeypatch):
    base = SimpleNamespace(
        tinfo=FakeType("FixtureScene *", pointed=FakeType("FixtureScene")),
        name="this",
        ea=0x10,
    )
    monkeypatch.setattr(ScanObject, "create", staticmethod(lambda _cfunc, expr: base if expr is not None else None))

    inner = FakeExpr(
        ctype.cast,
        x=FakeExpr(
            ctype.ptr,
            x=FakeExpr(ctype.add, x=FakeExpr(ctype.var), y=FakeNumberExpr(8)),
            type=SimpleNamespace(get_ptrarr_objsize=lambda: 8),
        ),
    )
    call = FakeExpr(ctype.call, a=[inner])
    obj = CallArgumentObject(0x1000, 0)

    derived = obj.create_scan_object(FakeCfunc([]), call)

    assert isinstance(derived, StructureReferenceObject)
    assert derived.struct_name == "FixtureScene"
    assert derived.offset == 8

def test_scan_object_create_sets_scan_root_provenance(monkeypatch):
    cfunc = FakeCfunc([FakeLvar("arg0")], entry_ea=0x401000)
    monkeypatch.setattr(ScanObject, "get_expression_address", staticmethod(lambda _cfunc, expr: expr.ea))

    expr = FakeExpr(ctype.var, v=SimpleNamespace(idx=0), ea=0x401234)
    obj = ScanObject.create(cfunc, expr)

    assert obj is not None
    assert obj.scan_root_function_ea == 0x401000
    assert obj.scan_root_ea == 0x401234
    assert obj.scan_root_function_name == "sub_401000"


def test_make_offset_scan_object_inherits_scan_root_provenance(monkeypatch):
    import importlib

    scan_object_module = importlib.import_module("forge.api.scan_object")
    base = SimpleNamespace(
        tinfo=FakeType("FixtureScene *", pointed=FakeType("FixtureScene")),
        name="this",
        ea=0x401234,
        scan_root_function_ea=0x401000,
        scan_root_ea=0x401234,
        scan_root_function_name="sub_401000",
    )
    base.inherit_scan_root_from = lambda other: (
        setattr(base, "scan_root_function_ea", other.scan_root_function_ea),
        setattr(base, "scan_root_ea", other.scan_root_ea),
        setattr(base, "scan_root_function_name", other.scan_root_function_name),
    )
    derived = scan_object_module._make_offset_scan_object(base, 0x538)

    assert derived.scan_root_function_ea == 0x401000
    assert derived.scan_root_ea == 0x401234
    assert derived.scan_root_function_name == "sub_401000"
    assert derived.offset == 0x538
    assert derived.ea == 0x401234






def test_variable_object_hash_uses_function_context_from_create(monkeypatch):
    cfunc = FakeCfunc([FakeLvar("arg0")], entry_ea=0x1234)
    monkeypatch.setattr(
        ScanObject,
        "get_expression_address",
        staticmethod(lambda _cfunc, expr: expr.ea),
    )

    expr = FakeExpr(ctype.var, v=SimpleNamespace(idx=0), ea=0x401234)
    obj = ScanObject.create(cfunc, expr)

    assert obj.func_ea == 0x1234
    assert hash(obj) == hash((obj.id, obj.name, 0x1234, 0x401234))


def test_variable_object_hash_is_safe_without_function_context():
    obj = VariableObject(FakeLvar("arg0"), 0)
    obj.ea = 0x401234

    assert obj.func_ea == -1
    assert hash(obj) == hash((obj.id, obj.name, -1, 0x401234))


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
    assert direct.scan_root_function_ea == 0x1000
    assert direct.scan_root_ea == 0x88
    assert direct.scan_root_function_name == "sub_1000"
    assert via_cast.size == 64
    assert via_cast.scan_root_function_ea == 0x1000
    assert via_cast.scan_root_ea == 0x88
    assert via_cast.scan_root_function_name == "sub_1000"


def test_scan_object_create_with_promote_root_false_leaves_root_unset(monkeypatch):
    """A mid-walk ScanObject.create (visitor step, assignment tracking) must
    NOT promote the lvar to a new scan root — that promotion is what causes
    a ``v0->field = v2`` LHS to be picked up as a fresh scan root when the
    scan was started on ``v2``.
    """
    cfunc = FakeCfunc([FakeLvar("v2")], entry_ea=0x401000)
    monkeypatch.setattr(
        ScanObject,
        "get_expression_address",
        staticmethod(lambda _cfunc, expr: expr.ea),
    )
    var_expr = FakeExpr(ctype.var, v=SimpleNamespace(idx=0), ea=0x401020)
    obj = ScanObject.create(cfunc, var_expr, promote_root=False)
    assert obj is not None
    assert obj.name == "v2"
    assert obj.scan_root_function_ea == -1  # BADADDR sentinel from __init__
    assert obj.scan_root_ea == -1
    # And the default behaviour (promote_root=True) still promotes.
    promoted = ScanObject.create(cfunc, var_expr)
    assert promoted.scan_root_function_ea == 0x401000
    assert promoted.scan_root_ea == 0x401020



def test_memory_allocation_object_create_multiplies_calloc_size(monkeypatch):
    import ida_name

    monkeypatch.setattr(ida_name, "get_short_name", lambda _ea: "calloc")
    monkeypatch.setattr(
        ScanObject,
        "get_expression_address",
        staticmethod(lambda _cfunc, expr: expr.ea),
    )
    call = FakeExpr(
        ctype.call,
        x=SimpleNamespace(obj_ea=0x5000),
        a=[FakeNumberExpr(1), FakeNumberExpr(0x2C)],
        ea=0x77,
    )

    obj = MemoryAllocationObject.create(FakeCfunc([]), call)

    assert obj is not None
    assert obj.name == "calloc"
    assert obj.size == 0x2C


def test_extract_numeric_argument_folds_constant_arithmetic(monkeypatch):
    """I.24: mul/add/sub fold when both operands are constant; a variable
    operand makes the whole expression unknown (None)."""
    monkeypatch.setattr(ctype, "mul", 30, raising=False)
    monkeypatch.setattr(ctype, "add", 31, raising=False)
    monkeypatch.setattr(ctype, "sub", 32, raising=False)

    prod = FakeExpr(ctype.mul, x=FakeNumberExpr(4), y=FakeNumberExpr(8))
    assert MemoryAllocationObject._extract_numeric_argument([prod], 0) == 32

    total = FakeExpr(ctype.add, x=FakeNumberExpr(10), y=FakeNumberExpr(44))
    assert MemoryAllocationObject._extract_numeric_argument([total], 0) == 54

    diff = FakeExpr(ctype.sub, x=FakeNumberExpr(64), y=FakeNumberExpr(8))
    assert MemoryAllocationObject._extract_numeric_argument([diff], 0) == 56

    # nested: (2 + 6) * 3
    inner = FakeExpr(ctype.add, x=FakeNumberExpr(2), y=FakeNumberExpr(6))
    outer = FakeExpr(ctype.mul, x=inner, y=FakeNumberExpr(3))
    assert MemoryAllocationObject._extract_numeric_argument([outer], 0) == 24

    # a variable operand poisons the fold
    partial = FakeExpr(ctype.mul, x=FakeExpr(ctype.var), y=FakeNumberExpr(12))
    assert MemoryAllocationObject._extract_numeric_argument([partial], 0) is None
    assert MemoryAllocationObject._extract_numeric_argument([], 0) is None


def test_memory_allocation_object_size_hint_unknown_vs_real_zero(monkeypatch):
    """I.24: calloc(w*h, 12) — non-constant first operand — still creates a
    row with size None; calloc(4, 8) folds to 32."""
    import ida_name

    monkeypatch.setattr(ida_name, "get_short_name", lambda _ea: "calloc")
    monkeypatch.setattr(
        ScanObject,
        "get_expression_address",
        staticmethod(lambda _cfunc, expr: expr.ea),
    )

    known = FakeExpr(
        ctype.call,
        x=SimpleNamespace(obj_ea=0x5000),
        a=[FakeNumberExpr(4), FakeNumberExpr(8)],
        ea=0x77,
    )
    unknown = FakeExpr(
        ctype.call,
        x=SimpleNamespace(obj_ea=0x5000),
        a=[FakeExpr(ctype.var), FakeNumberExpr(12)],
        ea=0x78,
    )

    assert MemoryAllocationObject.create(FakeCfunc([]), known).size == 32
    obj = MemoryAllocationObject.create(FakeCfunc([]), unknown)
    assert obj is not None
    assert obj.size is None


def test_memory_allocation_object_create_uses_windows_heapalloc_size_argument(monkeypatch):
    import ida_name

    monkeypatch.setattr(ida_name, "get_short_name", lambda _ea: "HeapAlloc")
    monkeypatch.setattr(
        ScanObject,
        "get_expression_address",
        staticmethod(lambda _cfunc, expr: expr.ea),
    )
    call = FakeExpr(
        ctype.call,
        x=SimpleNamespace(obj_ea=0x5000),
        a=[FakeNumberExpr(0), FakeNumberExpr(0), FakeNumberExpr(0x38)],
        ea=0x66,
    )

    obj = MemoryAllocationObject.create(FakeCfunc([]), call)

    assert obj is not None
    assert obj.name == "HeapAlloc"
    assert obj.size == 0x38


def test_memory_allocation_object_create_supports_prefixed_linux_kernel_allocators(monkeypatch):
    import ida_name

    monkeypatch.setattr(ida_name, "get_short_name", lambda _ea: "j___imp_kmalloc_array@12")
    monkeypatch.setattr(
        ScanObject,
        "get_expression_address",
        staticmethod(lambda _cfunc, expr: expr.ea),
    )
    call = FakeExpr(
        ctype.call,
        x=SimpleNamespace(obj_ea=0x5000),
        a=[FakeNumberExpr(2), FakeNumberExpr(0x20), FakeNumberExpr(0)],
        ea=0x55,
    )

    obj = MemoryAllocationObject.create(FakeCfunc([]), call)

    assert obj is not None
    assert obj.name == "j___imp_kmalloc_array@12"
    assert obj.size == 0x40


def test_memory_allocation_object_create_returns_none_size_for_non_numeric_size(monkeypatch):
    """I.24: an unprovably-constant size still creates the allocation row
    (size None), so callers can tell "unknown" from a real zero."""
    import ida_name

    monkeypatch.setattr(ida_name, "get_short_name", lambda _ea: "malloc")
    call = FakeExpr(ctype.call, x=SimpleNamespace(obj_ea=0x5000), a=[FakeExpr(ctype.var)], ea=0x99)
    obj = MemoryAllocationObject.create(FakeCfunc([]), call)

    assert obj is not None
    assert obj.size is None



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
    assert obj.size is None

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




def test_memory_allocation_create_ignores_cast_without_inner_call(monkeypatch):
    monkeypatch.setattr(ScanObject, "get_expression_address", staticmethod(lambda _cfunc, expr: expr.ea))
    bad_cast = FakeExpr(ctype.cast, x=None)
    assert MemoryAllocationObject.create(FakeCfunc([]), bad_cast) is None
