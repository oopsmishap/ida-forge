from __future__ import annotations

import sys
import types as py_types
from pathlib import Path

import ida_typeinf

from forge.api.tinfo import is_incomplete_tinfo


class FakeTinfo:
    def __init__(
        self,
        name: str,
        *,
        size: int = 4,
        pointed: "FakeTinfo | None" = None,
        array: bool = False,
        array_element: "FakeTinfo | None" = None,
        forward_decl: bool = False,
        func: bool = False,
        udt: bool = False,
        integral: bool = False,
        signed: bool = False,
        floating: bool = False,
        void: bool = False,
    ):
        self._name = name
        self._size = size
        self._pointed = pointed
        self._array = array
        self._array_element = array_element
        self._forward_decl = forward_decl
        self._func = func
        self._udt = udt
        self._integral = integral
        self._signed = signed
        self._floating = floating
        self._void = void

    def clone(self):
        return FakeTinfo(
            self._name,
            size=self._size,
            pointed=self._pointed.clone() if self._pointed is not None else None,
            array=self._array,
            array_element=self._array_element.clone() if self._array_element is not None else None,
            forward_decl=self._forward_decl,
            func=self._func,
            udt=self._udt,
            integral=self._integral,
            signed=self._signed,
            floating=self._floating,
            void=self._void,
        )

    def dstr(self):
        return self._name

    def get_size(self):
        return self._size

    def is_ptr(self):
        return self._pointed is not None

    def get_pointed_object(self):
        return self._pointed

    def create_ptr(self, pointed):
        self._pointed = pointed
        self._size = 8
        self._name = f"{pointed.dstr()} *"
        return True

    def is_array(self):
        return self._array

    def get_array_element(self):
        return self._array_element

    def is_forward_decl(self):
        return self._forward_decl

    def is_func(self):
        return self._func

    def is_funcptr(self):
        return self.is_ptr() and self._pointed is not None and self._pointed.is_func()

    def is_udt(self):
        return self._udt

    def is_integral(self):
        return self._integral

    def is_signed(self):
        return self._signed

    def is_float(self):
        return self._floating

    def is_void(self):
        return self._void

    def equals_to(self, other):
        return isinstance(other, FakeTinfo) and self.dstr() == other.dstr()



def _load_types_source_module():
    types_path = Path(__file__).resolve().parents[2] / "src" / "forge" / "api" / "types.py"
    source = types_path.read_text(encoding="utf-8")
    trimmed_source = source.split("\ntypes = Types()", 1)[0]
    module = py_types.ModuleType("forge.api.types_exec_test")
    module.__file__ = str(types_path)
    sys.modules[module.__name__] = module
    exec(compile(trimmed_source, str(types_path), "exec"), module.__dict__)
    return module



def _make_types_helper(module):
    helper = module.Types.__new__(module.Types)
    helper._type_cache = {
        "bool": py_types.SimpleNamespace(type=FakeTinfo("bool", size=1, integral=True)),
        "char": py_types.SimpleNamespace(type=FakeTinfo("char", size=1, integral=True)),
        "u8": py_types.SimpleNamespace(type=FakeTinfo("u8", size=1, integral=True)),
        "u16": py_types.SimpleNamespace(type=FakeTinfo("u16", size=2, integral=True)),
        "u32": py_types.SimpleNamespace(type=FakeTinfo("u32", size=4, integral=True)),
        "u64": py_types.SimpleNamespace(type=FakeTinfo("u64", size=8, integral=True)),
        "u128": py_types.SimpleNamespace(type=FakeTinfo("u128", size=16, integral=True)),
        "i8": py_types.SimpleNamespace(type=FakeTinfo("i8", size=1, integral=True, signed=True)),
        "i16": py_types.SimpleNamespace(type=FakeTinfo("i16", size=2, integral=True, signed=True)),
        "i32": py_types.SimpleNamespace(type=FakeTinfo("i32", size=4, integral=True, signed=True)),
        "i64": py_types.SimpleNamespace(type=FakeTinfo("i64", size=8, integral=True, signed=True)),
        "i128": py_types.SimpleNamespace(type=FakeTinfo("i128", size=16, integral=True, signed=True)),
        "f32": py_types.SimpleNamespace(type=FakeTinfo("f32", size=4, floating=True)),
        "f64": py_types.SimpleNamespace(type=FakeTinfo("f64", size=8, floating=True)),
        "size_t": py_types.SimpleNamespace(type=FakeTinfo("size_t", size=8, integral=True)),
    }
    module.ida_typeinf.tinfo_t = lambda value=None: value.clone() if isinstance(value, FakeTinfo) else FakeTinfo("tmp", size=0)
    return helper



def test_is_incomplete_tinfo_treats_none_as_unknown():
    assert is_incomplete_tinfo(None) is True



def test_is_incomplete_tinfo_recurses_through_pointer_wrappers():
    unknown = FakeTinfo("?", size=ida_typeinf.BADSIZE)
    pointer = FakeTinfo("mystery *", size=8, pointed=unknown)

    assert is_incomplete_tinfo(pointer) is True



def test_is_incomplete_tinfo_detects_forward_decl_in_array_elements():
    forward_decl = FakeTinfo("struct Widget", size=ida_typeinf.BADSIZE, forward_decl=True)
    array = FakeTinfo("Widget[4]", size=16, array=True, array_element=forward_decl)

    assert is_incomplete_tinfo(array) is True



def test_is_incomplete_tinfo_preserves_function_and_void_types():
    function = FakeTinfo("void (__fastcall *)(int)", size=ida_typeinf.BADSIZE, func=True)
    function_ptr = FakeTinfo("void (__fastcall **)(int)", size=8, pointed=function)
    void_type = FakeTinfo("void", size=ida_typeinf.BADSIZE, void=True)
    void_ptr = FakeTinfo("void *", size=8, pointed=void_type)

    assert is_incomplete_tinfo(function_ptr) is False
    assert is_incomplete_tinfo(void_ptr) is False



def test_convert_to_simple_type_preserves_meaningful_shapes():
    types_module = _load_types_source_module()
    helper = _make_types_helper(types_module)

    udt = FakeTinfo("FixtureScene", size=0x40, udt=True)
    udt_ptr = FakeTinfo("FixtureScene *", size=8, pointed=udt)
    func = FakeTinfo("void (*)(int)", size=ida_typeinf.BADSIZE, func=True)
    func_ptr = FakeTinfo("void (**)(int)", size=8, pointed=func)
    array = FakeTinfo("unsigned int[4]", size=16, array=True, array_element=FakeTinfo("unsigned int", size=4, integral=True))

    assert helper.convert_to_simple_type(udt_ptr).dstr() == "FixtureScene *"
    assert helper.convert_to_simple_type(func_ptr).dstr() == "void (**)(int)"
    assert helper.convert_to_simple_type(array).dstr() == "unsigned int[4]"



def test_convert_to_simple_type_canonicalizes_scalar_alias_pointers():
    types_module = _load_types_source_module()
    helper = _make_types_helper(types_module)

    aliased_scalar = FakeTinfo("unsigned __int64", size=8, integral=True, signed=False)
    aliased_pointer = FakeTinfo("unsigned __int64 *", size=8, pointed=aliased_scalar)

    result = helper.convert_to_simple_type(aliased_pointer)

    assert result.dstr() == "u64 *"
    assert result.is_ptr() is True
    assert result.get_pointed_object().dstr() == "u64"
