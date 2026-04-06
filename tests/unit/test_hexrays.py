from __future__ import annotations

from importlib import util
from pathlib import Path
from types import SimpleNamespace

import ida_typeinf



def _load_hexrays_module():
    hexrays_path = Path(__file__).resolve().parents[2] / "src" / "forge" / "api" / "hexrays.py"
    spec = util.spec_from_file_location("forge.api.hexrays_test", hexrays_path)
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeType:
    def __init__(
        self,
        name: str,
        *,
        args=None,
        pointed=None,
        func: bool = False,
        forward_decl: bool = False,
        size: int = 4,
    ):
        self._name = name
        self._args = list(args or [])
        self._pointed = pointed
        self._func = func
        self._forward_decl = forward_decl
        self._size = size

    def dstr(self):
        return self._name

    def is_func(self):
        return self._func

    def is_funcptr(self):
        return self._pointed is not None and self._func

    def is_ptr(self):
        return self._pointed is not None

    def is_void(self):
        return self._name == "void"

    def get_pointed_object(self):
        return self._pointed

    def get_nargs(self):
        return len(self._args)

    def get_nth_arg(self, idx):
        return self._args[idx]

    def is_forward_decl(self):
        return self._forward_decl

    def get_size(self):
        return self._size

    def clr_const(self):
        return None


class FakeExpr:
    def __init__(self, op, display: str, *, expr_type, ea=0x401000, x=None):
        self.op = op
        self._display = display
        self.type = expr_type
        self.ea = ea
        self.x = x

    def dstr(self):
        return self._display



def test_get_func_argument_info_matches_wrapped_arguments():
    hexrays_module = _load_hexrays_module()

    leaf = FakeExpr(
        hexrays_module.ctype.var,
        "arg0",
        expr_type=SimpleNamespace(dstr=lambda: "void *"),
    )
    wrapped = FakeExpr(
        hexrays_module.ctype.cast,
        "(FixtureScene *)arg0",
        expr_type=SimpleNamespace(dstr=lambda: "FixtureScene *"),
        x=leaf,
    )
    arg_tinfo = FakeType("FixtureScene *")
    func_tinfo = FakeType("void fn(FixtureScene *)", args=[arg_tinfo], func=True)
    call = SimpleNamespace(
        x=SimpleNamespace(type=func_tinfo),
        a=[SimpleNamespace(cexpr=wrapped, dstr=wrapped.dstr)],
    )

    idx, tinfo = hexrays_module.get_func_argument_info(call, leaf)

    assert idx == 0
    assert tinfo is arg_tinfo



def test_get_func_argument_info_reads_function_pointer_signatures():
    hexrays_module = _load_hexrays_module()

    arg_expr = FakeExpr(
        hexrays_module.ctype.var,
        "value",
        expr_type=SimpleNamespace(dstr=lambda: "u64 *"),
    )
    arg_tinfo = FakeType("u64 *")
    pointed_func = FakeType("void (*)(u64 *)", args=[arg_tinfo], func=True)
    func_ptr = FakeType("void (**)(u64 *)", pointed=pointed_func)
    call = SimpleNamespace(
        x=SimpleNamespace(type=func_ptr),
        a=[SimpleNamespace(cexpr=arg_expr, dstr=arg_expr.dstr)],
    )

    idx, tinfo = hexrays_module.get_func_argument_info(call, arg_expr)

    assert idx == 0
    assert tinfo is arg_tinfo



def test_is_legal_type_rejects_incomplete_forward_decl_pointer():
    hexrays_module = _load_hexrays_module()

    forward_decl = FakeType("struct Widget", forward_decl=True, size=ida_typeinf.BADSIZE)
    pointer = FakeType("Widget *", pointed=forward_decl, size=8)

    assert hexrays_module.is_legal_type(pointer) is False
