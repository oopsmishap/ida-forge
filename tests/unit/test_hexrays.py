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


def _make_cfunc(hexrays_module, *, treeitems=None, eamap=None, closest=None):
    if closest is not None:
        body = SimpleNamespace(find_closest_addr=lambda ea: closest)
    else:
        body = SimpleNamespace(
            find_closest_addr=lambda ea: (_ for _ in ()).throw(RuntimeError("stale"))
        )
    return SimpleNamespace(
        treeitems=treeitems or [],
        eamap=eamap,
        body=body,
    )


def test_collect_ctree_items_near_ea_uses_treeitems_first():
    hexrays_module = _load_hexrays_module()
    item_a = SimpleNamespace(ea=0x401000)
    item_b = SimpleNamespace(ea=0x401100)
    cfunc = _make_cfunc(hexrays_module, treeitems=[item_a, item_b])

    assert hexrays_module.collect_ctree_items_near_ea(cfunc, 0x401000) == [item_a]


def test_collect_ctree_items_near_ea_short_circuits_on_candidates():
    hexrays_module = _load_hexrays_module()
    item = SimpleNamespace(ea=0x401000)
    eamap_item = SimpleNamespace(ea=0x0)
    cfunc = _make_cfunc(
        hexrays_module,
        treeitems=[item],
        eamap={0x401000: [eamap_item]},
        closest=SimpleNamespace(ea=0x0),
    )

    # Default (short-circuit) mode: treeitems hit wins, eamap/closest unused.
    assert hexrays_module.collect_ctree_items_near_ea(cfunc, 0x401000) == [item]


def test_collect_ctree_items_near_ea_exhaustive_merges_all_sources():
    hexrays_module = _load_hexrays_module()
    item = SimpleNamespace(ea=0x401000)
    eamap_item = SimpleNamespace(ea=0x0)
    closest_item = SimpleNamespace(ea=0x0)
    cfunc = SimpleNamespace(
        treeitems=[item],
        eamap={0x401000: [eamap_item, item]},  # duplicate of the treeitem
        body=SimpleNamespace(find_closest_addr=lambda ea: closest_item),
    )

    result = hexrays_module.collect_ctree_items_near_ea(
        cfunc, 0x401000, exhaustive=True
    )

    # All sources contribute; duplicates by identity are dropped; None skipped.
    assert [id(x) for x in result] == [id(item), id(eamap_item), id(closest_item)]


def test_collect_ctree_items_near_ea_falls_back_when_eamap_raises():
    hexrays_module = _load_hexrays_module()

    class _RaisingMap(dict):
        def get(self, key, default=None):
            raise TypeError("simulated IDA API drift")

    closest_item = SimpleNamespace(ea=0x0)
    cfunc = SimpleNamespace(
        treeitems=[],
        eamap=_RaisingMap({0x401000: []}),
        body=SimpleNamespace(find_closest_addr=lambda ea: closest_item),
    )

    assert hexrays_module.collect_ctree_items_near_ea(cfunc, 0x401000) == [
        closest_item
    ]


def test_collect_ctree_items_near_ea_tolerates_stale_closest_lookup():
    hexrays_module = _load_hexrays_module()
    cfunc = _make_cfunc(hexrays_module, treeitems=[], eamap={})

    # find_closest_addr raises (stale cfunc after IDB type changes) -> no items
    assert hexrays_module.collect_ctree_items_near_ea(cfunc, 0x401000) == []


def test_collect_ctree_items_near_ea_handles_badaddr_and_none_cfunc():
    hexrays_module = _load_hexrays_module()

    assert hexrays_module.collect_ctree_items_near_ea(None, 0x401000) == []
    assert (
        hexrays_module.collect_ctree_items_near_ea(SimpleNamespace(), -1) == []
    )


# ---------------------------------------------------------------------------
# Tier 4: decompile guards (BADADDR / non-function EAs)
# ---------------------------------------------------------------------------


def _patch_decompile_deps(monkeypatch, hexrays_module):
    calls = {"decompile": [], "warned": []}

    monkeypatch.setattr(
        hexrays_module.ida_hexrays, "decompile",
        lambda ea: calls["decompile"].append(ea) or SimpleNamespace(),
        raising=False,
    )
    monkeypatch.setattr(
        hexrays_module.ida_funcs, "get_func",
        lambda ea: None, raising=False,
    )
    monkeypatch.setattr(
        hexrays_module,
        "log_warning",
        lambda msg, *a, **k: calls["warned"].append(msg), raising=False,
    )
    return calls


def test_decompile_rejects_badaddr(monkeypatch):
    hexrays_module = _load_hexrays_module()
    calls = _patch_decompile_deps(monkeypatch, hexrays_module)

    assert hexrays_module.decompile(-1) is None
    assert calls["decompile"] == []


def test_decompile_rejects_non_function_ea(monkeypatch):
    hexrays_module = _load_hexrays_module()
    calls = _patch_decompile_deps(monkeypatch, hexrays_module)

    assert hexrays_module.decompile(0x140000123) is None
    assert calls["decompile"] == []
    assert any("not a function" in msg for msg in calls["warned"])


def test_decompile_delegates_to_real_function(monkeypatch):
    hexrays_module = _load_hexrays_module()
    calls = _patch_decompile_deps(monkeypatch, hexrays_module)
    monkeypatch.setattr(
        hexrays_module.ida_funcs, "get_func",
        lambda ea: SimpleNamespace(start_ea=ea), raising=False,
    )

    result = hexrays_module.decompile(0x1400014F0)

    assert calls["decompile"] == [0x1400014F0]
    assert result is not None


def test_is_imported_matches_cached_absolute_import_ea(monkeypatch):
    """Cache coordinate fix: ``cache.imported_ea`` stores absolute EAs, so
    with image_base != 0 a cached import EA matches the normalized lookup
    (the old RVA cache never matched the absolute membership test)."""
    from forge.api import cache as cache_module
    from forge.api import domain as domain_module

    hexrays_module = _load_hexrays_module()
    domain_module.clear_fallback_records()
    cache_module.imported_ea.clear()
    monkeypatch.setattr(hexrays_module, "_current_domain_database", lambda required=False: None)
    monkeypatch.setattr(hexrays_module.ida_segment, "getseg", lambda _ea: None, raising=False)
    monkeypatch.setattr(
        hexrays_module.ida_nalt, "get_imagebase", lambda: 0x140000000, raising=False
    )
    try:
        cache_module.imported_ea.add(0x140001010)
        assert hexrays_module.is_imported(0x140001010) is True
        assert hexrays_module.is_imported(0x140002020) is False
    finally:
        cache_module.imported_ea.clear()
        domain_module.clear_fallback_records()
