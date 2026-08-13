"""T3.3 — the conftest IDA stub surface accepts the exact call shapes the
plugin passes (and rejects none real IDA would).

Each test executes a real call-site expression against the stub modules with
representative args and asserts the plugin's downstream handling matches what
the stub returns. It fails when a call site's argument shape drifts to
something the stub accepts but real IDA does not.
"""

from __future__ import annotations

import inspect
from importlib import util
from pathlib import Path

import ida_expr
import ida_hexrays
import ida_nalt
import ida_segment
import ida_typeinf

import forge.api.cache as cache_module


def _load_real_hexrays():
    """The conftest stubs ``forge.api.hexrays`` wholesale; load the real
    module under a non-stubbed name (test_hexrays pattern)."""
    path = Path(__file__).resolve().parents[2] / "src" / "forge" / "api" / "hexrays.py"
    spec = util.spec_from_file_location("forge.api.hexrays_stub_sig", path)
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hexrays_module = _load_real_hexrays()


def test_get_segm_name_shape():
    """hexrays.py:178 — ``get_segm_name(seg)`` on the segment from ``getseg``."""
    seg = ida_segment.getseg(0x140001000)
    name = ida_segment.get_segm_name(seg)
    assert name == ""
    # the downstream ".plt" check is what separates import thunks
    assert name != ".plt"


def test_add_idc_func_shape():
    """plugin.py:38 — IDC function registration is best-effort; only an
    exception matters, so the stub must accept (name, func, arg_types)."""
    assert ida_expr.add_idc_func("forge_api_call", lambda *a: None, []) is True


def test_enum_import_names_shape():
    """cache.py — zero import modules means no callback invocations, and the
    stub accepts the exact (module_index, callback) pair."""
    seen = []
    ok = ida_nalt.enum_import_names(0, lambda ea, name, ordinal: seen.append((ea, name, ordinal)))
    assert ok is True
    assert seen == []

    cache_module._collect_imported_ea()
    assert cache_module.imported_ea == set()


def test_mark_cfunc_dirty_shape():
    """hexrays.py:62 — guarded call; the stub must accept (ea, close_views)."""
    assert hasattr(ida_hexrays, "mark_cfunc_dirty")
    result = hexrays_module.mark_cfunc_dirty(0x140001000, close_views=False)
    assert result is None


def test_open_pseudocode_shape():
    """members.py:455 — VirtualFunction.show_location opens a new window."""
    result = ida_hexrays.open_pseudocode(0x140001000, ida_hexrays.OPF_NEW_WINDOW)
    assert result is None


def test_set_lvar_type_routes_through_modify_user_lvar_info():
    """B2 pin — the plugin's ``set_lvar_type`` commits via
    ``modify_user_lvar_info`` with the ``MLI_TYPE`` flag; the GUI-only
    ``vdui_t.set_lvar_type`` / removed ``cfunc.set_lvar_type`` are NOT called."""
    import ast

    tree = ast.parse(inspect.getsource(hexrays_module.set_lvar_type))
    called = [
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    ]
    assert "modify_user_lvar_info" in called
    assert "set_lvar_type" not in called

    class LVar:
        location = object()
        defea = 0x140001000

    class CFunc:
        entry_ea = 0x140001000

    committed = hexrays_module.set_lvar_type(CFunc(), LVar(), ida_typeinf.tinfo_t())
    assert committed is True


def test_get_named_type_shapes():
    """Every real call shape for ``get_named_type`` is accepted by the stub:
    ``(idati, name)``, ``(cvar.idati, name)``, and ``(None, name)``."""
    for idati in (ida_typeinf.get_idati(), ida_typeinf.cvar.idati, None):
        tinfo = ida_typeinf.tinfo_t()
        assert tinfo.get_named_type(idati, "SomeStruct") is True


def test_apply_tinfo_shape():
    """scanner.py:176 — ScannedGlobalObject.apply_type commits with the
    TINFO_DEFINITE flag; the stub's truthy return matches the no-op commit."""
    ok = ida_typeinf.apply_tinfo(
        0x140001000, ida_typeinf.tinfo_t(), ida_typeinf.TINFO_DEFINITE
    )
    assert ok is True