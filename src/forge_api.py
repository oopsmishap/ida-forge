"""forge_api - a flat, self-describing, LLM-friendly API for ida-forge.

Every user-visible forge capability is exposed as a single small function
returning plain JSON-serializable data (dict/list/str/int/bool/None). There is
no Qt, no hexrays widget, and no IDA dialog involved - ``import forge_api`` and
``forge_api.help()`` work even outside an IDA Pro session; functions that need
IDA raise a clear ``ForgeApiError`` when run without it.

Browse the catalog::

    import forge_api
    forge_api.help()                 # full catalog (signatures, docs, examples)
    forge_api.help("deep_scan")      # one entry

The Structure Builder workflow is: ``create_structure`` -> ``deep_scan``/``add_member``
(repeat / edit) -> ``finalize`` -> ``create_type`` (rebuilds the IDA type and
applies it to every variable the scan recorded). See each function's docstring
for the exact return shape; the ``example`` field in ``help()`` shows a concrete call.
"""

from __future__ import annotations

import contextlib
import importlib
import importlib.util
import inspect
import sys

from forge.api.store import catalog

__version__ = "0.1.0"

__all__ = [
    "add_member",
    "apply_type",
    "auto_resolve",
    "callees_of",
    "callers_of",
    "clear_structures",
    "create_child_types",
    "create_field",
    "create_structure",
    "create_type",
    "decompile",
    "deep_scan",
    "duplicate_structure",
    "finalize",
    "finalize_all",
    "function_info",
    "get_member",
    "get_structure",
    "guess_allocation",
    "help",
    "import_types",
    "imports",
    "inverse_if",
    "is_type",
    "link_child",
    "named_types",
    "nudge_members",
    "push_all",
    "push_type",
    "refresh_types",
    "remove_members",
    "remove_structure",
    "rename_local",
    "rename_structure",
    "scan_from_allocation",
    "scan_global",
    "set_current",
    "set_func_proto",
    "set_lvar_types",
    "set_member",
    "shallow_scan",
    "signature",
    "structures",
    "templated_apply",
    "templated_decl",
    "templated_keys",
    "to_hex",
    "to_usercall",
    "to_vtable",
    "type_of",
    "vtable_entries",
    "vtable_name",
]


class ForgeApiError(RuntimeError):
    """Raised for bad selections or an IDA-required function outside IDA."""


def _ida_available() -> bool:
    """True when an IDA Hex-Rays module is importable or already loaded.

    ``find_spec`` covers fresh imports; the ``sys.modules`` fallback covers
    conftest-stubbed environments (and a running IDA) where the module exists
    but carries no ``__spec__``.
    """
    if "ida_hexrays" in sys.modules:
        return True
    return importlib.util.find_spec("ida_hexrays") is not None


def _require_ida() -> None:
    """Raise unless a real (or stubbed) IDA Hex-Rays module is importable."""
    if not _ida_available():
        raise ForgeApiError(
            "forge_api.<function> requires an IDA Pro session with Hex-Rays"
        )


# --------------------------------------------------------------------------- #
# self-describing catalog
# --------------------------------------------------------------------------- #
_API: dict[str, dict] = {}


def api(*, group: str, returns: str, example: str):
    def decorate(fn):
        params = []
        for name, param in inspect.signature(fn).parameters.items():
            annotation = param.annotation
            if annotation is inspect.Parameter.empty:
                type_hint = ""
            else:
                type_hint = getattr(annotation, "__name__", str(annotation))
            params.append(
                {
                    "name": name,
                    "required": param.default is inspect.Parameter.empty,
                    "type": type_hint,
                }
            )
        _API[fn.__name__] = {
            "group": group,
            "doc": inspect.getdoc(fn) or "",
            "signature": str(inspect.signature(fn)),
            "params": params,
            "returns": returns,
            "example": example,
        }
        return fn

    return decorate


# --------------------------------------------------------------------------- #
# headless structure store (mirrors structure_form.structures, isolated)
# --------------------------------------------------------------------------- #
class _State:
    """Mutable holder for the headless store (functions never need `global`).

    ``structures`` is the shared :class:`StructureCatalog` (I.28) — the same
    objects the GUI Structure Builder form sees. ``current`` delegates to the
    catalog's current selection so persisted selections survive reloads.
    """

    def __init__(self):
        self.structures = catalog
        self.templated = None

    @property
    def current(self) -> str | None:
        return catalog.current

    @current.setter
    def current(self, value: str | None) -> None:
        catalog.current = value


_state = _State()
_structures = _state.structures


def _allocation_root_prior_type(ea: int, var_name: str) -> str | None:
    """The lvar's current type string when it is a pointer to a UDT.

    Returns ``None`` for untyped/integral/char-like roots — those already
    scan with byte semantics (O1: only struct-pointer-typed roots regress).
    """
    from forge.api.hexrays import decompile as _decompile

    cfunc = _decompile(ea)
    if cfunc is None:
        return None
    for lvar in list(cfunc.get_lvars()):
        if getattr(lvar, "name", None) != var_name:
            continue
        var_type = getattr(lvar, "type", None)
        if callable(var_type):
            # 9.4 exposes lvar_t.type as a method (O1 live finding).
            try:
                var_type = var_type()
            except Exception:  # noqa: BLE001 — degraded tinfo
                return None
        is_ptr = getattr(var_type, "is_ptr", None)
        get_pointed = getattr(var_type, "get_pointed_object", None)
        get_dstr = getattr(var_type, "dstr", None)
        if not (callable(is_ptr) and callable(get_pointed) and callable(get_dstr)):
            return None
        if not is_ptr():
            return None
        pointee = get_pointed()
        if callable(getattr(pointee, "is_udt", None)) and pointee.is_udt():
            try:
                return get_dstr()
            except Exception:  # noqa: BLE001 — degraded tinfo
                return None
        return None
    return None


def _mark_dirty() -> None:
    """Persist the shared catalog after an in-place store mutation."""
    from forge.api.store import catalog

    catalog._mark_dirty()


def _resolve_structure(structure_name: str | None = None, *, required: bool = True):
    structure = None
    if structure_name is not None:
        structure = _structures.get(structure_name)
    elif _state.current is not None:
        structure = _structures.get(_state.current)
    if required and structure is None:
        if structure_name is not None:
            raise ForgeApiError(f"no structure named {structure_name!r} in the forge_api store")
        raise ForgeApiError(
            "no structure selected; call forge_api.set_current(name) or pass structure=..."
        )
    return structure


def _member_type_str(member):
    tinfo = getattr(member, "tinfo", None)
    dstr = getattr(tinfo, "dstr", None)
    if callable(dstr):
        try:
            raw = dstr()
        except Exception:  # noqa: BLE001 — stub tinfos may lack anything
            return None
        if raw:
            try:
                from forge.api.members import normalize_type_display

                return normalize_type_display(raw)
            except Exception:  # noqa: BLE001 — facade import is best-effort
                return raw
        return raw
    return None


def _member_size(member):
    tinfo = getattr(member, "tinfo", None)
    get_size = getattr(tinfo, "get_size", None)
    if callable(get_size):
        try:
            size = get_size()
            if size >= 0:
                return size
        except Exception:  # noqa: BLE001 — stub tinfos may lack anything
            return None
    return None


def _to_member_dict(member) -> dict:
    score = None
    try:
        score = member.score
    except Exception:  # noqa: BLE001 — score needs a well-formed tinfo
        score = None
    return {
        "offset": getattr(member, "offset", 0),
        "name": getattr(member, "name", ""),
        "type": _member_type_str(member),
        "size": _member_size(member),
        "enabled": bool(getattr(member, "enabled", True)),
        "is_array": bool(getattr(member, "is_array", False)),
        "comment": getattr(member, "comment", ""),
        "origin": getattr(member, "origin", 0),
        "score": score,
    }


def _to_structure_dict(structure) -> dict:
    return {
        "name": structure.name,
        "main_offset": structure.main_offset,
        "created_type_name": structure.created_type_name,
        "members": [_to_member_dict(member) for member in structure.members],
        "collisions": list(structure.collisions),
        "child_relationships": [
            {
                "parent_structure_name": rel.parent_structure_name,
                "child_structure_name": rel.child_structure_name,
                "parent_member_offset": rel.parent_member_offset,
                "parent_member_name": rel.parent_member_name,
                "relation_kind": rel.relation_kind,
            }
            for rel in structure.child_relationships
        ],
    }


def _normalize_member_child_links(structure) -> None:
    """Rebind each member's child link to its relationship (form mirror)."""
    relationship_by_key = {
        (rel.child_structure_name, rel.parent_member_offset): rel
        for rel in structure.child_relationships
    }
    for member in structure.members:
        child_name = getattr(member, "linked_child_structure_name", None)
        if child_name is None:
            continue
        relationship = relationship_by_key.get((child_name, member.offset))
        if relationship is None:
            member.linked_child_structure_name = None
            member.child_relation_kind = None
            continue
        member.child_relation_kind = relationship.relation_kind


def _copy_duplicate_child_relationships(source, duplicate, structures: dict) -> None:
    for relationship in source.child_relationships:
        child_structure_name = (
            duplicate.name
            if relationship.child_structure_name == source.name
            else relationship.child_structure_name
        )
        source_member = source.get_member_by_offset(relationship.parent_member_offset)
        parent_member_name = (
            source_member.name
            if source_member is not None
            else relationship.parent_member_name
        )
        duplicated_relationship = duplicate.add_child_relationship(
            child_structure_name=child_structure_name,
            parent_member_offset=relationship.parent_member_offset,
            parent_member_name=parent_member_name,
            relation_kind=relationship.relation_kind,
        )
        child = structures.get(child_structure_name)
        if child is not None:
            child.add_parent_relationship(duplicated_relationship)
    _normalize_member_child_links(duplicate)


def _unique_structure_name(base_name: str) -> str:
    return catalog.unique_name(base_name)


def _ensure_placeholder_type(store_name: str) -> bool:
    """Make the IDB know a store structure's name so self/forward references
    parse before the real type is committed.

    The chicken-egg: ``add_member(..., "GridNode *")`` cannot parse until an
    IDB type named ``GridNode`` exists, but committing ``GridNode`` first
    was blocked while it was being refined (R10). The placeholder is a
    minimal struct that the overwrite path (R10) replaces wholesale at
    commit time. Idempotent — skips when the type already exists.

    Returns:
        bool — True when the store name is already an IDB type or the
        placeholder parsed.
    """
    if store_name not in _structures:
        return False
    if is_type(store_name):
        return True
    import ida_typeinf

    for placeholder_decl in (
        f"struct {store_name} {{ char _placeholder; }};",
        f"struct {store_name} {{ unsigned char _placeholder; }};",
    ):
        try:
            if ida_typeinf.idc_parse_types(placeholder_decl, 0):
                return True
        except Exception as exc:  # noqa: BLE001 — version/format tolerance
            from forge.util.logging import log_debug

            log_debug(
                f"Placeholder parse failed for {store_name}: "
                f"{placeholder_decl!r} ({exc})"
            )
    return False


# --------------------------------------------------------------------------- #
# meta
# --------------------------------------------------------------------------- #
@api(
    group="meta",
    returns="dict",
    example='catalog = forge_api.help()',
)
def help(topic: str | None = None) -> dict:
    """Return the self-describing catalog of every forge_api function.

    With ``topic`` returns only that entry (raises :class:`ForgeApiError` for an
    unknown name); without it returns all entries. Works outside IDA. Each entry
    has ``group``/``signature``/``doc``/``params``/``returns``/``example``.

    Returns:
        dict with ``module``, ``version`` and ``functions`` (name -> entry).
    """
    ordered = {
        name: _API[name]
        for name in sorted(_API, key=lambda n: (_API[n]["group"], n))
    }
    if topic is not None:
        entry = _API.get(topic)
        if entry is None:
            raise ForgeApiError(f"unknown topic {topic!r}")
        ordered = {topic: entry}
    return {"module": __name__, "version": __version__, "functions": ordered}


@api(
    group="meta",
    returns="str",
    example='forge_api.to_hex(0x401000)',
)
def to_hex(ea: int) -> str:
    """Format an address as a hex string for display or logging.

    This function is pure and works outside IDA.

    Returns:
        str like ``"0x401000"``.
    """
    try:
        from forge.api.hexrays import to_hex as _to_hex
    except (ImportError, ModuleNotFoundError):
        return f"0x{ea:08X}"
    return _to_hex(ea)


# --------------------------------------------------------------------------- #
# decompile / named types
# --------------------------------------------------------------------------- #
@api(
    group="decompile",
    returns="dict | None",
    example='d = forge_api.decompile(0x1400014F0); d["lvars"]',
)
def decompile(
    ea: int,
    *,
    max_lines: int | None = None,
    line_range: tuple[int, int] | None = None,
    force: bool = False,
) -> dict | None:
    """Decompile the function containing ``ea``: pseudocode, variables, calls.

    Returns ``None`` when the address is not in a function. The pseudocode is a
    single flattened string; ``lvars`` carries each local with its index, name,
    type declaration and whether it is a function argument; ``calls`` lists the
    EAs of functions called from the body. ``line_range`` (1-based, inclusive)
    or ``max_lines`` slice the pseudocode lines only — ``lvars``/``calls`` are
    untouched. ``force=True`` clears IDA's cached cfunctions first so freshly
    retyped globals/locals render (``clear_cached_cfuncs``).

    Returns:
        dict or None.
    """
    _require_ida()
    import ida_funcs
    import ida_hexrays
    import ida_idaapi
    import ida_lines

    from forge.api.hexrays import ctype as _ctype
    from forge.api.hexrays import decompile as _decompile

    if force and hasattr(ida_hexrays, "clear_cached_cfuncs"):
        ida_hexrays.clear_cached_cfuncs()
    cfunc = _decompile(ea)
    if cfunc is None:
        return None
    cfunc.get_pseudocode()

    # get_lvars() returns an ida_hexrays.lvars_t whose int indexing is not
    # usable in every build; materialize a plain list (iteration is supported).
    lvars = list(cfunc.get_lvars())
    lvar_rows = []
    for index, lvar in enumerate(lvars):
        type_str = None
        try:
            type_str = lvar.type().dstr()
        except Exception:  # noqa: BLE001 — broken lvar types degrade to None
            type_str = None
        lvar_rows.append(
            {
                "index": index,
                "name": lvar.name,
                "type": type_str,
                "is_arg": bool(getattr(lvar, "is_arg_var", False)),
            }
        )

    pseudocode_lines = []
    for line in cfunc.pseudocode:
        text = getattr(line, "line", None)
        pseudocode_lines.append(
            ida_lines.tag_remove(text) if isinstance(text, str) else str(line)
        )

    if line_range is not None:
        start, end = line_range
        pseudocode_lines = pseudocode_lines[max(0, start - 1) : end]
    elif max_lines is not None and max_lines >= 0:
        pseudocode_lines = pseudocode_lines[:max_lines]

    # cfunc.treeitems yields ida_hexrays.citem_t; the specific expression (with
    # .x / .obj_ea) is reached through the `to_specific_type` property.
    calls = set()
    for item in getattr(cfunc, "treeitems", []) or []:
        specific = getattr(item, "to_specific_type", None) or item
        if getattr(specific, "op", None) == _ctype.call:
            callee_ea = getattr(getattr(specific, "x", None), "obj_ea", None)
            if callee_ea is not None and callee_ea != ida_idaapi.BADADDR:
                calls.add(callee_ea)

    return {
        "ea": ea,
        "name": ida_funcs.get_func_name(ea),
        "pseudocode": "\n".join(pseudocode_lines),
        "lvars": lvar_rows,
        "calls": sorted(calls),
    }


@api(
    group="decompile",
    returns="str | None",
    example='proto = forge_api.signature(0x1400014F0)',
)
def signature(ea: int) -> str | None:
    """Return the function's first pseudocode line (its prototype).

    ``World *__fastcall sub_1400017A0(World *a1)`` for a typed function.
    Returns ``None`` when ``ea`` is not in a function or the function has no
    pseudocode.

    Returns:
        str or None.
    """
    result = decompile(ea, max_lines=1)
    if result is None:
        return None
    return result["pseudocode"] or None


@api(
    group="decompile",
    returns="list[int]",
    example='sources = forge_api.callers_of(0x1400014F0, "data")',
)
def callers_of(ea: int, kind: str = "code") -> list[int]:
    """List the functions whose code/data points at ``ea``.

    ``kind="code"`` walks code xrefs (``get_first_cref_to``), ``"data"`` data
    xrefs (``get_first_dref_to``); each source is resolved to its containing
    function start so the result is a set of function EAs (vtable/RTTI
    discovery uses ``kind="data"``). Sources outside any function report their
    raw EA. Unknown kinds return ``[]``.

    Returns:
        sorted list of function-start EAs.
    """
    _require_ida()
    import ida_funcs
    import ida_idaapi
    import ida_xref

    if kind == "code":
        get_first, get_next = ida_xref.get_first_cref_to, ida_xref.get_next_cref_to
    elif kind == "data":
        get_first, get_next = ida_xref.get_first_dref_to, ida_xref.get_next_dref_to
    else:
        return []

    starts = []
    seen = set()
    source = get_first(ea)
    while source not in (ida_idaapi.BADADDR, None) and source not in seen:
        seen.add(source)
        function = ida_funcs.get_func(source)
        starts.append(function.start_ea if function is not None else source)
        source = get_next(ea, source)
    return sorted(set(starts))


@api(
    group="decompile",
    returns="list[int]",
    example='targets = forge_api.callees_of(0x1400014F0)',
)
def callees_of(ea: int) -> list[int]:
    """List the functions called from the function containing ``ea``.

    Reuses the decompiler's call-expression scan (``decompile(...).calls``).
    Returns ``[]`` when ``ea`` is not in a function.

    Returns:
        sorted list of callee EAs.
    """
    result = decompile(ea)
    return result["calls"] if result is not None else []


@api(
    group="decompile",
    returns="dict | None",
    example='info = forge_api.function_info(0x1400014F0); info["callers"]',
)
def function_info(ea: int) -> dict | None:
    """Aggregate recon for the function containing ``ea``.

    Returns ``None`` when ``ea`` is not in a function, else
    ``{"name", "start_ea", "size", "prototype", "callers", "callees",
    "refs"}`` — ``refs`` is the union of code and data xref sources (in
    function-start terms, like :func:`callers_of`).

    Returns:
        dict or None.
    """
    _require_ida()
    import ida_funcs

    function = ida_funcs.get_func(ea)
    if function is None:
        return None
    code_callers = callers_of(ea, "code")
    data_callers = callers_of(ea, "data")
    return {
        "name": ida_funcs.get_func_name(ea),
        "start_ea": function.start_ea,
        "size": function.end_ea - function.start_ea,
        "prototype": signature(ea),
        "callers": code_callers,
        "callees": callees_of(ea),
        "refs": sorted(set(code_callers) | set(data_callers)),
    }


@api(
    group="decompile",
    returns="list[dict]",
    example='imports = forge_api.imports("Validate")',
)
def imports(pattern: str | None = None) -> list[dict]:
    """List the database's import table entries.

    Walks ``idautils.Entries()`` (available in every supported IDA version —
    ``idautils.imports`` does not exist in 9.4 and is never used), resolving
    each entry's name and the module (segment) it landed in. With ``pattern``
    given, rows are case-folded substring-filtered on the name; an empty list
    is a valid result.

    Returns:
        ``[{"module", "ea", "name"}, ...]`` sorted by EA.
    """
    _require_ida()
    import ida_name
    import ida_segment
    import idautils

    rows = []
    for entry in idautils.Entries():
        # shape differs across IDA versions: (ea, ordinal, name) or
        # (index, ordinal, ea, name) — normalize by length
        if len(entry) == 3:
            _ordinal, ea, name = entry
        elif len(entry) == 4:
            _index, _ordinal, ea, name = entry
        else:
            continue
        resolved = name or ida_name.get_name(ea)
        segment = ida_segment.getseg(ea)
        module = (
            ida_segment.get_segm_name(segment)
            if segment is not None
            else ""
        )
        rows.append({"module": module, "ea": ea, "name": resolved})
    if pattern:
        folded = pattern.casefold()
        rows = [row for row in rows if folded in row["name"].casefold()]
    return sorted(rows, key=lambda row: row["ea"])


@api(
    group="decompile",
    returns="dict",
    example='r = forge_api.set_lvar_types(0x1400014F0, {"a1": "World *"}); r["updated"]',
)
def set_lvar_types(ea: int, types, *, scope: str = "arg") -> dict:
    """Commit C types onto the function's local variables headless.

    ``types`` maps each local name to a C declaration (``dict`` or list of
    ``(name, decl)`` tuples). ``"*"`` is shorthand for ``void *``. With the
    default ``scope="arg"`` only function arguments are retyped; pass
    ``scope="all"`` to also retype plain locals. Each entry resolves
    independently — a missing name or unparsable declaration reports
    ``ok: False`` for that entry without aborting the rest. The result's
    ``signature`` is the first pseudocode line of a fresh decompile, so the
    caller sees the committed prototype immediately.

    Returns:
        ``{"ok": bool, "updated": [{"name", "ok"}],
        "signature": str | None}``.
    """
    _require_ida()
    from forge.api.hexrays import decompile as _decompile
    from forge.api.hexrays import mark_cfunc_dirty as _mark_cfunc_dirty
    from forge.api.hexrays import set_lvar_type as _set_lvar_type
    from forge.api.members import parse_user_tinfo

    cfunc = _decompile(ea)
    if cfunc is None:
        return {"ok": False, "error": f"could not decompile {hex(ea)}"}
    lvars = list(cfunc.get_lvars())
    by_name = {lvar.name: lvar for lvar in lvars}

    pairs = list(types.items()) if isinstance(types, dict) else list(types)
    updated = []
    any_ok = False
    for name, declaration in pairs:
        lvar = by_name.get(name)
        if lvar is None or (scope == "arg" and not getattr(lvar, "is_arg_var", False)):
            updated.append({"name": name, "ok": False})
            continue
        c_decl = "void *" if declaration == "*" else declaration
        tinfo = parse_user_tinfo(c_decl)
        if tinfo is None:
            updated.append({"name": name, "ok": False})
            continue
        if _set_lvar_type(cfunc, lvar, tinfo):
            updated.append({"name": name, "ok": True})
            any_ok = True
        else:
            updated.append({"name": name, "ok": False})

    signature = None
    if any_ok:
        _mark_cfunc_dirty(ea)
        fresh = _decompile(ea)
        if fresh is not None:
            import ida_lines

            for line in fresh.pseudocode:
                text = getattr(line, "line", None)
                rendered = (
                    ida_lines.tag_remove(text) if isinstance(text, str) else str(line)
                )
                if rendered:
                    signature = rendered
                    break
    return {"ok": any_ok, "updated": updated, "signature": signature}


@api(
    group="types",
    returns="dict",
    example='r = forge_api.set_func_proto(0x1400014F0, "int __cdecl f(World *, char *)")',
)
def set_func_proto(ea: int, declaration: str) -> dict:
    """Set a function's prototype in the IDB.

    Parses ``declaration`` as a function type (the til must be the local
    til — ``None`` silently fails) and applies it via ``ida_funcs.set_ti``.
    The result's ``prototype`` is the re-decompiled first line.

    Returns:
        ``{"ok": True, "ea": int, "prototype": str}`` or
        ``{"ok": False, "error": str}``.
    """
    _require_ida()
    import ida_funcs
    import ida_typeinf

    t = ida_typeinf.tinfo_t()
    parsed_name = ida_typeinf.parse_decl(
        t,
        ida_typeinf.get_idati(),
        declaration,
        ida_typeinf.PT_TYP | ida_typeinf.PT_SIL,
    )
    if parsed_name is None:
        return {"ok": False, "error": f"could not parse declaration {declaration!r}"}
    ida_funcs.set_ti(ea, t)
    return {"ok": True, "ea": ea, "prototype": signature(ea)}


@api(
    group="decompile",
    returns="bool",
    example='renamed = forge_api.rename_local(0x1400014F0, "a1", "world")',
)
def rename_local(ea: int, name_or_index, new_name: str | None = None) -> bool:
    """Rename a local variable (``rename_lvar``, the surviving headless API).

    ``name_or_index`` is the variable's name or its 0-based lvar index.
    Returns False when the function cannot be decompiled, the name/index is
    unknown, or IDA declines the rename.

    Returns:
        bool.
    """
    _require_ida()
    import ida_hexrays

    from forge.api.hexrays import decompile as _decompile

    cfunc = _decompile(ea)
    if cfunc is None:
        return False
    old_name = name_or_index
    if isinstance(name_or_index, int):
        lvars = list(cfunc.get_lvars())
        if not 0 <= name_or_index < len(lvars):
            return False
        old_name = lvars[name_or_index].name
    if not old_name:
        return False
    return bool(ida_hexrays.rename_lvar(ea, old_name, new_name))


@api(
    group="types",
    returns="list[str]",
    example='names = forge_api.named_types()',
)
def named_types() -> list[str]:
    """List every named type currently in the IDB (structs, enums, typedefs).

    Returns:
        sorted list of type names.
    """
    _require_ida()
    import ida_typeinf

    idati = ida_typeinf.get_idati()
    names = []
    for ordinal in range(ida_typeinf.get_ordinal_count(idati)):
        tinfo = ida_typeinf.tinfo_t()
        if tinfo.get_numbered_type(idati, ordinal):
            name = tinfo.get_type_name()
            if name:
                names.append(name)
    return sorted(set(names))


@api(
    group="types",
    returns="dict | None",
    example='t = forge_api.type_of("Recovered"); t["members"]',
)
def type_of(name: str) -> dict | None:
    """Describe an IDB named type: declaration string, size, kind, members.

    For UDTs ``members`` lists each udt member's ``offset``/``size`` in bytes
    (converted from IDA's bit units when bit-aligned; ``bit_offset`` always
    carries the raw value) plus ``name`` and ``type``. Returns ``None`` when
    ``name`` is not a known type.

    Returns:
        dict or None.
    """
    _require_ida()
    import ida_typeinf

    idati = ida_typeinf.get_idati()
    tinfo = ida_typeinf.tinfo_t()
    if not tinfo.get_named_type(idati, name):
        return None

    if tinfo.is_udt():
        kind = "struct"
    elif tinfo.is_ptr():
        kind = "pointer"
    elif tinfo.is_func():
        kind = "function"
    else:
        kind = "scalar"

    members = []
    if kind == "struct":
        udt_data = ida_typeinf.udt_type_data_t()
        if tinfo.get_udt_details(udt_data):
            for member in udt_data:
                # udt members report offsets/sizes in BITS; convert to the
                # byte units the rest of forge_api uses when bit-clean, and
                # keep the raw bit value available.
                offset_raw = getattr(member, "offset", 0)
                size_raw = getattr(member, "size", 0)
                member_type = None
                try:
                    member_type = member.type.dstr()
                except Exception:  # noqa: BLE001 — broken udt handles degrade
                    member_type = None
                members.append(
                    {
                        "offset": offset_raw // 8 if offset_raw % 8 == 0 else offset_raw,
                        "size": size_raw // 8 if size_raw % 8 == 0 else size_raw,
                        "bit_offset": offset_raw,
                        "name": getattr(member, "name", ""),
                        "type": member_type,
                    }
                )
            members.sort(key=lambda m: m["offset"])

    return {
        "name": name,
        "type": tinfo.dstr(),
        "size": tinfo.get_size(),
        "kind": kind,
        "members": members,
    }


@api(
    group="types",
    returns="bool",
    example='present = forge_api.is_type("World")',
)
def is_type(name: str) -> bool:
    """Return whether ``name`` is a named type in the IDB.

    Thin existence guard for ``create_type``/``to_vtable`` callers, using
    the same ``tinfo_t.get_named_type`` lookup as :func:`type_of`.

    Returns:
        bool.
    """
    _require_ida()
    import ida_typeinf

    tinfo = ida_typeinf.tinfo_t()
    return bool(tinfo.get_named_type(ida_typeinf.get_idati(), name))


@api(
    group="types",
    returns="dict",
    example='r = forge_api.apply_type(0x1400060C0, "OuterAggregate", redefine_range=True)',
)
def apply_type(
    ea: int, declaration: str, *, redefine_range: bool = False
) -> dict:
    """Apply a parsed type at any address — no scan evidence needed.

    ``create_type`` only types variables the scans recorded; ``apply_type``
    types an arbitrary global, local or data address from a C declaration.
    Store-structure names resolve via a lazy placeholder (same path as
    :func:`add_member`), so ``"GridNode"`` parses before its type exists.
    With ``redefine_range=True`` the type's byte span is first cleared: auto
    names on heads inside ``[ea, ea + size)`` are deleted (so a flattened
    ``qword_...`` chain cannot shadow the struct), then ``del_items`` (a
    simple delete), then the type is applied with ``TINFO_DEFINITE`` — the
    sequence that makes a global render as ``g_outer.cell_meta[0].tag``.

    Returns:
        ``{"ok": True, "ea": int, "type": str}`` or
        ``{"ok": False, "error": str}``.
    """
    _require_ida()
    import re as _re

    import ida_bytes
    import ida_name
    import ida_typeinf

    from forge.api.members import parse_user_tinfo

    tinfo = parse_user_tinfo(declaration)
    if tinfo is None:
        base_name = _re.sub(
            r"(?:\s*\*+\s*|\s*\[[^\]]*\]\s*)+$", "", declaration.strip()
        )
        if base_name in _structures and _ensure_placeholder_type(base_name):
            tinfo = parse_user_tinfo(declaration)
    if tinfo is None:
        return {"ok": False, "error": f"could not parse declaration {declaration!r}"}

    if redefine_range:
        size = tinfo.get_size()
        if size is not None and size > 0 and size != ida_typeinf.BADSIZE:
            for head in range(ea, ea + size):
                if head == ea:
                    continue
                flags = ida_bytes.get_flags(head)
                if not ida_bytes.is_head(flags):
                    continue
                if not ida_name.get_name(head):
                    continue
                # Keep user-typed names; strip the auto qword_/xmmword_
                # shadowing names so the struct owns the range.
                if hasattr(ida_bytes, "has_user_name") and ida_bytes.has_user_name(flags):
                    continue
                ida_name.del_global_name(head)
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, ea + size)

    ida_typeinf.apply_tinfo(ea, tinfo, ida_typeinf.TINFO_DEFINITE)
    return {"ok": True, "ea": ea, "type": tinfo.dstr()}


# --------------------------------------------------------------------------- #
# structure store
# --------------------------------------------------------------------------- #
@api(
    group="structures",
    returns="bool",
    example='forge_api.set_current("Recovered")',
)
def set_current(name: str) -> bool:
    """Select the store structure that ``structure=None`` functions act on.

    The store is isolated from the GUI Structure Builder form. Returns ``False``
    (no raise) when ``name`` is not in the store.

    Returns:
        bool.
    """
    if name not in _structures:
        return False
    _state.current = name
    return True


@api(
    group="structures",
    returns="list[str]",
    example='names = forge_api.structures()',
)
def structures() -> list[str]:
    """List the names of every structure in the headless store.

    Returns:
        sorted list of structure names.
    """
    return sorted(_structures)


@api(
    group="structures",
    returns="None",
    example="forge_api.clear_structures()",
)
def clear_structures() -> None:
    """Remove every structure from the shared store (not from the IDB).

    Also drops the persisted catalog so a cleared session does not resurrect
    stale structures on the next load. Returns None.
    """
    catalog.clear()
    try:
        from forge.api.storage import Storage

        Storage("Structures").kill()
    except Exception as exc:  # noqa: BLE001 — storage may be unavailable headless
        from forge.util.logging import log_warning

        log_warning(f"could not drop persisted structure catalog: {exc}")


@api(
    group="structures",
    returns="dict | None",
    example='s = forge_api.get_structure("Recovered")',
)
def get_structure(name: str | None = None) -> dict | None:
    """Return a structure's full model (members, collisions, relationships).

    With ``name`` None, returns the current structure. Returns ``None`` when no
    structure matches and none is selected.

    Returns:
        dict with ``name``/``main_offset``/``created_type_name``/``members``/
        ``collisions``/``child_relationships`` or None.
    """
    structure = _resolve_structure(name, required=False)
    if structure is None:
        return None
    return _to_structure_dict(structure)


@api(
    group="structures",
    returns="dict | None",
    example='m = forge_api.get_member("Recovered", 0x10)',
)
def get_member(
    structure: str | None = None,
    offset: int = 0,
    *,
    include_disabled: bool = True,
) -> dict | None:
    """Return the first member dict at ``offset``.

    Unlike :meth:`Structure.get_member_by_offset`, ``include_disabled=False``
    skips collision-disabled members. Returns ``None`` when no structure is
    selected/resolvable or no member matches (read-side convention matches
    :func:`get_structure`).

    Returns:
        member dict or None.
    """
    target = _resolve_structure(structure, required=False)
    if target is None:
        return None
    for member in target.members:
        if member.offset != offset:
            continue
        if not include_disabled and not member.enabled:
            continue
        return _to_member_dict(member)
    return None


@api(
    group="structures",
    returns="dict",
    example='s = forge_api.create_structure("Recovered")',
)
def create_structure(
    name: str, members: list[dict] | None = None, origin: int = 0
) -> dict:
    """Create a structure in the headless store and select it.

    ``members`` is an optional list of member specs: ``{"offset": int, "type":
    str, "name": str|None, "comment": str|None, "enabled": bool, "is_array":
    bool}``, each inserted through the same path as :func:`add_member`. Raises
    :class:`ForgeApiError` when the name already exists in the store. Nothing is
    written to the IDB until :func:`create_type`/:func:`finalize`.

    Returns:
        the new structure's dict (see :func:`get_structure`).
    """
    from forge.api.structure import Structure

    if name in _structures:
        raise ForgeApiError(f"structure {name!r} already exists")
    structure = Structure(name)
    _structures[name] = structure
    _state.current = name
    for spec in members or []:
        add_member(
            name,
            offset=spec["offset"],
            type=spec["type"],
            name=spec.get("name"),
            comment=spec.get("comment", ""),
            origin=spec.get("origin", origin),
            is_array=spec.get("is_array", False),
            enabled=spec.get("enabled", True),
        )
    return _to_structure_dict(structure)


@api(
    group="structures",
    returns="bool",
    example='removed = forge_api.remove_structure("Recovered")',
)
def remove_structure(name: str | None = None) -> bool:
    """Remove a structure from the headless store and unlink its relationships.

    With ``name`` None, removes the current structure. Returns whether a
    structure was removed.

    Returns:
        bool.
    """
    structure = _resolve_structure(name, required=False)
    if structure is None:
        return False
    del _structures[structure.name]
    for other in _structures.values():
        other.remove_relationships_with(structure.name)
    if _state.current == structure.name:
        _state.current = None
    return True


def _declaration_base_name(declaration: str) -> str:
    """Strip trailing pointer/array suffixes: ``"GridNode *"`` -> ``"GridNode"``."""
    import re as _re

    return _re.sub(r"(?:\s*\*+\s*|\s*\[[^\]]*\]\s*)+$", "", declaration.strip())


@api(
    group="structures",
    returns="dict",
    example='m = forge_api.add_member("Recovered", 0x10, "u32", name="count")',
)
def add_member(
    structure: str | None = None,
    offset: int = 0,
    type: str = "u32",
    name: str | None = None,
    comment: str = "",
    origin: int = 0,
    is_array: bool = False,
    enabled: bool = True,
) -> dict:
    """Add a member at ``offset`` with the given type to a store structure.

    ``type`` is a C type declaration parsed the same way the GUI accepts it
    (e.g. ``"u32"``, ``"MyStruct *"``, ``"__int64[8]"``). Store-structure
    names (``"GridNode *"`` for a store ``GridNode``) resolve via a lazy
    placeholder IDB type, so self/forward references parse before the real
    type exists. Returns the new member dict, or
    ``{"ok": False, "error": ...}`` when the type does not parse.

    Returns:
        member dict (see member fields on :func:`get_structure`).
    """
    from forge.api.members import Member, parse_user_tinfo

    target = _resolve_structure(structure)
    tinfo = parse_user_tinfo(type)
    if tinfo is None:
        base_name = _declaration_base_name(type)
        if base_name in _structures and _ensure_placeholder_type(base_name):
            tinfo = parse_user_tinfo(type)
    if tinfo is None:
        return {"ok": False, "error": f"could not parse type {type!r}"}
    member = Member(offset, tinfo, None, origin)
    if name is not None:
        member.name = name
    member.comment = comment
    member.is_array = is_array
    if not enabled:
        member.set_enabled(False)
    target.add_member(member)
    result = _to_member_dict(member)
    result["collision"] = target.has_collision(target.members.index(member))
    _mark_dirty()
    return result


@api(
    group="structures",
    returns="None",
    example='forge_api.remove_members("Recovered", [0x10, 0x18])',
)
def remove_members(structure: str | None = None, offsets: list = ()) -> None:
    """Remove the members at the given offsets from a store structure.

    Unknown offsets are ignored. Collisions are refreshed afterwards.

    Returns:
        None.
    """
    target = _resolve_structure(structure)
    indices = []
    for index, member in enumerate(target.members):
        if member.offset in offsets:
            indices.append(index)
    target.remove_members(indices)
    _mark_dirty()


@api(
    group="structures",
    returns="dict",
    example='m = forge_api.set_member("Recovered", 0x10, name="size", enabled=False)',
)
def set_member(
    structure: str | None = None,
    offset: int = 0,
    *,
    type: str | None = None,
    name: str | None = None,
    comment: str | None = None,
    enabled: bool | None = None,
    is_array: bool | None = None,
) -> dict:
    """Edit the member at ``offset`` in a store structure.

    Only the provided keyword fields change. ``type`` must parse as a C type;
    a parse failure returns ``{"ok": False, "error": ...}`` without changing
    anything. Raises :class:`ForgeApiError` when no member exists at ``offset``.

    Returns:
        the updated member dict.
    """
    from forge.api.members import parse_user_tinfo

    target = _resolve_structure(structure)
    member = target.get_member_by_offset(offset)
    if member is None:
        raise ForgeApiError(f"no member at offset 0x{offset:x}")
    if type is not None:
        tinfo = parse_user_tinfo(type)
        if tinfo is None:
            base_name = _declaration_base_name(type)
            if base_name in _structures and _ensure_placeholder_type(base_name):
                tinfo = parse_user_tinfo(type)
        if tinfo is None:
            return {"ok": False, "error": f"could not parse type {type!r}"}
        member.tinfo = tinfo
        member.is_array = False
        member.invalidate_score()
    if name is not None:
        member.name = name
    if comment is not None:
        member.comment = comment
    if is_array is not None:
        member.is_array = is_array
        member.invalidate_score()
    if enabled is not None and hasattr(member, "set_enabled"):
        member.set_enabled(bool(enabled))
    target.refresh_collisions()
    result = _to_member_dict(member)
    result["collision"] = target.has_collision(target.members.index(member))
    _mark_dirty()
    return result


@api(
    group="structures",
    returns="dict",
    example='l = forge_api.link_child("Recovered", 0x10, "ChildStruct")',
)
def link_child(
    structure: str | None = None,
    offset: int = 0,
    child_name: str = "",
) -> dict:
    """Link a store member to another store structure (child relationship).

    ``child_name`` must be in the store (else :class:`ForgeApiError`). If no
    member exists at ``offset`` a placeholder ``u32`` member is created
    first. The member becomes the parent pointer: ``linked_child_structure_name``
    + ``child_relation_kind="pointer"``, and the child/parent relationship
    records are kept on both structures so :func:`create_child_types` /
    :func:`finalize` child machinery works for hand-built structures.

    Returns:
        the (linked) member dict.
    """
    target = _resolve_structure(structure)
    if child_name not in _structures:
        raise ForgeApiError(
            f"no structure named {child_name!r} in the forge_api store"
        )
    child = _structures[child_name]
    member = target.get_member_by_offset(offset)
    if member is None:
        created = add_member(target.name, offset, "u32")
        if created.get("ok") is False:
            raise ForgeApiError(
                f"could not create placeholder member at 0x{offset:x}"
            )
        member = target.get_member_by_offset(offset)
    member.linked_child_structure_name = child_name
    member.child_relation_kind = "pointer"
    relationship = target.add_child_relationship(
        child_structure_name=child_name,
        parent_member_offset=offset,
        parent_member_name=member.name,
        relation_kind="pointer",
    )
    child.add_parent_relationship(relationship)
    _mark_dirty()
    return _to_member_dict(member)


@api(
    group="structures",
    returns="dict",
    example='r = forge_api.nudge_members("Recovered", [0x10, 0x18], 8)',
)
def nudge_members(
    structure: str | None = None, offsets: list = (), delta: int = 0
) -> dict:
    """Shift the given member offsets by ``delta`` (form ``nudge_selected_rows``).

    Mirrors the GUI rule: a nudge that would make a member overlap a member that
    was NOT moved is rejected and restored. Negative ``delta`` moving a member
    below zero is also rejected. The structure's ``main_offset`` follows when a
    moved member is the origin row.

    Returns:
        ``{"ok": True}`` or ``{"ok": False, "error": ...}``.
    """
    target = _resolve_structure(structure)
    members = [m for m in target.members if m.offset in offsets]
    if not members:
        return {"ok": True}
    if any(member.offset + delta < 0 for member in members):
        return {"ok": False, "error": "cannot move rows to a negative offset"}

    moved = {id(member) for member in members}
    original_offsets = {id(member): member.offset for member in target.members}
    original_main_offset = target.main_offset

    for member in members:
        old_offset = member.offset
        member.offset += delta
        member.invalidate_score()
        if target.main_offset == old_offset:
            target.set_main_offset(member.offset)

    target.members.sort()
    target.refresh_collisions()

    collides_outside_selection = any(
        target.has_collision(index) and id(member) not in moved
        for index, member in enumerate(target.members)
    )
    if collides_outside_selection:
        for member in target.members:
            member.offset = original_offsets[id(member)]
        target.set_main_offset(original_main_offset)
        target.members.sort()
        target.refresh_collisions()
        return {"ok": False, "error": "would overlap a non-selected member"}

    _mark_dirty()
    return {"ok": True}


@api(
    group="structures",
    returns="dict",
    example='r = forge_api.auto_resolve("Recovered")',
)
def auto_resolve(structure: str | None = None) -> dict:
    """Disable the lower-scoring half of each colliding member pair.

    Applies the same collision-resolution heuristic as the form's "Auto
    resolve". The disabled member dicts are returned so the caller can preview
    or revert.

    Returns:
        ``{"ok": True, "disabled": [member dicts]}``.
    """
    target = _resolve_structure(structure)
    disabled = target.auto_resolve()
    _mark_dirty()
    return {"ok": True, "disabled": [_to_member_dict(m) for m in disabled]}


@api(
    group="structures",
    returns="bool",
    example='ok = forge_api.rename_structure("Recovered", "Recovered2")',
)
def rename_structure(old: str, new: str) -> bool:
    """Rename a structure in the store (updates relationships).

    If the structure had a created IDA type named ``old``, the IDA type is
    renamed too. Returns ``False`` (no raise) when ``new`` already exists; raises
    :class:`ForgeApiError` when ``old`` is not in the store.

    Returns:
        bool.
    """
    structure = _resolve_structure(old)
    if new in _structures:
        return False
    if not structure.rename_created_type(old, new):
        return False
    structure.name = new
    structure.is_auto_named = False
    _structures[new] = structure
    del _structures[old]
    for other in _structures.values():
        other.rename_relationship_references(old, new)
    if _state.current == old:
        _state.current = new
    return True


@api(
    group="structures",
    returns="str",
    example='new = forge_api.duplicate_structure("Recovered")',
)
def duplicate_structure(name: str) -> str:
    """Duplicate a store structure (members, provenance, child relationships).

    The duplicate gets a free name (``"X Copy"``, then ``"X Copy 2"``, ...) and
    becomes the current structure. Child members are re-linked to the duplicate
    like the form's duplicate action.

    Returns:
        the new structure's name.
    """
    import copy as _copy

    from forge.api.structure import Structure

    source = _resolve_structure(name)
    new_name = _unique_structure_name(source.name)
    cloned = Structure(new_name)
    cloned.main_offset = source.main_offset
    cloned.members = [
        _copy.copy(member) for member in source.members
    ]
    for member in cloned.members:
        if hasattr(member, "scanned_variables"):
            member.scanned_variables = set(member.scanned_variables)
    cloned.provenance = source.clone_provenance()
    cloned.is_auto_named = True
    _structures[new_name] = cloned
    _copy_duplicate_child_relationships(source, cloned, _structures)
    cloned.refresh_collisions()
    _state.current = new_name
    return new_name


@api(
    group="structures",
    returns="dict",
    example='vt = forge_api.to_vtable("Recovered", 0x0, 0x140006358)',
)
def to_vtable(structure: str | None = None, offset: int = 0, address: int = 0) -> dict:
    """Convert the member at ``offset`` into a vtable row at ``address``.

    Reads the vtable pointer table at ``address`` (IDA functions) and replaces
    the member with a :class:`VirtualTable`; the member's name, scanned
    variables and comment carry over. When no member exists at the offset
    (rows whose members are all collision-disabled) an enabled placeholder is
    created first, so the vtable row is never lost.

    Returns:
        the new vtable member dict.
    """
    _require_ida()
    from forge.api.members import Member, VirtualTable, parse_user_tinfo

    target = _resolve_structure(structure)
    member = target.get_member_by_offset(offset)
    if member is None:
        # No member at all (offsets whose rows are all collision-disabled):
        # build an enabled placeholder so the row still converts without
        # silently losing the vtable.
        tinfo = parse_user_tinfo("u32")
        if tinfo is None:
            raise ForgeApiError(f"no member at offset 0x{offset:x}")
        member = Member(offset, tinfo, None, 0)
        target.add_member(member)
    target.members.remove(member)
    vtable = VirtualTable(offset, address, None, member.origin)
    vtable.scanned_variables = getattr(member, "scanned_variables", set())
    vtable.comment = getattr(member, "comment", "")
    vtable.name = getattr(member, "name", "") or vtable.name
    target.add_member(vtable)
    _mark_dirty()
    return _to_member_dict(vtable)


@api(
    group="types",
    returns="list[dict] | dict",
    example='slots = forge_api.vtable_entries(0x140006358)',
)
def vtable_entries(address: int) -> list[dict] | dict:
    """Read a vtable's function-pointer slots starting at ``address``.

    Walks the pointer table like the GUI's vtable conversion: each
    code/import pointer becomes a slot until the first non-function datum
    (or a data xref marks the table end). Returns
    ``[{"offset", "ea", "slot"}, ...]``; ``{"ok": False, "error": ...}`` when
    ``address`` is not a plausible vtable (no name, unreadable pointer).

    Returns:
        list of slot dicts, or an error dict.
    """
    _require_ida()
    from forge.api.members import VirtualTable

    try:
        vtable = VirtualTable(0, address, None, 0)
        slots = [
            {"offset": vf.offset, "ea": vf.address, "slot": index}
            for index, vf in enumerate(vtable.virtual_functions)
        ]
    except (AssertionError, AttributeError, TypeError, ValueError) as exc:
        return {"ok": False, "error": f"no vtable at {hex(address)}: {exc}"}
    return slots


@api(
    group="types",
    returns="dict",
    example='vt = forge_api.vtable_name(0x140006358); vt["is_nice"]',
)
def vtable_name(address: int) -> dict:
    """Resolve the display name IDA attaches to the vtable at ``address``.

    Returns ``{"name": ..., "is_nice": bool}``, or
    ``{"ok": False, "error": ...}`` when the address is not a vtable. A
    ``name`` of ``""`` with no error means IDA had no name for it.

    Returns:
        dict.
    """
    _require_ida()
    from forge.api.members import VirtualTable

    try:
        vtable = VirtualTable(0, address, None, 0)
        return {
            "name": vtable.vtable_name,
            "is_nice": vtable.has_nice_vtable_name,
        }
    except (AssertionError, AttributeError, TypeError, ValueError) as exc:
        return {"ok": False, "error": f"no vtable at {hex(address)}: {exc}"}


# --------------------------------------------------------------------------- #
# type-library mirror (I.27)
# --------------------------------------------------------------------------- #
def _mirror_store():
    from forge.api.storage import Storage

    return Storage("TypeMirror")


_SYSTEM_TYPE_NAMES = frozenset(
    {
        # IDA compiler-generated locals (not in the base til).
        "C_SCOPE_TABLE",
        "UNWIND_INFO_HDR",
        "UNWIND_CODE",
        "XMM_SAVE_AREA32",
        "XSAVE_FORMAT",
        "RUNTIME_FUNCTION",
        "SCOPE_TABLE",
        "M128A",
        "LARGE_INTEGER",
        "ULARGE_INTEGER",
        "_FILETIME",
        "FILETIME",
        "_LARGE_INTEGER",
        "_ULARGE_INTEGER",
        "_M128A",
        "_XSAVE_FORMAT",
        "_SCOPE_TABLE",
        "SYSTEM_SERVICE_TABLE",
        "OBJECT_DIRECTORY_INFORMATION",
    }
)


def _idb_udt_snapshot(name: str) -> tuple[str | None, list]:
    """The IDB named UDT's member rows as ``(hash, rows)``; ``(None, [])``
    when ``name`` is not a known UDT."""
    import hashlib as _hashlib

    import ida_typeinf

    idati = ida_typeinf.get_idati()
    tinfo = ida_typeinf.tinfo_t()
    if not tinfo.get_named_type(idati, name) or not tinfo.is_udt():
        return None, []
    udt = ida_typeinf.udt_type_data_t()
    if not tinfo.get_udt_details(udt):
        return None, []
    rows = []
    for member in udt:
        member_type = None
        try:
            member_type = member.type.dstr()
        except Exception:  # noqa: BLE001 — degraded udt handles
            member_type = ""
        rows.append((member.offset, getattr(member, "name", ""), member_type))
    digest = _hashlib.sha1(repr(sorted(rows)).encode("utf-8")).hexdigest()  # noqa: S324 — change-detection digest, not security
    return digest, rows


@api(
    group="types",
    returns="dict",
    example='r = forge_api.import_types("World"); r["imported"]',
)
def import_types(pattern: str | None = None) -> dict:
    """Import the database's local (non-lib) UDTs into the shared catalog.

    Scans the local til for struct-like types that are NOT part of the base
    til (system headers) and NOT auto-generated names (contain ``::``);
    each missing catalog entry becomes a store structure with members mapped
    from the IDB type (provenance ``kind="imported"``). Already-present
    names are reported under ``skipped`` — importing never merges. Types
    IDA synthesizes locally (e.g. ``UNWIND_INFO_HDR``, compiler scope
    tables) live in no til, so they import like user types.

    Returns:
        ``{"imported": [names], "skipped": [names]}``.
    """
    _require_ida()
    import ida_typeinf

    from forge.api.structure import Structure

    idati = ida_typeinf.get_idati()
    base_til = None
    try:
        base_til = idati.base(0)
    except Exception:  # noqa: BLE001 — base-til handle varies by IDA version
        base_til = None
    imported = []
    skipped = []
    seen = set()
    for ordinal in range(ida_typeinf.get_ordinal_count(idati)):
        name = ida_typeinf.get_numbered_type_name(idati, ordinal)
        if not name or name in seen:
            continue
        seen.add(name)
        if "::" in name:
            continue
        # Compiler-generated locals live in the local til, not the base til,
        # so only a name-based denylist can exclude them (O1 live pass,
        # 2026-08-13: UNWIND_INFO_HDR/C_SCOPE_TABLE imported otherwise).
        if name in _SYSTEM_TYPE_NAMES or name.startswith("_$"):
            continue
        if pattern and pattern.casefold() not in name.casefold():
            continue
        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.get_numbered_type(idati, ordinal) or not tinfo.is_udt():
            continue
        base = ida_typeinf.tinfo_t()
        if base_til is not None and base.get_named_type(base_til, name):
            continue
        if name in catalog:
            skipped.append(name)
            continue

        structure = Structure(name)
        structure.set_provenance(kind="imported")
        catalog[name] = structure
        udt = ida_typeinf.udt_type_data_t()
        if tinfo.get_udt_details(udt):
            for member in sorted(udt, key=lambda m: getattr(m, "offset", 0)):
                member_type = ""
                try:
                    member_type = member.type.dstr()
                except Exception:  # noqa: BLE001 — degraded udt handles
                    member_type = "u64"
                add_member(
                    name,
                    getattr(member, "offset", 0),
                    member_type or "u64",
                    name=getattr(member, "name", "") or None,
                )
        imported.append(name)
    return {"imported": imported, "skipped": skipped}


@api(
    group="types",
    returns="bool",
    example='ok = forge_api.push_type("World")',
)
def push_type(name: str) -> bool:
    """Push one store structure into the IDB as a type (delta sync).

    Recreates the IDB type (``create_type(..., overwrite=True)``) when it is
    missing or its members differ from the store structure, then records
    ``{ordinal, hash, provenance}`` in the ``TypeMirror`` baseline. A
    structure already in sync is a no-op. Returns False when the structure is
    unknown or the type write failed.

    Returns:
        bool.
    """
    import dataclasses as _dataclasses

    _require_ida()
    target = _resolve_structure(name, required=False)
    if target is None:
        return False
    _, idb_rows = _idb_udt_snapshot(name)
    store_rows = [
        (member.offset, getattr(member, "name", ""), _member_type_str(member) or "")
        for member in target.members
        if getattr(member, "enabled", True)
    ]
    if sorted(idb_rows) != sorted(store_rows):
        result = create_type(name, overwrite=True)
        if not result.get("ok", False):
            return False
    # Baseline is the IDB-side digest: refresh_types() compares against the
    # same snapshot shape, so an unchanged IDB is a no-op and only real
    # IDB edits surface as updates.
    baseline_hash, _ = _idb_udt_snapshot(name)
    try:
        import ida_typeinf

        ordinal = ida_typeinf.get_type_ordinal(ida_typeinf.get_idati(), name)
        provenance = target.provenance
        if not isinstance(provenance, dict):
            provenance = _dataclasses.asdict(provenance)
        _mirror_store()[name] = {
            "ordinal": ordinal,
            "hash": baseline_hash,
            "provenance": provenance,
        }
    except Exception as exc:  # noqa: BLE001 — mirror is a cache, never fatal
        from forge.util.logging import log_warning

        log_warning(f"could not update TypeMirror baseline for {name}: {exc}")
    return True


@api(
    group="types",
    returns="dict",
    example='r = forge_api.push_all(); r["pushed"]',
)
def push_all() -> dict:
    """Push every catalog structure into the IDB (see :func:`push_type`).

    Returns:
        ``{"pushed": [names], "failed": {name: error}}``.
    """
    _require_ida()
    pushed = []
    failed = {}
    for name in list(catalog):
        try:
            if push_type(name):
                pushed.append(name)
            else:
                failed[name] = "type write failed or unknown structure"
        except Exception as exc:  # noqa: BLE001 — one bad type must not stop the rest
            failed[name] = str(exc)
    return {"pushed": pushed, "failed": failed}


@api(
    group="types",
    returns="dict",
    example='r = forge_api.refresh_types(); r["updated"]',
)
def refresh_types() -> dict:
    """Pull IDB changes back into catalog structures (type-library mirror).

    For every baseline entry whose current IDB member layout differs,
    re-import members into the store structure: update the types of members
    whose offset matches (keeping their names), add new members, never
    delete. Updates the baseline hash afterwards.

    Returns:
        ``{"updated": [names], "unchanged": [names]}``.
    """
    _require_ida()
    from forge.api.members import Member, parse_user_tinfo
    from forge.api.structure import Structure

    updated = []
    unchanged = []
    baseline = {}
    try:
        baseline = dict(_mirror_store().items())
    except Exception as exc:  # noqa: BLE001 — empty baseline on storage failure
        from forge.util.logging import log_warning

        log_warning(f"could not read TypeMirror baseline: {exc}")
    for name, entry in baseline.items():
        idb_hash, idb_rows = _idb_udt_snapshot(name)
        if idb_hash is None or idb_hash == entry.get("hash"):
            unchanged.append(name)
            continue
        structure = catalog.get(name)
        if structure is None:
            structure = Structure(name)
            catalog[name] = structure
        for offset, _member_name, member_type in idb_rows:
            existing = structure.get_member_by_offset(offset)
            tinfo = parse_user_tinfo(member_type or "u64")
            if tinfo is None:
                tinfo = parse_user_tinfo("u64")
            if existing is not None:
                # update the type in place; keep the store's name
                existing.tinfo = tinfo
            else:
                structure.add_member(
                    Member(offset, tinfo, None, 0)
                )
        structure.refresh_collisions()
        entry["hash"] = idb_hash
        try:
            _mirror_store()[name] = entry
        except Exception as exc:  # noqa: BLE001 — cache write is best-effort
            from forge.util.logging import log_warning

            log_warning(f"could not refresh TypeMirror baseline for {name}: {exc}")
        updated.append(name)
    _mark_dirty()
    return {"updated": updated, "unchanged": unchanged}


# --------------------------------------------------------------------------- #
# scanning
# --------------------------------------------------------------------------- #
def _make_var_root(cfunc, lvars, index):
    from forge.api.scan_object import VariableObject

    obj = VariableObject(lvars[index], index)
    obj.func_ea = cfunc.entry_ea
    return obj


_INTEGRAL_SCALARS = {
    "int",
    "unsigned int",
    "long",
    "unsigned long",
    "long long",
    "unsigned long long",
    "__int64",
    "unsigned __int64",
    "char",
    "unsigned char",
    "short",
    "unsigned short",
}


def _target_scan_structure(structure: str | None):
    """Resolve the scan's target structure, auto-creating one when needed.

    With ``structure`` given, behaves exactly like ``_resolve_structure``.
    With ``structure=None`` creates a fresh auto-named structure
    (``Structure``, ``Structure Copy``, ...) and selects it, so a bare scan
    never raises ``no structure named ... in the forge_api store``.
    """
    from forge.api.structure import Structure

    if structure is not None:
        return _resolve_structure(structure)
    name = _unique_structure_name("Structure")
    target = Structure(name)
    _structures[name] = target
    _state.current = name
    return target


def _root_retype_target(obj, root_type: str | None) -> str | None:
    """The effective root type to commit, or None when no retype is wanted.

    ``root_type`` wins when given. Otherwise an integral-scalar root is
    auto-retyped to ``void *`` (pointer arithmetic is what makes
    ``memptr`` shapes — an ``__int64`` root yields 2 members where the same
    function retyped ``void *`` yields the full set).
    """
    if root_type is not None:
        return root_type
    tinfo = getattr(obj, "tinfo", None)
    if tinfo is None:
        return None
    try:
        dstr = tinfo.dstr()
    except Exception:  # noqa: BLE001 — broken tinfo degrades to no retype
        return None
    if dstr in _INTEGRAL_SCALARS:
        return "void *"
    return None


def _apply_root_retype(cfunc, obj, target_decl: str):
    """Retype the scan root lvar when the type actually changes.

    Returns a freshly decompiled cfunc when a retype was committed, else
    None. Persists via ``set_lvar_type`` (``MLI_TYPE``), then marks the
    function dirty so the visitor rescans with the retyped root.
    """
    from forge.api.hexrays import decompile as _decompile
    from forge.api.hexrays import mark_cfunc_dirty as _mark_dirty
    from forge.api.hexrays import set_lvar_type
    from forge.api.members import parse_user_tinfo

    lvar = getattr(obj, "lvar", None)
    if lvar is None:
        return None
    try:
        current = lvar.type()
        if current is not None and current.dstr() == target_decl:
            return None
    except Exception as exc:  # noqa: BLE001 — unqueryable lvar type: retype anyway
        from forge.util.logging import log_debug

        log_debug(f"Could not read current lvar type for retype: {exc}")
    tinfo = parse_user_tinfo(target_decl)
    if tinfo is None:
        return None
    if not set_lvar_type(cfunc, lvar, tinfo):
        return None
    _mark_dirty(getattr(cfunc, "entry_ea", None) or 0)
    return _decompile(getattr(cfunc, "entry_ea", None) or 0)


def _resolve_scan_root(
    cfunc, *, var_name: str | None = None, var_index: int | None = None, item_ea: int | None = None
):
    """Resolve a scan root ScanObject from the explicit-or-default criteria."""
    import ida_idaapi

    from forge.api.scan_object import ScanObject

    if item_ea is not None and item_ea != ida_idaapi.BADADDR:
        from forge.api.hexrays import collect_ctree_items_near_ea

        for item in collect_ctree_items_near_ea(cfunc, item_ea, exhaustive=True):
            try:
                obj = ScanObject.create(cfunc, item)
            except Exception:  # noqa: BLE001 — non-expression items are skipped
                obj = None
            if obj is not None:
                return obj
        raise ForgeApiError(f"no scan-able expression near 0x{item_ea:x}")

    lvars = list(cfunc.get_lvars())
    if var_name is not None:
        for index, lvar in enumerate(lvars):
            if lvar.name == var_name:
                return _make_var_root(cfunc, lvars, index)
        raise ForgeApiError(f"no variable named {var_name!r} in function")
    if var_index is not None:
        if 0 <= var_index < len(lvars):
            return _make_var_root(cfunc, lvars, var_index)
        raise ForgeApiError(f"variable index {var_index} out of range")

    argids = list(getattr(cfunc, "argidx", None) or [])
    if argids and 0 <= argids[0] < len(lvars):
        return _make_var_root(cfunc, lvars, argids[0])
    return None


def _scan_result(target) -> dict:
    return {
        "structure": target.name,
        "members": [_to_member_dict(member) for member in target.members],
    }


@api(
    group="scan",
    returns="dict",
    example='r = forge_api.deep_scan(0x1400014F0, var_name="a1", structure="Recovered")',
)
def deep_scan(
    ea: int,
    *,
    var_name: str | None = None,
    var_index: int | None = None,
    item_ea: int | None = None,
    recurse_calls: bool = False,
    max_depth: int | None = None,
    structure: str | None = None,
    root_type: str | None = None,
) -> dict:
    """Recover the structure's members by deep-scanning a decompiled function.

    Decompiles the function containing ``ea`` and runs the same
    ``NewDeepScanVisitor`` the GUI uses over the chosen root variable (default:
    the first argument; override with ``var_name``/``var_index``/``item_ea``).
    Members are merged into the target structure in the headless store.
    ``recurse_calls`` follows values passed into called functions; ``max_depth``
    caps recursion (None = unlimited). On an unresolvable root returns
    ``{"ok": False, "error": ...}``.

    With ``structure`` None a fresh auto-named store structure is created
    (``Structure``, then ``Structure Copy``, ...). ``root_type`` retypes the
    root lvar first (persisted via ``modify_user_lvar_info``); an integral
    scalar root (``__int64``/``int``/...) is auto-retyped to ``void *`` so
    pointer arithmetic produces ``memptr`` shapes — the fully-populated
    member set without caller-side retyping.

    Returns:
        ``{"structure": name, "members": [member dicts]}`` or an ok:False dict.
    """
    _require_ida()
    from forge.api.hexrays import decompile as _decompile
    from forge.api.scanner import NewDeepScanVisitor

    target = _target_scan_structure(structure)
    cfunc = _decompile(ea)
    if cfunc is None:
        return {"ok": False, "error": f"could not decompile {hex(ea)}"}
    obj = _resolve_scan_root(cfunc, var_name=var_name, var_index=var_index, item_ea=item_ea)
    if obj is None:
        return {"ok": False, "error": "could not resolve a scan root (default: first argument)"}
    root_decl = _root_retype_target(obj, root_type)
    if root_decl is not None:
        refreshed = _apply_root_retype(cfunc, obj, root_decl)
        if refreshed is not None:
            cfunc = refreshed
            obj = _resolve_scan_root(
                cfunc, var_name=var_name, var_index=var_index, item_ea=item_ea
            )
            if obj is None:
                return {
                    "ok": False,
                    "error": "could not resolve a scan root after retype",
                }
    visitor = NewDeepScanVisitor(
        cfunc,
        target.main_offset,
        obj,
        target,
        recurse_calls=recurse_calls,
        max_depth=max_depth,
    )
    visitor.process()
    _mark_dirty()
    return _scan_result(target)


@api(
    group="scan",
    returns="dict",
    example='r = forge_api.shallow_scan(0x1400014F0, var_name="a1", structure="Recovered")',
)
def shallow_scan(
    ea: int,
    *,
    var_name: str | None = None,
    var_index: int | None = None,
    item_ea: int | None = None,
    structure: str | None = None,
    root_type: str | None = None,
) -> dict:
    """Recover a structure's members with a single-pass shallow scan.

    Runs ``NewShallowScanVisitor`` over the chosen root variable (same root
    resolution and ``root_type`` retype semantics as :func:`deep_scan`;
    with ``structure`` None a fresh auto-named structure is created).

    Returns:
        ``{"structure": name, "members": [member dicts]}`` or an ok:False dict.
    """
    _require_ida()
    from forge.api.hexrays import decompile as _decompile
    from forge.api.scanner import NewShallowScanVisitor

    target = _target_scan_structure(structure)
    cfunc = _decompile(ea)
    if cfunc is None:
        return {"ok": False, "error": f"could not decompile {hex(ea)}"}
    obj = _resolve_scan_root(cfunc, var_name=var_name, var_index=var_index, item_ea=item_ea)
    if obj is None:
        return {"ok": False, "error": "could not resolve a scan root (default: first argument)"}
    root_decl = _root_retype_target(obj, root_type)
    if root_decl is not None:
        refreshed = _apply_root_retype(cfunc, obj, root_decl)
        if refreshed is not None:
            cfunc = refreshed
            obj = _resolve_scan_root(
                cfunc, var_name=var_name, var_index=var_index, item_ea=item_ea
            )
            if obj is None:
                return {
                    "ok": False,
                    "error": "could not resolve a scan root after retype",
                }
    visitor = NewShallowScanVisitor(cfunc, target.main_offset, obj, target)
    visitor.process()
    _mark_dirty()
    return _scan_result(target)


@api(
    group="scan",
    returns="dict",
    example='r = forge_api.scan_global(0x1400A4000)',
)
def scan_global(ea: int, *, max_depth: int | None = None, span: int | None = None) -> dict:
    """Deep-scan a global object from every function that references it.

    Creates a store structure named ``global_<short_name>`` and runs a deep scan
    (with call recursion, like the GUI's global scan) per referring function.
    Additionally (I.20), every named sub-head inside the object's byte range
    ``[ea, ea + span)`` becomes a member — stored pointers like
    ``qword_140006128`` that the visitor alone cannot attribute become
    deterministic members. ``span`` defaults to the size of the item at
    ``ea``. Returns ``{"ok": False, "error": ...}`` when the address has no
    references.

    Returns:
        ``{"structure": name, "functions_scanned": int, "members": [...]}``.
    """
    _require_ida()

    import ida_bytes
    import ida_name

    from forge.api.hexrays import decompile as _decompile
    from forge.api.hexrays import get_funcs_referencing_address
    from forge.api.scan_object import GlobalVariableObject
    from forge.api.scanner import NewDeepScanVisitor
    from forge.api.structure import Structure

    xrefs = sorted(get_funcs_referencing_address(ea))
    if not xrefs:
        return {"ok": False, "error": "no function references to this address"}
    short_name = ida_name.get_short_name(ea) or hex(ea)
    struct_name = f"global_{short_name}"
    target = _structures.get(struct_name)
    if target is None:
        target = Structure(struct_name)
        _structures[struct_name] = target
    _state.current = struct_name

    scanned = 0
    for func_ea in xrefs:
        cfunc = _decompile(func_ea)
        if cfunc is None:
            continue
        obj = GlobalVariableObject(ea)
        obj.name = short_name
        NewDeepScanVisitor(
            cfunc,
            target.main_offset,
            obj,
            target,
            recurse_calls=True,
            max_depth=max_depth,
        ).process()
        scanned += 1

    _add_named_sub_heads(
        target,
        ea,
        span if span is not None else ida_bytes.get_item_size(ea),
    )

    return {
        "structure": struct_name,
        "functions_scanned": scanned,
        "members": [_to_member_dict(member) for member in target.members],
    }


def _head_name_without_address(name: str) -> str:
    """``qword_140006128`` -> ``qword``; other names stay as-is."""
    import re as _re

    match = _re.match(r"^(.+?)_[0-9A-Fa-f]{4,}$", name)
    return match.group(1) if match else name


def _add_named_sub_heads(target, ea: int, span: int):
    """I.20: synthesize members for named sub-heads inside a global span.

    Every named item in ``[ea, ea + span)`` (excluding the base itself) that
    has no member yet becomes a ``u8``/``u16``/``u32``/``u64`` (or
    ``u8[N]``) member named after the head's short name without its address
    prefix. Deterministic superset of the GUI's stored-address handling.
    """
    import ida_bytes
    import ida_idaapi
    import ida_name

    sizes = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}
    end = ea + span
    head = ea
    while True:
        head = ida_bytes.next_head(head, end)
        if head in (ida_idaapi.BADADDR, None) or head >= end:
            break
        name = ida_name.get_name(head)
        if not name:
            continue
        item_size = ida_bytes.get_item_size(head)
        size_type = sizes.get(item_size, f"u8[{item_size}]")
        if target.get_member_by_offset(head - ea) is None:
            add_member(
                target.name,
                head - ea,
                size_type,
                name=_head_name_without_address(name),
            )


# --------------------------------------------------------------------------- #
# build / apply / finalize
# --------------------------------------------------------------------------- #
@api(
    group="build",
    returns="dict",
    example='r = forge_api.create_type("Recovered", overwrite=True)',
)
def create_type(name: str | None = None, *, overwrite: bool = False) -> dict:
    """Build the IDA type for a structure and apply it to scan evidence.

    Packs the structure's enabled members into a C declaration
    (:meth:`Structure.build_cdecl`), creates/overwrites the IDA named type via
    :meth:`Structure.set_cdecl` and applies the pointer type to every variable
    the scans recorded (the "apply globally" step). ``overwrite=True`` replaces
    an existing type without asking; ``overwrite=False`` aborts if the type
    exists. Never shows a dialog.

    Returns:
        ``{"ok": True, "type_name": str, "declaration": str}`` or
        ``{"ok": False, "error": str}``.
    """
    _require_ida()
    import ida_typeinf

    from forge.api.structure import Structure

    target = _resolve_structure(name)
    result = target.build_cdecl()
    if result is None:
        return {"ok": False, "error": "no enabled packable members"}
    _, cdecl = result

    if overwrite is False:
        # Distinct early path: a type that exists is a hard abort, not the
        # generic set_cdecl-None lie (which used to mask recreate failures).
        tinfo = ida_typeinf.tinfo_t()
        if tinfo.get_named_type(ida_typeinf.get_idati(), name):
            return {"ok": False, "error": "type already exists (overwrite disabled)"}
    elif overwrite is True and not Structure._declaration_parses(cdecl):
        # Validate before the destructive delete so a malformed edit cannot
        # destroy the existing type (the DB would end up with no type at all).
        return {"ok": False, "error": "declaration could not be parsed for overwrite"}

    created = target.set_cdecl(cdecl, target.main_offset, overwrite=overwrite)
    if created is None:
        if overwrite is True:
            return {
                "ok": False,
                "error": "failed to recreate type after delete (see IDA log)",
            }
        return {"ok": False, "error": "type already exists (overwrite disabled)"}
    return {
        "ok": True,
        "type_name": target.created_type_name,
        "declaration": cdecl,
        "skipped": [m.name for m in target.members if not m.enabled],
    }


@api(
    group="build",
    returns="dict",
    example='r = forge_api.create_child_types("Parent")',
)
def create_child_types(name: str | None = None) -> dict:
    """Create the IDA types for every child structure of ``name``.

    Each linked child that does not have a created type yet is finalized with
    :meth:`Structure.create_type_if_ready` (children-first). ``skipped`` lists
    children that could not be created because they have unresolved children.

    Returns:
        ``{"ok": bool, "created": [names], "skipped": [names]}``.
    """
    _require_ida()
    target = _resolve_structure(name)
    if not target.child_relationships:
        return {"ok": False, "error": "structure has no child relationships"}
    created = []
    for child in target.iter_child_structures(_structures):
        if child.created_type_name is not None:
            created.append(child.name)
            continue
        if child.create_type_if_ready(_structures, headless=True) is not None:
            created.append(child.name)
    skipped = target.get_unresolved_child_names(_structures)
    return {"ok": not skipped, "created": created, "skipped": skipped}


@api(
    group="build",
    returns="dict",
    example='r = forge_api.finalize("Recovered")',
)
def finalize(name: str | None = None) -> dict:
    """Finalize one structure: build its type and apply to scan evidence.

    Equivalent to the GUI "Finalize": guards unresolved children, refreshes
    linked child member types, packs and creates the type. Runs headless —
    the same dialog-free commit chain as :func:`create_type` (never
    ``pack_structure``, whose Qt dialogs return None in idalib workers).
    Returns the unresolved child names when the structure cannot be
    finalized because of children; any other commit failure reports a real
    error string instead of an empty ``unresolved`` list.

    Returns:
        ``{"ok": True, "type_name": str}`` or
        ``{"ok": False, "unresolved": [...]}`` /
        ``{"ok": False, "error": str}``.
    """
    _require_ida()
    target = _resolve_structure(name)
    unresolved = target.get_unresolved_child_names(_structures)
    tinfo = target.create_type_if_ready(_structures, headless=True)
    if tinfo is None:
        if unresolved:
            return {"ok": False, "unresolved": unresolved}
        return {"ok": False, "error": "failed to create type (see IDA log for reason)"}
    return {
        "ok": True,
        "type_name": target.created_type_name,
        "skipped": [m.name for m in target.members if not m.enabled],
    }


@api(
    group="build",
    returns="list[dict]",
    example='results = forge_api.finalize_all()',
)
def finalize_all() -> list:
    """Finalize every top-level structure in the store, children first.

    For each structure that is not some other structure's child, runs the
    subtree postorder walk (:meth:`Structure.create_subtree_types_postorder`).

    Returns:
        list of ``{"structure": name, "ok": bool, "created": bool}``.
    """
    _require_ida()
    child_names = {
        rel.child_structure_name
        for s in _structures.values()
        for rel in s.child_relationships
    }
    roots = [name for name in _structures if name not in child_names]
    results = []
    for root_name in roots:
        root = _structures[root_name]
        ok = root.create_subtree_types_postorder(_structures, headless=True)
        results.append(
            {
                "structure": root_name,
                "ok": ok,
                "created": root.created_type_name is not None,
            }
        )
    return results


# --------------------------------------------------------------------------- #
# templated types
# --------------------------------------------------------------------------- #
def _templated_instance():
    if _state.templated is None:
        from forge.features.templated_types.templated_types import TemplatedTypes

        _state.templated = TemplatedTypes()
    return _state.templated


@api(
    group="templated",
    returns="list[str]",
    example='keys = forge_api.templated_keys()',
)
def templated_keys() -> list:
    """List the available templated-type keys (from the templated-types TOML).

    Returns:
        sorted list of template keys.
    """
    _require_ida()
    return sorted(_templated_instance().keys)


@api(
    group="templated",
    returns="dict | None",
    example='d = forge_api.templated_decl("Vector", ["u32"])',
)
def templated_decl(key: str, args: list) -> dict | None:
    """Resolve a templated type's declaration for the given type arguments.

    ``args`` are the template type arguments (each key expects a fixed count;
    the templated-types TOML formats the struct/name with them). Returns
    ``None`` when the key is unknown or the argument count is wrong.

    Returns:
        ``{"name": str, "cdecl": str}`` or None.
    """
    _require_ida()
    result = _templated_instance().get_decl_str(key, list(args))
    if result is None:
        return None
    name, cdecl = result
    return {"name": name, "cdecl": cdecl}


@api(
    group="templated",
    returns="bool",
    example='ok = forge_api.templated_apply("Vector", ["u32"])',
)
def templated_apply(key: str, args: list) -> bool:
    """Apply a templated type into the IDB (imports the type and its typedef).

    Returns ``False`` when the key is unknown or arguments do not match; on
    success the generated struct and typedef are created in the IDB.

    Returns:
        bool.
    """
    _require_ida()
    template = _templated_instance()
    if template.get_decl_str(key, list(args)) is None:
        return False
    template.set_type(key, list(args))
    return True


# --------------------------------------------------------------------------- #
# other features
# --------------------------------------------------------------------------- #
@api(
    group="features",
    returns="dict",
    example='r = forge_api.to_usercall(0x1400014F0)',
)
def to_usercall(ea: int) -> dict:
    """Convert a function's calling convention to the ``__usercall`` family.

    Applies the same cc-remap as the "Convert to __usercall" action
    (CDECL -> ``__usercall``, register conventions -> ``__usercall_``,
    varargs -> ``__usercalle_``) via ``ConvertToUsercall.convert_to_usercall``.

    Returns:
        ``{"ok": True, "ea": int, "convention": str}`` or
        ``{"ok": False, "error": str}``.
    """
    _require_ida()
    from forge.api.hexrays import decompile as _decompile
    from forge.features.convert_to_usercall import convert_to_usercall

    cfunc = _decompile(ea)
    if cfunc is None:
        return {"ok": False, "error": "decompile failed"}
    name = convert_to_usercall(cfunc)
    if name is None:
        return {"ok": False, "error": "unknown calling convention"}
    return {"ok": True, "ea": ea, "convention": name}


@api(
    group="features",
    returns="bool",
    example='ok = forge_api.inverse_if(0x1400014F0, 0x140001723)',
)
def inverse_if(ea: int, insn_ea: int) -> bool:
    """Invert an unconditional ``if`` statement at ``insn_ea`` in function ``ea``.

    Locates the ``cit_if`` item nearest to ``insn_ea``, flips its condition with
    :func:`forge.features.swap_if.helper.inverse_if` and records the inversion in
    the swap-if storage so IDA re-decompilation keeps it. Returns ``False`` when
    no ``if`` is found or decompilation fails.

    Returns:
        bool.
    """
    _require_ida()
    import ida_hexrays

    from forge.api.hexrays import collect_ctree_items_near_ea
    from forge.api.hexrays import decompile as _decompile
    from forge.features.swap_if.helper import inverse_if as _inverse_if
    from forge.features.swap_if.storage import set_inverted

    cfunc = _decompile(ea)
    if cfunc is None:
        return False

    cif = None
    for item in collect_ctree_items_near_ea(cfunc, insn_ea, exhaustive=True):
        insn = getattr(item, "it", None)
        if insn is None:
            insn = item
        specific = getattr(insn, "to_specific_type", None) or insn
        if getattr(specific, "op", None) == getattr(ida_hexrays, "cit_if", None):
            candidate = getattr(specific, "cif", None)
            # The qswap in helper.inverse_if needs a real else branch (the GUI
            # SwapThenElse action gates on ielse too); skip else-less ifs.
            if candidate is not None and getattr(candidate, "ielse", None) is not None:
                cif = candidate
                break
    if cif is None:
        return False

    _inverse_if(cif)
    set_inverted(ea, insn_ea)
    return True


@api(
    group="features",
    returns="bool",
    example='ok = forge_api.create_field("Recovered", 0x18, "u32 field_18")',
)
def create_field(
    struct_name: str, offset: int, declaration: str, idx: int = 0
) -> bool:
    """Insert a new field into an existing IDB struct type at ``offset``+``idx``.

    Mirrors the "Create new field" action: replaces part of the padding member
    at ``offset`` with the given field (``declaration`` is ``TYPE NAME[SIZE]``),
    shrinking/re-splitting the surrounding padding. Raises :class:`ForgeApiError`
    when ``struct_name`` is not a known type.

    Returns:
        bool — True when the field was written into the numbered type.
    """
    _require_ida()
    import ida_typeinf

    from forge.features.create_new_field.create_new_field import apply_new_field

    tinfo = ida_typeinf.tinfo_t()
    if not tinfo.get_named_type(ida_typeinf.get_idati(), struct_name):
        raise ForgeApiError(f"no type {struct_name}")
    result = apply_new_field(tinfo, offset, idx, declaration)
    _mark_dirty()
    return result


@api(
    group="scan",
    returns="dict",
    example='r = forge_api.scan_from_allocation(0x1400014F0, var_name="a1", name="World", commit=True)',
)
def scan_from_allocation(
    ea: int,
    *,
    var_name: str | None = None,
    var_index: int | None = None,
    item_ea: int | None = None,
    name: str | None = None,
    root_type: str | None = None,
    vtable_addr: int | None = None,
    commit: bool = False,
) -> dict:
    """One-shot heap-object recovery from an allocation site.

    Finds the first heap allocation feeding the variable (I.23: via
    :func:`guess_allocation`), creates a store structure named ``name`` (or an
    auto ``Allocation`` name), deep-scans the allocator's result (I.8 root
    retype applies when ``root_type`` is given), optionally converts the
    member at offset 0 to a vtable (I.26: ``vtable_addr`` from
    :func:`vtable_entries`), and optionally commits the type.

    Returns ``{"ok": False, "error": ...}`` when the variable has no heap
    allocation. Success returns ``{"ok": True, "allocation": <row>,
    "structure": <name>, "members": [...]}``.

    Returns:
        dict.
    """
    rows = guess_allocation(ea, var_name=var_name, var_index=var_index, item_ea=item_ea)
    allocation = next((row for row in rows if row["kind"] == "HEAP"), None)
    if allocation is None:
        return {
            "ok": False,
            "error": f"no heap allocation found for variable in {hex(ea)}",
        }

    struct_name = name or _unique_structure_name("Allocation")
    create_structure(struct_name)
    # O1: heap buffers whose root variable is already typed as a struct
    # pointer (e.g. ``ArrayCell *cells``) scan as typed memptr chains and
    # collapse to offset-0 noise; a byte-semantic void * root recovers the
    # element lattice. Retype only when no explicit root_type was given,
    # and restore the analyst's type afterwards.
    restore_type = None
    if root_type is None:
        restore_type = _allocation_root_prior_type(ea, allocation["var"])
        if restore_type:
            root_type = "void *"
    scan_result = deep_scan(
        ea,
        var_name=allocation["var"],
        structure=struct_name,
        recurse_calls=True,
        root_type=root_type,
    )
    if restore_type:
        with contextlib.suppress(Exception):
            set_lvar_types(ea, {allocation["var"]: restore_type})
    members = scan_result.get("members", [])

    if vtable_addr is not None:
        to_vtable(struct_name, 0, vtable_addr)

    if commit:
        create_type(struct_name, overwrite=True)

    return {
        "ok": True,
        "allocation": allocation,
        "structure": struct_name,
        "members": members,
    }


@api(
    group="features",
    returns="list[dict]",
    example='rows = forge_api.guess_allocation(0x1400014F0, var_name="a1")',
)
def guess_allocation(
    ea: int,
    *,
    var_name: str | None = None,
    var_index: int | None = None,
    item_ea: int | None = None,
) -> list:
    """Guess the allocation sites of a variable (heap/stack/global).

    Walks upward from the variable's occurrences through the function's
    assignment graph until it reaches an allocator call (``malloc``, ``calloc``,
    ``realloc``, ``new``/``operator new``, ...), a stack address or a global
    reference. Roots that are parameters or otherwise never reassigned yield no
    rows - scan a local that receives an allocator result instead. Runs the
    same ``GuessAllocationVisitor`` as the action and returns its collected
    rows instead of showing a chooser.

    Returns:
        list of ``{"ea": int, "var": str, "line": str,
        "kind": "HEAP"|"STACK"|"GLOBAL", "size_hint": int | None,
        "callee": int | None}`` — ``size_hint`` is the folded byte size of
        the allocator call (``None`` when it could not be proven constant);
        ``callee`` is the function whose body supplied the allocation when
        the assignment went through a non-allocator helper (I.25).
    """
    _require_ida()
    from forge.api.hexrays import decompile as _decompile
    from forge.features.guess_allocation.guess_allocation import GuessAllocationVisitor

    cfunc = _decompile(ea)
    if cfunc is None:
        return []
    obj = _resolve_scan_root(cfunc, var_name=var_name, var_index=var_index, item_ea=item_ea)
    if obj is None:
        return []
    visitor = GuessAllocationVisitor(cfunc, obj, interactive=False)
    visitor.process()
    return [
        {
            "ea": int(row[0]),
            "var": row[1],
            "line": row[2],
            "kind": row[3],
            "size_hint": row[4],
            "callee": row[5],
        }
        for row in visitor._data
    ]
