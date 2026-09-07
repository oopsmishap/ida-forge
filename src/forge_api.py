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
import copy
import dataclasses
import json
import re
import sys

from forge.api.store import catalog

__version__ = "0.1.0"

__all__ = [
    "add_member",
    "apply_type",
    "auto_resolve",
    "backfill_lumina",
    "callees_of",
    "callers_of",
    "commit_declaration",
    "create_child_types",
    "create_field",
    "create_structure",
    "create_type",
    "create_typedef",
    "database_session",
    "decompile",
    "decompile_many",
    "deep_scan",
    "discover_global_slots",
    "domain_status",
    "functions",
    "duplicate_structure",
    "export_store",
    "finalize",
    "finalize_all",
    "function_info",
    "get_member",
    "get_structure",
    "grouped",
    "guess_allocation",
    "help",
    "import_store",
    "import_types",
    "imports",
    "inverse_if",
    "is_type",
    "link_child",
    "name_cpp_evidence",
    "name_members_from_printf",
    "named_types",
    "nudge_members",
    "plan_structure",
    "push_all",
    "push_type",
    "reapply",
    "recover",
    "recover_abi_structure",
    "recover_pointer_flow",
    "refresh_types",
    "remove_members",
    "remove_structure",
    "rename_ea",
    "rename_local",
    "rename_member",
    "rename_structure",
    "scan_from_allocation",
    "scan_global",
    "scan_returned",
    "scan_sites",
    "set_current",
    "set_func_proto",
    "set_lvar_types",
    "set_member",
    "set_pack",
    "shallow_scan",
    "signature",
    "split_flags",
    "structures",
    "templated_apply",
    "templated_decl",
    "templated_keys",
    "to_hex",
    "to_usercall",
    "to_vtable",
    "transaction",
    "synthesize_cpp",
    "type_of",
    "undo_type",
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

def _sdk_fallback(capability: str, reason: str):
    """Record an unavoidable SDK fallback through the Domain diagnostics store."""
    from forge.api.domain import sdk_fallback
    return sdk_fallback(capability, reason)

def _current_domain_database(*, required: bool = True):
    """Return the active Domain database using the facade's compatibility helper."""
    database = _domain_database_or_none()
    if database is None and required:
        raise ForgeApiError("ida-domain database session unavailable")
    return database


def _try_domain_method(
    database, namespace: str, method: str, *args, capability: str, unavailable_reason: str,
    failure_reason: str, **kwargs,
):
    """Call an optional Domain operation and record fallback evidence on failure."""
    handler = getattr(database, namespace, None) if database is not None else None
    operation = getattr(handler, method, None)
    if not callable(operation):
        _sdk_fallback(capability, unavailable_reason)
        return False, None
    try:
        return True, operation(*args, **kwargs)
    except Exception:
        _sdk_fallback(capability, failure_reason)
        return False, None


def _domain_decompile_result(database, ea: int):
    """Map a Domain decompile object to forge's stable result shape."""
    from forge.api.domain import decompile_result
    return decompile_result(database, ea)


def _require_ida() -> None:
    """Raise unless a real (or stubbed) IDA Hex-Rays module is importable."""
    if not _ida_available():
        raise ForgeApiError(
            "forge_api.<function> requires an IDA Pro session with Hex-Rays"
        )

def _validate_ea(ea: int, *, allow_zero: bool = True) -> int:
    """Validate an address before formatting or crossing the IDA boundary."""
    if isinstance(ea, bool) or not isinstance(ea, int):
        raise ForgeApiError(f"ea must be an int, got {ea!r}")
    if ea < 0 or (not allow_zero and ea == 0):
        raise ForgeApiError(f"ea must be a non-negative address, got {ea!r}")
    return ea


def _validate_declaration(declaration: str) -> str:
    """Reject non-string/empty C declarations before parser or IDA calls."""
    if not isinstance(declaration, str) or not declaration.strip():
        raise ForgeApiError(f"declaration must be a non-empty string, got {declaration!r}")
    return declaration.strip()


# --------------------------------------------------------------------------- #
# self-describing catalog
_API: dict[str, dict] = {}

def api(*, group: str, returns: str, example: str, side_effects: str = "unknown"):
    def decorate(fn):
        params = []
        for name, param in inspect.signature(fn).parameters.items():
            annotation = param.annotation
            type_hint = "" if annotation is inspect.Parameter.empty else getattr(annotation, "__name__", str(annotation))
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
            "kind": "operation",
            "error_contract": {
                "raises": ["ForgeApiError"],
                "returns": "{ok: false, error: string, code: string}",
                "recoverable": "{ok: false, error: string, code: string}",
            },
            "side_effects": side_effects,
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
        # Re-entrancy guard for _refresh_type_references (see that helper).
        self.refreshing_references = False

    @property
    def current(self) -> str | None:
        return catalog.current

    @current.setter
    def current(self, value: str | None) -> None:
        catalog.current = value


_state = _State()
_structures = _state.structures
@contextlib.contextmanager
@api(
    group="meta",
    returns="context manager",
    example='with forge_api.transaction("layout batch"): ...',
    side_effects="catalog mutation; one persistence commit",
)
def transaction(label: str = "forge_api transaction"):
    """Group catalog mutations with rollback on exception and one commit."""
    with catalog.transaction(label) as store:
        yield store


@contextlib.contextmanager
@api(
    group="meta",
    returns="context manager",
    example='with forge_api.database_session("fixture.i64"): ...',
    side_effects="open and close IDA Domain database",
)
def database_session(path, *, save_on_close: bool = False, options=None):
    """Open an IDA Domain database and deterministically close its session."""
    from forge.api.domain import database_session as _database_session

    with _database_session(path, save_on_close=save_on_close, options=options) as database:
        yield database

def _domain_database_or_none():
    """Return the active Domain database, or ``None`` outside an IDA session."""
    try:
        from forge.api.domain import current_database
        return current_database(required=False)
    except (ImportError, AttributeError, RuntimeError, TypeError, ValueError, OSError):
        return None


@api(
    group="meta",
    returns="dict",
    example="forge_api.domain_status()",
    side_effects="diagnostic read",
)
def domain_status(*, clear_fallbacks: bool = False) -> dict:
    """Return detached Domain capability and SDK-fallback diagnostics."""
    from forge.api import domain

    snapshot = domain.capability_snapshot()
    records = list(domain.fallback_records())
    fallback_rows = [
        {"capability": record.capability, "reason": record.reason}
        for record in records
    ]
    summary: dict[str, list[dict]] = {}
    counts: dict[str, int] = {}
    for row in fallback_rows:
        component = row["capability"].split(".", 1)[0]
        summary.setdefault(component, []).append(dict(row))
        counts[component] = counts.get(component, 0) + 1
    removed = len(fallback_rows) if clear_fallbacks else 0
    if clear_fallbacks:
        domain.clear_fallback_records()
    return {
        **snapshot,
        "available": snapshot["ida_domain"]["available"],
        "preferred": "ida-domain",
        "fallbacks": fallback_rows,
        "fallback_summary": summary,
        "fallback_counts": counts,
        "fallback_clear_requested": clear_fallbacks,
        "fallbacks_cleared": removed,
    }


@api(
    group="meta",
    returns="dict",
    example='groups = forge_api.grouped(group="structures")',
)
def grouped(*, group: str | None = None, include_meta: bool = False) -> dict:
    """Return detached API metadata grouped for maintainable clients."""
    entries = help()["functions"]
    selected = {
        name: entry
        for name, entry in entries.items()
        if (group is None or entry["group"] == group)
        and (include_meta or entry["group"] != "meta")
    }
    groups: dict[str, dict] = {}
    for name, entry in selected.items():
        groups.setdefault(entry["group"], {})[name] = copy.deepcopy(entry)
    return {"module": __name__, "version": __version__, "groups": groups}

@api(
    group="decompile",
    returns="list[dict]",
    example="forge_api.functions()",
    side_effects="database enumeration read",
)
def functions() -> list[dict]:
    """List valid functions through Domain, with explicit SDK fallback."""
    _require_ida()
    database = _domain_database_or_none()
    rows = None
    if database is not None:
        handler = getattr(database, "functions", None)
        getter = getattr(handler, "get_all", None)
        if callable(getter):
            try:
                rows = getter()
            except Exception:
                rows = None
    if rows is None:
        _sdk_fallback("functions.enumeration", "ida-domain function enumeration unavailable")
        import ida_funcs
        rows = []
        for ea in ida_funcs.Functions():
            function = ida_funcs.get_func(ea)
            if function is not None:
                rows.append(
                    type("FunctionRow", (), {
                        "name": ida_funcs.get_func_name(ea),
                        "start_ea": function.start_ea,
                        "end_ea": function.end_ea,
                    })()
                )
    result = []
    for row in rows:
        start = getattr(row, "start_ea", None)
        end = getattr(row, "end_ea", None)
        if isinstance(start, bool) or isinstance(end, bool):
            continue
        if not isinstance(start, int) or not isinstance(end, int) or end < start:
            continue
        result.append({"name": getattr(row, "name", None), "start_ea": start, "end_ea": end})
    return sorted(result, key=lambda item: item["start_ea"])

@api(
    group="recovery",
    returns="dict",
    example="forge_api.recover_pointer_flow(ea, types)",
    side_effects="IDA local-variable type mutation",
)
def recover_pointer_flow(ea: int, types: dict) -> dict:
    """Apply recovered pointer types and report whether application verified."""
    result = set_lvar_types(ea, types, scope="all", replace=True)
    if result.get("ok"):
        return {"ok": True, "updated": result.get("updated", []), "ea": ea, "verified": True}
    return {"ok": False, "error": result.get("error", "type application failed"), "ea": ea, "verified": False}


@api(
    group="recovery",
    returns="dict",
    example="forge_api.recover_abi_structure(name, members, abi=metadata)",
    side_effects="headless structure mutation",
)
def recover_abi_structure(name: str, members: list[dict], *, abi: dict | None = None) -> dict:
    """Create or replace a structure from detached C++ ABI evidence.

    ABI rebuild with site preservation, entirely IN PLACE: the previous
    Structure object (if any) keeps its identity — its committed-type
    state (``created_type_name``), provenance, and the inbound parent
    links other structures hold against it are never destroyed, so the
    no-delete guard on committed structures is honored. Only the member
    rows are replaced. Scan evidence recorded on a prior member survives
    the rebuild — each prior member's ``scanned_variables``/child link
    merges into the ABI member at the same offset
    (:func:`forge.api.members.merge_member_evidence`), the prior
    provenance is restored (a rebuild must not silently reset
    ``kind="cpp_synthesis"``), child links whose parent member did not
    survive the rebuild are dropped (with their reciprocal on the child),
    the structure's reference-catalog rows are re-recorded from the new
    ABI declarations (:meth:`TypeReferenceCatalog.rebuild`), the
    persisted scan-site rows are recomputed, and the surviving evidence
    is reported under ``preserved_sites``.
    """
    from forge.api.members import merge_member_evidence
    from forge.api.provenance import references

    previous = _structures.get(name)
    prior_members: list = []
    prior_provenance = None
    if previous is not None:
        # In-place rebuild: committed structures must never be deleted
        # and recreated (remove_structure refuses them). Clearing the
        # member rows keeps the committed IDB type and every inbound
        # relationship intact; the caller re-commits afterwards with
        # create_type(..., overwrite=True) if the layout changed.
        target = previous
        prior_members = list(target.members)
        prior_provenance = target.clone_provenance()
        target.clear_members()
    else:
        create_structure(name)
        target = _resolve_structure(name)
    _state.current = name
    failed_members = []
    for member in members:
        added = add_member(
            name,
            int(member["offset"]),
            str(member["type"]),
            name=member.get("name"),
        )
        # M3: an ok:False add_member means the ABI member VANISHED from
        # the rebuilt structure — surface it, never silently shrink.
        if isinstance(added, dict) and added.get("ok") is False:
            failed_members.append(
                {
                    "offset": member.get("offset"),
                    "type": str(member.get("type", "")),
                    "name": member.get("name"),
                    "error": added.get("error"),
                }
            )
    preserved = []
    merged_offsets: set[int] = set()
    for prior in prior_members:
        current = target.get_member_by_offset(getattr(prior, "offset", None))
        if current is None or current is prior:
            continue
        kept = merge_member_evidence(current, prior)
        if kept is not current:
            continue
        preserved.append({"offset": current.offset, "member": current.name})
        merged_offsets.add(current.offset)
        child_name = getattr(current, "linked_child_structure_name", None)
        if child_name and child_name in _structures and not any(
            rel.child_structure_name == child_name
            and rel.parent_member_offset == current.offset
            for rel in target.child_relationships
        ):
            relationship = target.add_child_relationship(
                child_structure_name=child_name,
                parent_member_offset=current.offset,
                parent_member_name=current.name,
                relation_kind=getattr(current, "child_relation_kind", None) or "pointer",
            )
            _structures[child_name].add_parent_relationship(relationship)
    for relationship in list(target.child_relationships):
        if relationship.parent_member_offset in merged_offsets:
            survivor = target.get_member_by_offset(relationship.parent_member_offset)
            if survivor is not None:
                relationship.parent_member_name = survivor.name
            continue
        # The prior evidence this link was created from did not survive
        # the rebuild: drop the stale link and its reciprocal on the child
        # (the recreate path dropped it with the old object).
        target.child_relationships.remove(relationship)
        child = _structures.get(relationship.child_structure_name)
        if child is not None:
            child.parent_relationships = [
                rel
                for rel in child.parent_relationships
                if not (
                    rel.parent_structure_name == name
                    and rel.parent_member_offset == relationship.parent_member_offset
                )
            ]
    target.abi_metadata = copy.deepcopy(abi or {})
    if prior_provenance is not None:
        target.provenance = prior_provenance
    _refresh_scan_sites(target)
    references.rebuild([target])
    _mark_dirty()
    payload = _to_structure_dict(target)
    payload["abi_metadata"] = copy.deepcopy(target.abi_metadata)
    payload["preserved_sites"] = preserved
    if failed_members:
        # M3: the rebuilt structure is smaller than the ABI evidence
        # asked for — report every vanished member instead of ok:True.
        payload["failed_members"] = failed_members
        payload["ok"] = False
        payload["error"] = (
            f"{len(failed_members)} ABI member(s) could not be added: "
            + "; ".join(
                row.get("error") or "unknown error" for row in failed_members
            )
        )
        return payload
    # Success contract (same shape as the other facade verbs): synthesize_cpp
    # branches on result["ok"] — without it the caller returned the raw
    # payload as if the rebuild had failed.
    payload["ok"] = True
    return payload


@api(
    group="recovery",
    returns="dict",
    example="forge_api.synthesize_cpp(name, members, abi=metadata, roots=roots)",
    side_effects="headless structure/provenance mutation",
)
def synthesize_cpp(
    name: str,
    members: list[dict],
    *,
    abi: dict | None = None,
    roots: list[dict] | None = None,
    commit: bool = True,
) -> dict:
    """Synthesize a C++ structure and persist detached root provenance."""
    result = recover_abi_structure(name, members, abi=abi)
    if not result.get("ok"):
        return result
    target = _resolve_structure(name)
    root_rows = [copy.deepcopy(row) for row in (roots or [])]
    first = root_rows[0] if root_rows else {}
    target.set_provenance(
        kind="cpp_synthesis",
        root_object_ea=first.get("object_ea"),
        root_function_ea=first.get("function_ea"),
        has_multiple_roots=len(root_rows) > 1,
    )
    # Roots: the persisted provenance model has no roots field — the
    # detached GLOBAL_EA rows below are the durable record, and the full
    # root list rides on the returned payload.
    # 根对象是该类型的应用位点：记录 GLOBAL_EA 行，create_type 提交后的
    # 引用刷新（_refresh_type_references）会依据这些行把类型重新应用到根上。
    from forge.api.provenance import references

    for row in root_rows:
        if row.get("object_ea") is not None:
            references.record_global_ea(int(row["object_ea"]), name, detail="cpp_synthesis root")
    if commit:
        commit_result = create_type(name)
        if isinstance(commit_result, dict) and not commit_result.get("ok", True):
            return commit_result
    _mark_dirty()
    try:
        payload = _to_structure_dict(target)
    except AttributeError:
        provenance = getattr(target, "provenance", {})
        if hasattr(provenance, "__dict__"):
            provenance = copy.deepcopy(provenance.__dict__)
        else:
            provenance = copy.deepcopy(provenance)
        payload = {"name": name, "provenance": provenance}
    provenance_payload = payload.get("provenance")
    if isinstance(provenance_payload, dict):
        provenance_payload["roots"] = copy.deepcopy(root_rows)
    payload.update({"ok": True, "structure": name})
    return payload


@api(
    group="recovery",
    returns="dict",
    example="forge_api.name_cpp_evidence(name)",
    side_effects="IDA name mutation",
)
def name_cpp_evidence(name: str) -> dict:
    """Name vtable slots and the primary vptr from persisted ABI evidence."""
    target = _resolve_structure(name)
    renamed = []
    for member in target.members:
        if hasattr(member, "vtable_name"):
            old_name = getattr(member, "name", "")
            member.name = "vptr"
            renamed.append({"offset": member.offset, "name": "vptr"})
    for table in target.abi_metadata.get("vtables", []):
        for slot in table.get("slots", []):
            if slot.get("ea") is not None and slot.get("name"):
                rename_ea(slot["ea"], slot["name"])
    _mark_dirty()
    return {"ok": True, "structure": name, "renamed": renamed}


@api(
    group="recovery",
    returns="dict",
    example="forge_api.discover_global_slots(target_ea)",
    side_effects="IDA memory read",
)
def discover_global_slots(target_ea: int, *, span: int = 0x1000) -> dict:
    """Find writable global pointer slots that point at a target address."""
    _require_ida()
    import ida_bytes
    import ida_segment

    if span <= 0:
        return {"ok": False, "error": "span must be positive"}
    candidates = []
    width = 8
    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        if not getattr(segment, "perm", 0) & getattr(ida_segment, "SEGPERM_WRITE", 2):
            continue
        start = int(segment.start_ea)
        end = min(int(segment.end_ea), start + span)
        for slot_ea in range(start, end, width):
            if ida_bytes.get_qword(slot_ea) == target_ea:
                candidates.append({"slot_ea": slot_ea, "target_ea": target_ea, "span": span})
    return {"ok": True, "target_ea": target_ea, "candidates": candidates}




@api(
    group="structures",
    returns="dict",
    example='plan = forge_api.plan_structure("Recovered", [{"offset": 0, "type": "u32"}])',
    side_effects="unknown",
)
def plan_structure(
    name: str,
    members: list[dict] | None = None,
    *,
    pack: int | None = 1,
) -> dict:
    """Build a detached structure plan without mutating catalog or IDB."""
    try:
        _validate_pack(pack)
        from forge.api.members import Member, parse_user_tinfo
        from forge.api.structure import Structure

        target = Structure(name)
        target.pack = pack
        seen_offsets: set[int] = set()
        planned: list[dict] = []
        for spec in members or []:
            if not isinstance(spec, dict):
                raise ForgeApiError("member spec must be a dict")
            offset = int(spec["offset"])
            if offset < 0:
                raise ForgeApiError(f"member offset must be non-negative: {offset}")
            if offset in seen_offsets:
                raise ForgeApiError(f"duplicate member offset: 0x{offset:x}")
            seen_offsets.add(offset)
            declaration = str(spec["type"])
            tinfo = parse_user_tinfo(declaration)
            if tinfo is None:
                raise ForgeApiError(f"could not parse type {declaration!r}")
            member_name = spec.get("name")
            if member_name is not None:
                _validate_member_name(member_name)
            member = Member(offset, tinfo, None, int(spec.get("origin", 0)))
            member.decl_src = declaration
            if member_name is not None:
                member.name = member_name
            member.comment = spec.get("comment", "")
            member.is_array = bool(spec.get("is_array", False))
            if not spec.get("enabled", True):
                member.set_enabled(False)
            target.add_member(member)
            planned.append(_to_member_dict(member))
        target.refresh_collisions()
        declaration_preview = None
        warning = None
        try:
            built = target.build_cdecl()
            declaration_preview = built[1] if built else None
        except Exception as exc:
            warning = f"declaration preview unavailable: {exc}"
        result = {
            "ok": True,
            "name": name,
            "pack": pack,
            "members": planned,
            "collisions": list(target.collisions),
            "declaration": declaration_preview,
        }
        if warning:
            result["warning"] = warning
        return result
    except (ForgeApiError, KeyError, TypeError, ValueError) as exc:
        return {"ok": False, "error": str(exc), "code": "invalid_input"}


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


def _declaration_named_types(declaration: str) -> list[str]:
    """Named-type candidates in a prototype, minus the function's own name.

    ``declaration_type_references`` counts every non-keyword identifier;
    in a prototype the identifier directly preceding the parameter list's
    ``(`` is the function name, never a referenced type, so it is stripped
    first. Function-pointer parameters keep working — their declarator
    names already sit behind pointer stars.
    """
    import re as _re

    from forge.api.members import declaration_type_references

    stripped = _re.sub(r"[A-Za-z_]\w*(?=\s*\()", " ", declaration)
    return declaration_type_references(stripped)


def _record_ea_reference_rows(ea: int, declaration: str) -> None:
    """Record one GLOBAL_EA row per named type an applied declaration uses."""
    from forge.api.provenance import references

    for type_name in _declaration_named_types(declaration):
        references.record_global_ea(ea, type_name, detail=declaration)


def _record_lvar_reference_rows(ea: int, pairs, updated: list) -> None:
    """Record one LVAR row per named type each successfully retyped local uses."""
    from forge.api.provenance import references

    ok_by_name = {row["name"]: row.get("ok") for row in updated}
    for name, declaration in pairs:
        if not ok_by_name.get(name):
            continue
        declaration = "void *" if declaration == "*" else declaration
        for type_name in _declaration_named_types(declaration):
            references.record_lvar(ea, name, type_name, detail=declaration)


def _preserve_authored_members(target) -> list[dict]:
    """Keep authored identity when a scan lands on an occupied offset (gap #8).

    Deep scans append scan-built rows blindly, so a re-scan over a
    structure with authored members (``decl_src``/human names from
    ABI evidence, ``set_member``, ...) collides at the same offset.
    ``members.merge_member_evidence`` merges the scan-built row's
    evidence (``scanned_variables``, links) into the authored survivor
    and the loser is dropped. Two authored members at one offset stay a
    deliberate collision and are never touched.
    """
    from forge.api.members import is_authored_member

    merged: list[dict] = []
    groups: dict[int, list] = {}
    for member in target.members:
        groups.setdefault(member.offset, []).append(member)
    for offset in sorted(groups):
        group = groups[offset]
        if len(group) < 2:
            continue
        survivor = group[0]
        for other in group[1:]:
            if is_authored_member(survivor) and is_authored_member(other):
                continue
            # Gap #8 merge goes through the catalog: merge_member_evidence
            # keeps the authored identity fields, and the catalog itself
            # drops (and persists) the loser — the facade can no longer
            # forget the drop-the-loser step.
            result = catalog.merge_member(target.name, other)
            if not result.get("ok"):
                continue
            kept = result["merged"]
            loser = result["dropped"]
            target.refresh_collisions()
            if loser is not None:
                merged.append(
                    {
                        "offset": offset,
                        "kept": kept.name,
                        "merged": loser.name,
                    }
                )
            survivor = kept
    return merged


def _refresh_type_references(name: str) -> dict:
    """Refresh every recorded consumer of a (re-)committed type (gap #10).

    After ``name`` re-lands in the IDB (fresh ordinal), dependent store
    structures re-commit through :func:`push_type` in reference order and
    recorded application sites (globals, locals, prototypes) re-apply
    their stored declarations. Bounded to direct dependents; a nested
    commit (``push_type`` -> ``create_type``) does not re-enter (the
    ``_state.refreshing_references`` guard), so the cascade per commit is
    exactly one level deep and every failure is reported, never fatal.
    """
    from forge.api.provenance import GLOBAL_EA, LVAR, PROTOTYPE, references

    if getattr(_state, "refreshing_references", False):
        return {"skipped": "reentrant"}
    _state.refreshing_references = True
    report: dict = {
        "type": name,
        "structures": [],
        "globals": 0,
        "lvars": 0,
        "prototypes": 0,
        "deferred": [],
        "failed": [],
    }
    try:
        rows = references.dependents_of(name)
        owners = [
            owner
            for owner in sorted(references.owners_of(name))
            if owner != name and owner in _structures
        ]
        ordered, deferred = references.resolve_commit_order(owners)
        report["deferred"] = deferred
        for owner in ordered:
            try:
                if push_type(owner):
                    report["structures"].append(owner)
                else:
                    report["failed"].append({"structure": owner, "error": "type write failed"})
            except Exception as exc:  # noqa: BLE001 — one bad owner must not abort
                report["failed"].append({"structure": owner, "error": str(exc)})
        for row in rows:
            try:
                if row.kind == GLOBAL_EA and row.ea is not None and row.detail:
                    if apply_type(row.ea, row.detail).get("ok"):
                        report["globals"] += 1
                elif row.kind == LVAR and row.func_ea is not None and row.var and row.detail:
                    if set_lvar_types(row.func_ea, {row.var: row.detail}, scope="all").get("ok"):
                        report["lvars"] += 1
                elif row.kind == PROTOTYPE and row.func_ea is not None and row.detail:
                    if set_func_proto(row.func_ea, row.detail).get("ok"):
                        report["prototypes"] += 1
            except Exception as exc:  # noqa: BLE001 — recorded, never fatal
                report["failed"].append({"site": repr(row.consumer_key()), "error": str(exc)})
        return report
    finally:
        _state.refreshing_references = False


def _refresh_references_after_rename(old: str, new: str) -> dict:
    """Re-point stored references after a type re-file (rename).

    Member declarations still naming ``old`` are rewritten to ``new``,
    every catalog row (structure-member rows AND applied-site rows)
    referencing ``old`` is re-pointed through a payload rewrite, and the
    renamed structure re-commits so its committed members bind to the
    new name. The re-commit triggers :func:`_refresh_type_references`
    for the dependents via the ordinary ``create_type`` hook.
    """
    import re as _re

    from forge.api.provenance import references

    pattern = _re.compile(rf"\b{_re.escape(old)}\b")
    for structure in list(_structures.values()):
        for member in structure.members:
            declaration = getattr(member, "decl_src", None)
            if declaration and pattern.search(declaration):
                member.decl_src = pattern.sub(new, declaration)
    payload = references.to_payload()
    rows = payload.get("references", [])
    changed = 0
    for row in rows:
        if row.get("type_name") == old:
            row["type_name"] = new
            changed += 1
        if row.get("owner") == old:
            row["owner"] = new
            changed += 1
        if row.get("detail") and old in row["detail"]:
            row["detail"] = pattern.sub(new, row["detail"])
    if changed:
        references.load_payload(payload)
    report = {"repointed_rows": changed}
    # Ordinal refresh gate (gap #10): rows now point at ``new`` — refresh
    # every consumer so recorded sites (globals, locals, prototypes) and
    # dependent structures re-bind to the new name. One level deep (guard).
    report["references"] = _refresh_type_references(new)
    if _ida_available() and new in _structures:
        try:
            report["recommitted"] = [new] if push_type(new) else []
        except Exception as exc:  # noqa: BLE001 — rename must never break
            from forge.util.logging import log_warning

            log_warning(f"could not re-commit {new!r} after rename: {exc}")
    _mark_dirty()
    return report


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
    import re as _re

    tinfo = getattr(member, "tinfo", None)
    dstr = getattr(tinfo, "dstr", None)
    if callable(dstr):
        try:
            raw = dstr()
        except Exception:  # noqa: BLE001 — stub tinfos may lack anything
            return None
        # E4 (eval review 2026-08-13): a tinfo whose type was deleted and
        # re-filed renders as an ordinal ref (``#102 *``) — when the member
        # still has its authored declaration string, that is the honest
        # display (and the pack path re-parses it fresh).
        if (
            _re.match(r"#\d+", raw or "")
            and getattr(member, "decl_src", None) is not None
        ):
            try:
                from forge.api.members import normalize_type_display

                return normalize_type_display(member.decl_src)
            except Exception:  # noqa: BLE001 — facade import is best-effort
                return member.decl_src
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
    provenance = getattr(structure, "provenance", {})
    if dataclasses.is_dataclass(provenance):
        provenance = dataclasses.asdict(provenance)
    elif isinstance(provenance, dict):
        provenance = copy.deepcopy(provenance)
    else:
        provenance = {}
    return {
        "name": structure.name,
        "main_offset": structure.main_offset,
        "created_type_name": structure.created_type_name,
        "pack": structure.pack,
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
        "provenance": provenance,
        "abi_metadata": copy.deepcopy(getattr(structure, "abi_metadata", {})),
        "scan_sites": copy.deepcopy(getattr(structure, "scan_sites_rows", [])),
        "last_applied": copy.deepcopy(getattr(structure, "last_apply_sites", [])),
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
            # idc_parse_types returns an ERROR COUNT (0 == success), not a
            # boolean — the old `if parse(...)` treated every failure as
            # success and every success as failure (C5).
            if ida_typeinf.idc_parse_types(placeholder_decl, 0) == 0:
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
        name: copy.deepcopy(_API[name])
        for name in sorted(_API, key=lambda n: (_API[n]["group"], n))
    }
    if topic is not None:
        entry = _API.get(topic)
        if entry is None:
            raise ForgeApiError(f"unknown topic {topic!r}")
        ordered = {topic: copy.deepcopy(entry)}
    return {
        "module": __name__,
        "version": __version__,
        "schema_version": 1,
        "detached": True,
        "functions": ordered,
    }


@api(
    group="meta",
    returns="str",
    example='forge_api.to_hex(0x401000)',
)
def to_hex(ea: int) -> str:
    """Format a validated address as a hex string for display or logging.

    This function is pure and works outside IDA.
    """
    _validate_ea(ea)
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
    EAs of functions called from the body — RAW call-expression targets,
    IAT slots included (:func:`callees_of` resolves slots to the imported
    functions they point at, E.23). ``line_range`` (1-based, inclusive)
    or ``max_lines`` slice the pseudocode lines only — ``lvars``/``calls``
    are untouched. ``max_lines`` truncates MID-DECLARATION (a cap on the
    first N lines); ``line_range`` slices whole, complete declarations —
    prefer it for declaration-quote use (E20d). ``force=True`` clears
    IDA's cached cfunctions first so freshly retyped globals/locals
    render (``clear_cached_cfuncs``).

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
    returns="list[dict]",
    example='heads = forge_api.decompile_many([0x1400014F0, 0x1400020F0])',
)
def decompile_many(eas: list) -> list:
    """Decompile many functions; return their first pseudocode lines (F.2).

    One decompile per EA; each row is ``{"ea", "ok", "head"}`` with
    ``head`` the first pseudocode line (None outside functions). GUI
    progress is shown ONLY when ``ida_kernwin.replace_wait_box`` exists —
    idalib/headless workers stay silent.

    Returns:
        list of row dicts.
    """
    _require_ida()
    import ida_kernwin

    has_progress = hasattr(ida_kernwin, "replace_wait_box") and hasattr(
        ida_kernwin, "hide_wait_box"
    )
    rows = []
    targets = list(eas or [])
    if has_progress:
        ida_kernwin.replace_wait_box("forge: decompiling...")
    try:
        for position, ea in enumerate(targets):
            if has_progress:
                ida_kernwin.replace_wait_box(
                    f"forge: decompiling {position + 1}/{len(targets)}..."
                )
            try:
                head = signature(ea)
            except Exception:  # noqa: BLE001 — one bad EA must not stop the rest
                head = None
            rows.append({"ea": ea, "ok": head is not None, "head": head})
    finally:
        if has_progress:
            ida_kernwin.hide_wait_box()
    return rows


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
    database = _domain_database_or_none()
    if database is not None:
        method = "code_refs_to_ea" if kind == "code" else ("data_refs_to_ea" if kind == "data" else None)
        if method is None:
            return []
        handled, sources = _try_domain_method(database, "xrefs", method, ea, capability="xrefs.callers_of", unavailable_reason="ida-domain xref lookup unavailable", failure_reason="ida-domain xref lookup failed")
        if handled:
            starts = []
            functions = getattr(database, "functions", None)
            getter = getattr(functions, "get_at", None)
            for source in sources or []:
                function = getter(source) if callable(getter) else None
                starts.append(getattr(function, "start_ea", source))
            return sorted(set(starts))
    import ida_funcs
    import ida_idaapi
    import ida_xref
    get_first, get_next = (ida_xref.get_first_cref_to, ida_xref.get_next_cref_to) if kind == "code" else ((ida_xref.get_first_dref_to, ida_xref.get_next_dref_to) if kind == "data" else (None, None))
    if get_first is None:
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


def _import_slot_to_name(ea: int) -> str | None:
    """The import-table name for an IAT slot (E.23), else None.

    IAT slots live in ``.idata``; addresses outside it fall back to the
    plain ``ida_name`` lookup (no name means None).
    """
    database = _domain_database_or_none()
    if database is not None:
        names = getattr(database, "names", None)
        name = getattr(names, "get_at", lambda _ea: None)(ea)
        if name:
            return name
        imports_handler = getattr(database, "imports", None)
        getter = getattr(imports_handler, "get_import_at", None)
        if callable(getter):
            row = getter(ea)
            if row is not None and getattr(row, "name", None):
                return row.name
            ordinal_name = getattr(names, "get_at", lambda _ea: None)(ea)
            if ordinal_name:
                return ordinal_name
    try:
        import ida_name
        return ida_name.get_name(ea) or None
    except Exception:
        return None


def _import_slot_target_ea(ea: int) -> int | None:
    """The imported function an IAT slot resolves to (E.23)."""
    if _import_slot_to_name(ea) is None:
        return None
    database = _domain_database_or_none()
    if database is not None:
        bytes_api = getattr(database, "bytes", None)
        db_info = getattr(database, "database", None)
        pointer_size = getattr(db_info, "pointer_size", 8)
        reader = getattr(bytes_api, "get_qword_at" if pointer_size == 8 else "get_dword_at", None)
        if callable(reader):
            try:
                pointer = reader(ea)
            except Exception as exc:  # noqa: BLE001
                _sdk_fallback("bytes.import_slot_pointer", str(exc))
                return 0
            function = getattr(getattr(database, "functions", None), "get_at", lambda _ea: None)(pointer)
            return getattr(function, "start_ea", pointer) if function is not None else pointer
    try:
        import ida_funcs
        from forge.api.hexrays import read_pointer
        pointer = read_pointer(ea)
        function = ida_funcs.get_func(pointer)
        if function is not None:
            return function.start_ea
    except Exception:  # noqa: BLE001
        return None
    return None


def _resolve_import_slot_callees(eas) -> list[int]:
    """Replace IAT-slot EAs with the functions they resolve to (E.23).

    The decompiler reports call targets at the IAT slot address for
    imported calls; those slots are not functions. Every callee EA that
    is not inside a function is replaced with the pointer stored at the
    slot when that lands in a function; unresolvable EAs are kept as-is.
    """
    database = _domain_database_or_none()
    resolved = []
    for ea in eas:
        if database is not None:
            handled, function = _try_domain_method(database, "functions", "get_at", ea, capability="functions.resolve_import_slots", unavailable_reason="ida-domain function lookup unavailable", failure_reason="ida-domain function lookup failed")
            if handled:
                resolved.append(getattr(function, "start_ea", ea) if function is not None else ( _import_slot_target_ea(ea) or ea))
                continue
        target = _import_slot_target_ea(ea)
        resolved.append(target if target is not None else ea)
    return sorted(set(resolved))


@api(
    group="decompile",
    returns="list[int]",
    example='targets = forge_api.callees_of(0x1400014F0)',
)
def callees_of(ea: int) -> list[int]:
    """List the functions called from the function containing ``ea``.

    Reuses the decompiler's call-expression scan
    (``:func:`decompile`'s ``calls``); IAT-slot targets are resolved to
    the imported functions they point at (E.23). Returns ``[]`` when
    ``ea`` is not in a function.

    Returns:
        sorted list of callee EAs.
    """
    result = decompile(ea)
    if result is None:
        return []
    return _resolve_import_slot_callees(result["calls"])


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
    database = _domain_database_or_none()
    if database is not None:
        functions = getattr(database, "functions", None)
        function = getattr(functions, "get_at", lambda _ea: None)(ea)
        if function is not None:
            start_ea = getattr(function, "start_ea", None)
            end_ea = getattr(function, "end_ea", None)
            if (isinstance(start_ea, bool) or isinstance(end_ea, bool) or not isinstance(start_ea, int) or not isinstance(end_ea, int) or end_ea < start_ea):
                return None
            name = getattr(functions, "get_name", lambda _fn: None)(function)
            code_callers = sorted({value for value in callers_of(ea, "code") if isinstance(value, int) and not isinstance(value, bool)})
            data_callers = sorted({value for value in callers_of(ea, "data") if isinstance(value, int) and not isinstance(value, bool)})
            callees = sorted({value for value in callees_of(ea) if isinstance(value, int) and not isinstance(value, bool)})
            return {"name": name, "start_ea": start_ea, "size": end_ea - start_ea, "prototype": signature(ea), "callers": code_callers, "callees": callees, "refs": sorted(set(code_callers) | set(data_callers))}
    import ida_funcs
    function = ida_funcs.get_func(ea)
    if function is None:
        return None
    code_callers = _resolve_import_slot_callees(callers_of(ea, "code"))
    data_callers = _resolve_import_slot_callees(callers_of(ea, "data"))
    return {"name": ida_funcs.get_func_name(ea), "start_ea": function.start_ea, "size": function.end_ea - function.start_ea, "prototype": signature(ea), "callers": code_callers, "callees": callees_of(ea), "refs": sorted(set(code_callers) | set(data_callers))}


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

    rows = []
    # E5 (eval review 2026-08-13): the old ``idautils.Entries()`` walk
    # resolved the wrong namespace (returned one bogus ``.text`` row and
    # filtered every real module to []). Walk the actual import table with
    # the ordinal API, falling back to Entries() only when the IAT API is
    # unavailable or empty.
    try:
        import ida_idaapi
        import ida_nalt

        module_count = ida_nalt.get_import_module_qty()
        if module_count > 0:
            for module_index in range(module_count):
                module = ida_nalt.get_import_module_name(module_index) or ""
                seen_addresses: set[int] = set()

                def _collect(
                    ea: int,
                    name: str,
                    _ordinal: int,
                    _seen=seen_addresses,
                    _module=module,
                ) -> int:
                    if ea in (ida_idaapi.BADADDR, 0) or ea in _seen:
                        return 1
                    _seen.add(ea)
                    rows.append(
                        {
                            "module": _module,
                            "ea": ea,
                            "name": name or ida_name.get_name(ea),
                        }
                    )
                    return 1

                ida_nalt.enum_import_names(module_index, _collect)
    except Exception:  # noqa: BLE001 — IAT API shape varies; fall back below
        rows = []

    if not rows:
        import idautils

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
        rows = [
            row
            for row in rows
            if folded in row["name"].casefold() or folded in row["module"].casefold()
        ]
    return sorted(rows, key=lambda row: row["ea"])


@api(
    group="decompile",
    returns="dict",
    example='r = forge_api.set_lvar_types(0x1400014F0, {"a1": "World *"}); r["updated"]',
)
def set_lvar_types(ea: int, types, *, scope: str = "arg", replace: bool = False) -> dict:
    """Commit C types onto the function's local variables headless.

    ``types`` maps each local name to a C declaration (``dict`` or list of
    ``(name, decl)`` tuples). ``"*"`` is shorthand for ``void *``. With the
    default ``scope="arg"`` only function arguments are retyped; pass
    ``scope="all"`` to also retype plain locals. ``replace=True``
    (``recover_pointer_flow``) states that existing lvar types must be
    overwritten rather than merged; application is unconditional either
    way, the flag keeps the forwarded contract explicit. Each entry
    resolves independently — a missing name or unparsable declaration
    reports ``ok: False`` for that entry without aborting the rest. The
    result's ``signature`` is the first pseudocode line of a fresh
    decompile, so the caller sees the committed prototype immediately.


    Returns:
        ``{"ok": bool, "updated": [{"name", "ok"}],
        "signature": str | None}``.
    """
    _require_ida()
    database = _domain_database_or_none()
    if database is not None:
        pseudocode = getattr(database, "pseudocode", None)
        function = getattr(pseudocode, "decompile", lambda _ea: None)(ea)
        if function is not None:
            variables = list(getattr(function, "local_variables", ()))
            by_name = {variable.name: variable for variable in variables}
            pairs = list(types.items()) if isinstance(types, dict) else list(types)
            updated = []
            any_ok = False
            type_handler = getattr(database, "types", None)
            parser = getattr(type_handler, "parse_one_declaration", None)
            for name, declaration in pairs:
                variable = by_name.get(name)
                if variable is None or (scope == "arg" and not getattr(variable, "is_arg", False)):
                    updated.append({"name": name, "ok": False})
                    continue
                declaration = "void *" if declaration == "*" else declaration
                tinfo = parser(None, declaration) if callable(parser) else None
                ok = bool(tinfo is not None and variable.set_type(tinfo) and function.save_local_variable_info(variable, save_type=True))
                updated.append({"name": name, "ok": ok})
                any_ok = any_ok or ok
            signature = _domain_decompile_result(database, ea).get("pseudocode")
            _record_lvar_reference_rows(ea, pairs, updated)
            return {"ok": any_ok, "updated": updated, "signature": signature}
    from forge.api.hexrays import decompile as _decompile
    from forge.api.hexrays import set_lvar_type as _set_lvar_type
    from forge.api.members import parse_user_tinfo
    import ida_hexrays
    cfunc = _decompile(ea)
    if cfunc is None:
        return {"ok": False, "error": f"could not decompile {hex(ea)}"}
    lvars = list(cfunc.get_lvars())
    by_name = {lvar.name: lvar for lvar in lvars}
    pairs = list(types.items()) if isinstance(types, dict) else list(types)
    updated = []
    any_ok = False
    modify = getattr(ida_hexrays, "modify_user_lvar_info", None)
    saved_cls = getattr(ida_hexrays, "lvar_saved_info_t", None)
    locator_cls = getattr(ida_hexrays, "lvar_locator_t", None)
    flags = getattr(ida_hexrays, "MLI_TYPE", 0x10)
    for name, declaration in pairs:
        lvar = by_name.get(name)
        if lvar is None or (scope == "arg" and not getattr(lvar, "is_arg_var", False)):
            updated.append({"name": name, "ok": False})
            continue
        tinfo = parse_user_tinfo("void *" if declaration == "*" else declaration)
        ok = False
        if tinfo is not None and callable(modify) and callable(saved_cls) and callable(locator_cls):
            saved = saved_cls()
            saved.ll = locator_cls(lvar.location, lvar.defea)
            saved.type = tinfo
            ok = bool(modify(ea, flags, saved))
        if not ok and tinfo is not None:
            ok = bool(_set_lvar_type(cfunc, lvar, tinfo))
        updated.append({"name": name, "ok": ok})
        any_ok = any_ok or ok
    signature_text = None
    pseudocode = getattr(cfunc, "pseudocode", None)
    if pseudocode:
        line = getattr(pseudocode[0], "line", None)
        if line is not None:
            try:
                import ida_lines
                signature_text = ida_lines.tag_remove(line)
            except Exception:
                signature_text = str(line)
    _record_lvar_reference_rows(ea, pairs, updated)
    return {"ok": any_ok, "updated": updated, "signature": signature_text}


def _parse_function_decl(declaration: str):
    """Parse a function prototype across IDA versions (E1, 2026-08-13).

    ``ida_typeinf.parse_decl`` returns None for function declarations on
    the 9.4 build; ``idc.parse_decl`` is the working path. Tries both,
    plus the ``None``-til form used by the member parser.
    """
    _require_ida()
    database = _domain_database_or_none()
    if database is not None:
        parser = getattr(getattr(database, "types", None), "parse_one_declaration", None)
        if callable(parser):
            return parser(None, declaration)
    import ida_typeinf
    flags = ida_typeinf.PT_TYP | ida_typeinf.PT_SIL
    for til in (None, ida_typeinf.get_idati()):
        tinfo = ida_typeinf.tinfo_t()
        try:
            if ida_typeinf.parse_decl(tinfo, til, declaration, flags):
                return tinfo
        except Exception:
            continue
    return None


@api(
    group="types",
    returns="dict",
    example='r = forge_api.set_func_proto(0x1400014F0, "int __cdecl f(World *, char *)")',
)
def set_func_proto(ea: int, declaration: str) -> dict:
    """Set a function's prototype in the IDB.

    Parses ``declaration`` as a function type (``ida_typeinf.parse_decl``
    then ``idc.parse_decl`` fallback, E1) and applies it via
    ``ida_typeinf.apply_tinfo`` (``ida_funcs.set_ti`` was removed on
    9.4). The result's ``prototype`` is the re-decompiled first line.

    Returns:
        ``{"ok": True, "ea": int, "prototype": str}`` or
        ``{"ok": False, "error": str}``.
    """
    _require_ida()
    from forge.api.provenance import references

    database = _domain_database_or_none()
    if database is not None:
        applier = getattr(getattr(database, "types", None), "apply_declaration_at", None)
        if callable(applier):
            try:
                applied = applier(ea, declaration)
            except Exception:
                applied = False
            if not applied:
                return {"ok": False, "error": f"could not parse declaration {declaration!r}"}
            for type_name in _declaration_named_types(declaration):
                references.record_prototype(ea, type_name, detail=declaration)
            return {"ok": True, "ea": ea, "prototype": signature(ea)}
    import ida_typeinf
    tinfo = _parse_function_decl(declaration)
    if tinfo is None:
        return {"ok": False, "error": f"could not parse declaration {declaration!r}"}
    apply_tinfo = getattr(ida_typeinf, "apply_tinfo", None)
    if apply_tinfo is not None:
        apply_tinfo(ea, tinfo, ida_typeinf.TINFO_DEFINITE)
    for type_name in _declaration_named_types(declaration):
        references.record_prototype(ea, type_name, detail=declaration)
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
    database = _domain_database_or_none()
    if database is not None:
        function = getattr(getattr(database, "pseudocode", None), "decompile", lambda _ea: None)(ea)
        variables = list(getattr(function, "local_variables", ())) if function is not None else []
        old_name = variables[name_or_index].name if isinstance(name_or_index, int) and 0 <= name_or_index < len(variables) else name_or_index
        variable = next((item for item in variables if item.name == old_name), None)
        if variable is None or not new_name:
            return False
        variable.set_user_name(new_name)
        return bool(function.save_local_variable_info(variable, save_name=True))
    import ida_hexrays
    if isinstance(name_or_index, int):
        from forge.api.hexrays import decompile as _decompile
        function = _decompile(ea)
        variables = list(function.get_lvars()) if function is not None else []
        if name_or_index < 0 or name_or_index >= len(variables):
            return False
        name_or_index = variables[name_or_index].name
    return bool(ida_hexrays.rename_lvar(ea, name_or_index, new_name))


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
    database = _current_domain_database(required=False)
    if database is not None:
        handler = getattr(database, "types", None)
        getter = getattr(handler, "get_all", None)
        details = getattr(handler, "get_details", None)
        if callable(getter) and callable(details):
            names = []
            for tinfo in getter():
                row = details(tinfo)
                name = getattr(row, "name", None)
                if name:
                    names.append(name)
            return sorted(set(names))
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

    For UDTs ``members`` lists each member's ``offset``/``size`` in BYTES
    (the convention every other forge_api verb uses — both the ida-domain
    and SDK paths report the value the IDB carries, with no bit-unit
    conversion invented here) plus ``name`` and ``type``. Returns ``None``
    when ``name`` is not a known type.

    Returns:
        dict or None.
    """
    _require_ida()
    if isinstance(name, int) and not isinstance(name, bool):
        import ida_bytes
        import ida_nalt
        import ida_typeinf

        address_tinfo = ida_typeinf.tinfo_t()
        # 9.x: address tinfo lives on nalt/bytes helpers taking
        # (tinfo_out, ea) — the old module-level get_tinfo(ea, tinfo) shape
        # no longer exists and silently returned None for every EA (R2.6).
        getter = getattr(ida_nalt, "get_tinfo", None) or getattr(
            ida_bytes, "get_tinfo", None
        )
        if not callable(getter) or not getter(address_tinfo, name):
            return None
        return {
            "name": name,
            "type": getattr(address_tinfo, "dstr", lambda: "")(),
            "size": getattr(address_tinfo, "get_size", lambda: 0)(),
            "kind": "scalar",
            "members": [],
        }
    database = _current_domain_database(required=False)
    if database is not None:
        handled, domain_tinfo = _try_domain_method(
            database, "types", "get_by_name", name,
            capability="types.get_by_name",
            unavailable_reason="ida-domain named type lookup unavailable",
            failure_reason="ida-domain named type lookup failed",
        )
        if handled:
            if domain_tinfo is None:
                return None
            handled, details = _try_domain_method(
                database, "types", "get_details", domain_tinfo,
                capability="types.get_details",
                unavailable_reason="ida-domain type details unavailable",
                failure_reason="ida-domain type details failed",
            )
            if handled:
                kind = "struct" if domain_tinfo.is_udt() else ("pointer" if domain_tinfo.is_ptr() else ("function" if domain_tinfo.is_func() else "scalar"))
                members = []
                if kind == "struct":
                    handled, domain_members = _try_domain_method(
                        database, "types", "get_udt_members", domain_tinfo,
                        capability="types.get_udt_members",
                        unavailable_reason="ida-domain UDT member lookup unavailable",
                        failure_reason="ida-domain UDT member lookup failed",
                    )
                    if handled:
                        members = [
                            {
                                "offset": member.offset,
                                "size": member.size,
                                "name": getattr(member, "name", ""),
                                "type": member.type.dstr(),
                            }
                            for member in domain_members or []
                        ]
                type_text = getattr(details, "declaration", None) or domain_tinfo.dstr()
                size = getattr(details, "size", None)
                if size is None:
                    size = getattr(domain_tinfo, "get_size", lambda: 0)()
                return {"name": getattr(details, "name", name), "type": type_text, "size": size, "kind": kind, "members": members}
    import ida_typeinf
    idati = ida_typeinf.get_idati()
    tinfo = ida_typeinf.tinfo_t()
    if not tinfo.get_named_type(idati, name):
        return None
    is_udt = getattr(tinfo, "is_udt", lambda: False)
    is_ptr = getattr(tinfo, "is_ptr", lambda: False)
    is_func = getattr(tinfo, "is_func", lambda: False)
    if callable(is_udt) and is_udt():
        kind = "struct"
    elif callable(is_ptr) and is_ptr():
        kind = "pointer"
    elif callable(is_func) and is_func():
        kind = "function"
    else:
        kind = "scalar"

    members = []
    if kind == "struct":
        udt_data = ida_typeinf.udt_type_data_t()
        if tinfo.get_udt_details(udt_data):
            for member in udt_data:
                # The UDT member rows are reported in the same byte units
                # every other forge_api verb uses — no bit-unit conversion
                # here (M1: the old //8 + invented bit_offset disagreed 8x
                # with the ida-domain path).
                member_type = None
                try:
                    member_type = member.type.dstr()
                except Exception:  # noqa: BLE001 — broken udt handles degrade
                    member_type = None
                members.append(
                    {
                        "offset": getattr(member, "offset", 0),
                        "size": getattr(member, "size", 0),
                        "name": getattr(member, "name", ""),
                        "type": member_type,
                    }
                )
            members.sort(key=lambda m: m["offset"])

    get_dstr = getattr(tinfo, "dstr", lambda: name)
    get_size = getattr(tinfo, "get_size", lambda: 0)
    return {
        "name": name,
        "type": get_dstr(),
        "size": get_size(),
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
    database = _current_domain_database(required=False)
    if database is not None:
        handled, domain_type = _try_domain_method(database, "types", "get_by_name", name, capability="types.is_type", unavailable_reason="ida-domain named type lookup unavailable", failure_reason="ida-domain named type lookup failed")
        if handled:
            return domain_type is not None
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
    ``qword_...`` chain cannot shadow the struct), then the whole span is
    deleted with ``DELIT_DELNAMES`` and the type applied with
    ``TINFO_DEFINITE`` — the report-proven sequence that makes a global
    render as one struct item (``g_outer.cell_meta[0].tag``) and survives
    idalib's deferred-analysis re-split race (R2.2/R2.3). The base head's
    name is re-applied afterwards, so a user-named global keeps rendering
    by name. When a user-named SUB-head sits inside the span, the
    full-span delete is skipped (the user's name is never swallowed) and
    the type applies to the first item only, as before. ``del_items``
    takes the END offset ``ea + size``, never a length (R2.4).

    Returns:
        ``{"ok": True, "ea": int, "type": str}`` (with optional
        ``"warning"`` when the item re-split despite a retry) or
        ``{"ok": False, "error": str}``.
    """
    _require_ida()
    database = _domain_database_or_none()
    if database is not None:
        types_api = getattr(database, "types", None)
        parser = getattr(types_api, "parse_one_declaration", None)
        applier = getattr(types_api, "apply_at", None)
        if callable(parser) and callable(applier):
            tinfo = parser(None, declaration)
            if tinfo is None:
                return {"ok": False, "error": f"could not parse declaration {declaration!r}"}
            try:
                applied = bool(applier(tinfo, ea))
            except Exception:
                applied = False
            if not applied:
                return {"ok": False, "error": f"could not apply type at {hex(ea)}"}
            # R2.5 (recovery eval 2026-08-30): domain ``apply_at`` can report
            # success while idalib's deferred analysis drops the item type —
            # verify the tinfo actually landed before trusting it; otherwise
            # fall through to the definitive ida_* path below.
            if applied:
                try:
                    import ida_typeinf as _ti
                    import ida_nalt as _na

                    landed = _ti.tinfo_t()
                    if _na.get_tinfo(landed, ea):
                        display = getattr(tinfo, "dstr", lambda: declaration)()
                        _record_ea_reference_rows(ea, declaration)
                        return {"ok": True, "ea": ea, "type": display}
                except Exception:  # noqa: BLE001 — verification is best-effort;
                    pass  # fall through to the definitive ida_* path
    import re as _re

    import ida_name
    import ida_bytes

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
            from forge.util.logging import log_debug

            log_debug(f"apply_type redefine_range span {hex(ea)}..{hex(ea + size)}")
            user_named = False
            for head in range(ea, ea + size):
                if head == ea:
                    continue
                flags = ida_bytes.get_flags(head)
                if not ida_bytes.is_head(flags):
                    continue
                if not ida_name.get_name(head):
                    continue
                # Keep user-typed names; strip the auto qword_/xmmword_
                # shadowing names so the struct owns the range (R2.2: a
                # user-named sub-head blocks the whole-span delete).
                if hasattr(ida_bytes, "has_user_name") and ida_bytes.has_user_name(flags):
                    user_named = True
                    continue
                ida_name.del_global_name(head)
            base_name = ida_name.get_name(ea)
            if user_named:
                from forge.util.logging import log_warning

                log_warning(
                    "skipping full-span item: user-named sub-head inside span"
                )
            else:
                # R2.3 (recovery eval): with DELIT_SIMPLE the deferred
                # auto-analysis re-splits a fresh struct item back to 1 B
                # (idalib race). DELIT_DELNAMES + apply + auto_wait is the
                # sequence that survives save/reopen. R2.4: the 3rd
                # argument is an END offset (ea + size), never a length.
                import ida_auto

                ida_bytes.del_items(ea, ida_bytes.DELIT_DELNAMES, ea + size)
                ida_typeinf.apply_tinfo(ea, tinfo, ida_typeinf.TINFO_DEFINITE)
                ida_auto.auto_wait()
                if ida_bytes.get_item_size(ea) != size:
                    # Deferred-analysis re-split race: one retry with
                    # settled analysis; still failing, report the warning
                    # instead of lying about the item.
                    ida_typeinf.apply_tinfo(ea, tinfo, ida_typeinf.TINFO_DEFINITE)
                    if ida_bytes.get_item_size(ea) != size:
                        _record_ea_reference_rows(ea, declaration)
                        return {
                            "ok": True,
                            "ea": ea,
                            "type": tinfo.dstr(),
                            "warning": (
                                "re-split race: item at "
                                f"{hex(ea)} re-split to a smaller item "
                                "after apply; re-run apply_type once "
                                "auto-analysis settles"
                            ),
                        }
                # the delete clears the base head's name too (DELIT_DELNAMES
                # removes names of deleted items) — restore it so named
                # globals keep rendering by name.
                if base_name:
                    ida_name.set_name(
                        ea, base_name, getattr(ida_name, "SN_NOCHECK", 0)
                    )

    ida_typeinf.apply_tinfo(ea, tinfo, ida_typeinf.TINFO_DEFINITE)
    _record_ea_reference_rows(ea, declaration)
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
    member_name: str | None = None,
    member_type: str | None = None,
    include_disabled: bool = False,
) -> dict | None:
    """Return the first member dict at ``offset``.

    Collision-disabled members are hidden by default (E20c);
    ``include_disabled=True`` includes them. ``member_name`` (E11,
    2026-08-13)
    disambiguates collision pairs — without it, the offset match silently
    picks whichever member sorts first. ``member_type`` (E24) narrows the
    match further: only members whose displayed type string equals it
    (``"u32"``, ``"Child *"``, ...) qualify, so same-offset/same-name
    members that only differ by type stay addressable. Returns ``None``
    when no structure is selected/resolvable or no member matches
    (read-side convention matches :func:`get_structure`).

    Returns:
        member dict or None.
    """
    target = _resolve_structure(structure, required=False)
    if target is None:
        return None
    for member in target.members:
        if member.offset != offset:
            continue
        if member_name is not None and member.name != member_name:
            continue
        if member_type is not None and _member_type_str(member) != member_type:
            continue
        if not include_disabled and not member.enabled:
            continue
        return _to_member_dict(member)
    return None


@api(
    group="structures",
    returns="dict",
    example='s = forge_api.create_structure("Recovered", pack=None)',
)
def create_structure(
    name: str,
    members: list[dict] | None = None,
    origin: int = 0,
    pack: int | None = 1,
) -> dict:
    """Create a structure in the headless store and select it.

    ``members`` is an optional list of member specs: ``{"offset": int, "type":
    str, "name": str|None, "comment": str|None, "enabled": bool, "is_array":
    bool}``, each inserted through the same path as :func:`add_member`. Raises
    :class:`ForgeApiError` when the name already exists in the store. Nothing is
    written to the IDB until :func:`create_type`/:func:`finalize`.

    ``pack`` sets the byte-alignment of the committed layout (default 1 =
    fully packed; ``None`` = natural alignment). Applied when the structure
    is committed; change it later with :func:`set_pack`.

    Returns:
        the new structure's dict (see :func:`get_structure`).
    """
    from forge.api.structure import Structure

    _validate_pack(pack)
    if name in _structures:
        raise ForgeApiError(f"structure {name!r} already exists")
    structure = Structure(name)
    structure.pack = pack
    _structures[name] = structure
    _state.current = name
    # E3 (eval review 2026-08-13): a member whose type references the
    # structure's own name (``"KV *"`` inside ``KV``) cannot parse until
    # an IDB type named ``KV`` exists — previously the parse failure was
    # swallowed and the member silently dropped from the created
    # structure. Seed the lazy placeholder up front so the first
    # self/forward reference survives.
    if members and not is_type(name):
        _ensure_placeholder_type(name)
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

    REFUSES (raises :class:`ForgeApiError`) when the structure has been
    committed to the IDB — a committed type is the end state, never a
    scratch object: fix its layout in place with ``remove_members`` /
    ``add_member`` / ``set_member`` and re-``create_type(overwrite=True)``
    (the update path, which never deletes the applied type). Uncommitted
    (never-``create_type``-ed) structures may be removed freely; the store
    is the working area, the IDB is the record.

    Returns:
        bool.
    """
    structure = _resolve_structure(name, required=False)
    if structure is None:
        return False
    if getattr(structure, "created_type_name", None) is not None:
        raise ForgeApiError(
            f"structure {structure.name!r} is committed to the IDB — do not "
            "delete it. Update it in place (remove_members/add_member/"
            "set_member) and re-commit with create_type(..., overwrite=True)."
        )
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

    if name is not None:
        _validate_member_name(name)
    target = _resolve_structure(structure)
    tinfo = parse_user_tinfo(type)
    if tinfo is None:
        base_name = _declaration_base_name(type)
        if base_name in _structures and _ensure_placeholder_type(base_name):
            tinfo = parse_user_tinfo(type)
    if tinfo is None:
        return {"ok": False, "error": f"could not parse type {type!r}"}
    member = Member(offset, tinfo, None, origin)
    member.decl_src = type
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
    member_name: str | None = None,
    member_type: str | None = None,
    type: str | None = None,
    name: str | None = None,
    comment: str | None = None,
    enabled: bool | None = None,
    is_array: bool | None = None,
) -> dict:
    """Edit the member at ``offset`` in a store structure.

    Only the provided keyword fields change. ``member_name`` (E11,
    2026-08-13) selects which member at a collision-offset is edited —
    without it the offset match silently picks whichever member sorts
    first. ``member_type`` (E24) narrows the selection the same way
    :func:`get_member` does: the member's displayed type string must
    equal it. ``type`` must parse as a C type; a parse failure returns
    ``{"ok": False, "error": ...}`` without changing anything. Raises
    :class:`ForgeApiError` when no member exists at ``offset``.

    Returns:
        the updated member dict.
    """
    from forge.api.members import parse_user_tinfo

    if name is not None:
        _validate_member_name(name)
    target = _resolve_structure(structure)
    if member_name is not None:
        member = next(
            (
                m
                for m in target.members
                if m.offset == offset and m.name == member_name
                and (member_type is None or _member_type_str(m) == member_type)
            ),
            None,
        )
    else:
        member = next(
            (
                m
                for m in target.members
                if m.offset == offset
                and (member_type is None or _member_type_str(m) == member_type)
            ),
            None,
        )
    if member is None:
        raise ForgeApiError(
            f"no member at offset 0x{offset:x}"
            + (f" named {member_name!r}" if member_name else "")
            + (f" typed {member_type!r}" if member_type else "")
        )
    if type is not None:
        tinfo = parse_user_tinfo(type)
        if tinfo is None:
            base_name = _declaration_base_name(type)
            if base_name in _structures and _ensure_placeholder_type(base_name):
                tinfo = parse_user_tinfo(type)
        if tinfo is None:
            return {"ok": False, "error": f"could not parse type {type!r}"}
        member.tinfo = tinfo
        member.decl_src = type
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
    if type is not None:
        # 类型已变更：按新声明重建该结构的引用目录行（旧的类型引用行
        # 随 rebuild 一并清除，dependents_of 查询保持新鲜）。
        from forge.api.provenance import references

        references.rebuild([target])
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
    # E8 (eval review 2026-08-13): linking used to leave the placeholder's
    # ``u32`` type in place (the linked member serially rendered u32_10
    # and needed a manual set_member afterwards). Materialize the pointer
    # member type now that the child is known.
    from forge.api.members import materialize_linked_child_member_type

    materialize_linked_child_member_type(member, child_name, "pointer")
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

    Mirrors the GUI rule: a nudge that would move a member onto a member that
    was NOT moved is rejected and restored. Negative ``delta`` moving a member
    below zero is also rejected. The structure's ``main_offset`` follows when a
    moved member is the origin row.

    Returns:
        ``{"ok": True, "moved": {old_hex: new_hex}}`` or
        ``{"ok": False, "error": ...}`` (E20b — the moved map makes the
        nudge observable; error dicts are unchanged).
    """
    target = _resolve_structure(structure)
    members = [m for m in target.members if m.offset in offsets]
    if not members:
        # Eval review round 2 §3.7: a silent ok:True for unknown
        # offsets hides typos — say so.
        return {
            "ok": False,
            "error": "no member at offset(s) "
            + ", ".join(f"0x{o:x}" for o in offsets),
        }
    if any(member.offset + delta < 0 for member in members):
        return {"ok": False, "error": "cannot move rows to a negative offset"}

    moved = {id(member): member for member in members}
    original_offsets = {id(member): member.offset for member in target.members}
    original_main_offset = target.main_offset

    moved_map = {}
    for member in members:
        old_offset = member.offset
        member.offset += delta
        moved_map[hex(old_offset)] = hex(member.offset)
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
    return {"ok": True, "moved": moved_map}


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
    if structure.created_type_name == new:
        # Type re-file (rename): re-point every stored reference (member
        # declarations naming the old name, catalog rows) and refresh the
        # consumers so prototypes and dependents re-bind to the new name
        # (gap #10 rename path — payload rewrite then refresh).
        _refresh_references_after_rename(old, new)
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
    cloned.pack = source.pack
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
    example='r = forge_api.set_pack("Outer", None)',
)
def set_pack(name: str | None = None, pack: int | None = 1) -> dict:
    """Set the byte-alignment of a store structure's committed layout.

    ``pack`` is the ``#pragma pack(push, N)`` alignment used when the
    structure is committed: default ``1`` (fully packed — the store's
    default, matching recovery-eval layouts); ``None`` restores natural
    alignment. Int >= 1 or None only (raises :class:`ForgeApiError`).
    Takes effect on the next ``create_type``/``finalize`` commit.

    Returns:
        ``{"ok": True, "pack": pack}``.
    """
    structure = _resolve_structure(name, required=True)
    _validate_pack(pack)
    structure.pack = pack
    _mark_dirty()
    return {"ok": True, "pack": pack}


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
    When the address IS a named pointer table but its first pointer does
    not resolve into a function, the data is not a vtable — reported
    explicitly as ``"not a code-pointer array"`` (E20e, was a silent []).

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
    except (AssertionError, AttributeError, OSError, TypeError, ValueError) as exc:
        return {"ok": False, "error": f"no vtable at {hex(address)}: {exc}"}
    if not slots:
        return {"ok": False, "error": "not a code-pointer array"}
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


@api(
    group="structures",
    returns="dict",
    example='r = forge_api.export_store("forge_store.json")',
)
def export_store(path: str) -> dict:
    """Dump every store structure to a portable JSON file (F.5).

    Uses the same serialization the catalog's netnode persistence uses
    (member decls as strings — never live tinfo handles). No IDA calls:
    works headless. The file is the input of :func:`import_store`.

    Returns:
        ``{"ok": True, "structures": int, "path": str}`` or an error dict.
    """
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "structures": [
                        catalog._serialize(structure)
                        for structure in _structures.values()
                    ]
                },
                handle,
                indent=2,
            )
    except (OSError, TypeError) as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "structures": len(_structures), "path": str(path)}


@api(
    group="structures",
    returns="dict",
    example='r = forge_api.import_store("forge_store.json")',
)
def import_store(path: str, *, merge: bool = False) -> dict:
    """Rebuild store structures from an :func:`export_store` dump (F.5).

    Deserializes through the same path as the catalog's persistence
    loader (members, relationships, provenance). With ``merge=False``
    (default) names already in the store are SKIPPED and reported; with
    ``merge=True`` existing entries are replaced by the file's versions.

    Returns:
        ``{"ok": True, "imported": [names], "skipped": [names]}`` or an
        error dict.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": str(exc)}
    raw_structures = (
        payload.get("structures", []) if isinstance(payload, dict) else []
    )
    imported = []
    skipped = []
    for position, raw in enumerate(raw_structures):
        # m8: a corrupt export row (non-dict, missing keys) must degrade
        # to a skipped row — never raise outside the per-row guard.
        label = raw.get("name") if isinstance(raw, dict) else None
        try:
            if not isinstance(raw, dict):
                raise TypeError(f"row {position} is not an object")
            name = raw.get("name")
            if not name:
                continue
            if not merge and name in _structures:
                skipped.append(name)
                continue
            structure = catalog._deserialize(raw)
        except Exception:  # noqa: BLE001 — a corrupt entry must not abort the import
            skipped.append(label if label else f"<row {position}>")
            continue
        _structures[name] = structure
        imported.append(name)
    _mark_dirty()
    return {"ok": True, "imported": imported, "skipped": skipped}


# --------------------------------------------------------------------------- #
# type-library mirror (I.27)
# --------------------------------------------------------------------------- #
def _mirror_store():
    from forge.api.storage import Storage

    return Storage("TypeMirror")


_SYSTEM_TYPE_NAMES = frozenset(
    {
        "M128A",
        "LARGE_INTEGER",
        "ULARGE_INTEGER",
        "_FILETIME",
        "FILETIME",
        "_LARGE_INTEGER",
        "UNWIND_INFO_HDR",
        "_ULARGE_INTEGER",
        "_M128A",
        "_XSAVE_FORMAT",
        "_SCOPE_TABLE",
        "SYSTEM_SERVICE_TABLE",
        "C_SCOPE_TABLE",
        "UNWIND_INFO_HDR",
        "OBJECT_DIRECTORY_INFORMATION",
    }
)


def _idb_udt_snapshot(name: str) -> tuple[str | None, list]:
    """Return a stable hash and detached UDT member rows."""
    import hashlib as _hashlib
    database = _current_domain_database(required=False)
    if database is not None:
        handler = getattr(database, "types", None)
        get_by_name = getattr(handler, "get_by_name", None)
        get_details = getattr(handler, "get_details", None)
        get_members = getattr(handler, "get_udt_members", None)
        if callable(get_by_name) and callable(get_details) and callable(get_members):
            tinfo = get_by_name(name)
            details = get_details(tinfo) if tinfo is not None else None
            if tinfo is None or not getattr(tinfo, "is_udt", lambda: False)() or details is None:
                return None, []
            rows = [(member.offset, getattr(member, "name", ""), member.type.dstr()) for member in get_members(tinfo)]
            return _hashlib.sha1(repr(sorted(rows)).encode("utf-8")).hexdigest(), rows
    import ida_typeinf
    idati = ida_typeinf.get_idati()
    tinfo = ida_typeinf.tinfo_t()
    if not tinfo.get_named_type(idati, name) or not tinfo.is_udt():
        return None, []
    udt = ida_typeinf.udt_type_data_t()
    if not tinfo.get_udt_details(udt):
        return None, []
    rows = [(member.offset, getattr(member, "name", ""), member.type.dstr()) for member in udt]
    return _hashlib.sha1(repr(sorted(rows)).encode("utf-8")).hexdigest(), rows

def _domain_named_udts() -> list[tuple[str, object]]:
    """Enumerate named Domain UDTs as ``(name, tinfo)`` rows."""
    database = _current_domain_database(required=False)
    handler = getattr(database, "types", None) if database is not None else None
    getter = getattr(handler, "get_all", None)
    details = getattr(handler, "get_details", None)
    if not callable(getter) or not callable(details):
        return []
    rows = []
    for tinfo in getter():
        if getattr(tinfo, "is_udt", lambda: False)():
            name = getattr(details(tinfo), "name", None)
            if name:
                rows.append((name, tinfo))
    return sorted(rows, key=lambda row: row[0])


def _domain_base_type_names(base_til) -> set[str]:
    """Return names enumerated from Domain's base-library type handler."""
    database = _current_domain_database(required=False)
    handler = getattr(database, "types", None) if database is not None else None
    getter = getattr(handler, "get_all", None)
    details = getattr(handler, "get_details", None)
    if not callable(getter) or not callable(details):
        return set()
    return {
        getattr(details(tinfo), "name", "")
        for tinfo in getter(library=base_til)
        if getattr(details(tinfo), "name", None)
    }




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
        ``{"imported": [names], "skipped": {name: reason}}``.
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
    skipped = {}
    seen = set()
    import_failures = []
    failed_members = []
    for ordinal in range(ida_typeinf.get_ordinal_count(idati)):
        name = ida_typeinf.get_numbered_type_name(idati, ordinal)
        if not name or name in seen:
            continue
        seen.add(name)
        if "::" in name:
            # E26: compiler-synthesized template names are silently not
            # candidate types — they are not "skipped" catalog entries.
            continue
        # Compiler-generated locals live in the local til, not the base til,
        # so only a name-based denylist can exclude them (O1 live pass,
        # 2026-08-13: UNWIND_INFO_HDR/C_SCOPE_TABLE imported otherwise).
        if name in _SYSTEM_TYPE_NAMES or name.startswith("_$"):
            skipped[name] = "system/compiler name"
            continue
        if pattern and pattern.casefold() not in name.casefold():
            continue
        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.get_numbered_type(idati, ordinal) or not tinfo.is_udt():
            continue
        base = ida_typeinf.tinfo_t()
        if base_til is not None and base.get_named_type(base_til, name):
            skipped[name] = "base til"
            continue
        if name in catalog:
            skipped[name] = "already in store"
            continue
        failed_members = []
        imported_structure = Structure(name)
        imported_structure.provenance.kind = "imported"
        catalog[name] = imported_structure

        udt = ida_typeinf.udt_type_data_t()
        if tinfo.get_udt_details(udt):
            for member in sorted(udt, key=lambda m: getattr(m, "offset", 0)):
                member_type = ""
                try:
                    member_type = member.type.dstr()
                except Exception:  # noqa: BLE001 — degraded udt handles
                    member_type = "u64"
                added = add_member(
                    name,
                    getattr(member, "offset", 0),
                    member_type or "u64",
                    name=getattr(member, "name", "") or None,
                )
                # M3: a member that fails to add must not vanish silently.
                if isinstance(added, dict) and added.get("ok") is False:
                    failed_members.append(
                        {
                            "structure": name,
                            "offset": getattr(member, "offset", 0),
                            "error": added.get("error"),
                        }
                    )
        imported.append(name)
        if failed_members:
            import_failures.extend(failed_members)
    result = {"imported": imported, "skipped": skipped}
    if import_failures:
        result["failed_members"] = import_failures
    if not imported and not skipped:
        # E20f: an empty import is a finding, not a bug — say so.
        result["note"] = "no foreign UDTs in the til"
    return result


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
    store_rows = [(member.offset, getattr(member, "name", ""), _member_type_str(member)) for member in target.members]
    fresh_write = False
    if sorted(store_rows) != sorted(idb_rows):
        # Ordinal refresh gate (gap #10): the push path refreshes ONCE, at
        # the end of this call — engage the guard so the create_type hook
        # defers, and restore the caller's guard state exactly (a cascade
        # caller may already hold it).
        saved_guard = _state.refreshing_references
        _state.refreshing_references = True
        try:
            result = create_type(name, overwrite=True)
        finally:
            _state.refreshing_references = saved_guard
        if isinstance(result, dict) and not result.get("ok", True):
            return False
        fresh_write = True
    if _current_domain_database(required=False) is None:
        _sdk_fallback("types.ordinal", "ida-domain type ordinal lookup unavailable")
    baseline_hash, _ = _idb_udt_snapshot(name)
    try:
        import ida_typeinf
        ordinal_getter = getattr(ida_typeinf, "get_type_ordinal", None)
        if not callable(ordinal_getter):
            raise AttributeError("IDA SDK ordinal lookup unavailable")
        ordinal = ordinal_getter(ida_typeinf.get_idati(), name)
        provenance = target.provenance
        if not isinstance(provenance, dict):
            provenance = _dataclasses.asdict(provenance)
        _mirror_store()[name] = {"ordinal": ordinal, "hash": baseline_hash, "provenance": provenance}
    except Exception as exc:  # noqa: BLE001
        _sdk_fallback("types.ordinal", "ida-domain type ordinal lookup unavailable")
        from forge.util.logging import log_warning
        log_warning(f"could not update TypeMirror baseline for {name}: {exc}")
    if fresh_write:
        # Fresh write re-landed the type with a new ordinal: refresh every
        # recorded consumer (dependents first, then globals/locals/
        # prototypes). In a cascade this call is reentrant-guarded and
        # skipped, so the cascade stays exactly one level deep.
        _refresh_type_references(name)
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
    for name in sorted(catalog):
        try:
            if push_type(name):
                pushed.append(name)
            elif name in _structures:
                result = create_type(name, overwrite=True)
                failed[name] = str(result.get("error") or "type write failed")
            else:
                failed[name] = "unknown structure"
        except Exception as exc:  # noqa: BLE001
            failed[name] = str(exc)
    return {"pushed": pushed, "failed": failed}


@api(
    group="types",
    returns="dict",
    example='r = forge_api.refresh_types(); r["updated"]',
)
def refresh_types(*, include_names: bool = False) -> dict:
    """Pull IDB changes back into store types (type-library mirror).

    For every baseline entry whose current IDB member layout differs,
    re-import members into the store structure: update the types of members
    whose offset matches (keeping their names), add new members, never
    delete. Updates the baseline hash afterwards.

    ``include_names`` (E26) also adopts the IDB member NAMES for store
    members whose name is still the synthesized pattern (``u32_10`` /
    ``field_8`` — :meth:`Member._is_name_aliased`); the IDB name wins on
    mismatch. Naming a store member by hand (any non-synthesized name) is
    never overwritten.

    Returns:
        ``{"updated": [names], "unchanged": [names], "renamed": [names]}``.
    """
    _require_ida()
    from forge.api.members import Member, parse_user_tinfo
    from forge.api.structure import Structure

    updated = []
    unchanged = []
    renamed = []
    baseline = {}
    try:
        baseline = dict(_mirror_store().items())
    except Exception as exc:  # noqa: BLE001 — empty baseline on storage failure
        from forge.util.logging import log_warning

        log_warning(f"could not read TypeMirror baseline: {exc}")
    for name, entry in sorted(baseline.items()):
        idb_hash, idb_rows = _idb_udt_snapshot(name)
        if idb_hash is None or idb_hash == entry.get("hash"):
            unchanged.append(name)
            continue
        structure = catalog.get(name)
        if structure is None:
            structure = Structure(name)
            catalog[name] = structure
        for offset, idb_member_name, member_type in idb_rows:
            existing = structure.get_member_by_offset(offset)
            tinfo = parse_user_tinfo(member_type or "u64")
            if tinfo is None:
                tinfo = parse_user_tinfo("u64")
            if existing is not None:
                # update the type in place; keep the store's name unless
                # the name is synthesized and include_names is requested
                existing.tinfo = tinfo
                _is_aliased = getattr(existing, "_is_name_aliased", None)
                if (
                    include_names
                    and idb_member_name
                    and callable(_is_aliased)
                    and _is_aliased()
                    and existing.name != idb_member_name
                ):
                    existing.name = idb_member_name
                    renamed.append(idb_member_name)
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
    return {"updated": updated, "unchanged": unchanged, "renamed": renamed}


# --------------------------------------------------------------------------- #
# scanning
# --------------------------------------------------------------------------- #
def _make_var_root(cfunc, lvars, index):
    from forge.api.scan_object import VariableObject, resolve_lvar_init_alloc_size

    obj = VariableObject(lvars[index], index)
    obj.func_ea = cfunc.entry_ea
    # R3.13: tag the root lvar with its initial allocator size so the
    # downwards-visitor's ``_create_scan_object_from_expr`` can refuse
    # to wrap a member-reference around a different-size lvar (e.g.
    # ``v0->field = v2`` where v0 is a 0x38-byte calloc target and v2
    # is the 0x2C-byte scan root).
    obj.alloc_size = resolve_lvar_init_alloc_size(cfunc, index)
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
    """Retype the scan root through the public local-type facade."""
    from forge.api.hexrays import decompile as _decompile
    entry_ea = getattr(cfunc, "entry_ea", None) or 0
    name = getattr(obj, "name", None) or getattr(getattr(obj, "lvar", None), "name", None)
    result = set_lvar_types(entry_ea, {name: target_decl}, scope="all")
    if not result.get("ok"):
        return None
    return _decompile(entry_ea)


def _root_prior_type(obj) -> str | None:
    """The lvar's type string BEFORE a scan retype (for restore-on-fail)."""
    lvar = getattr(obj, "lvar", None)
    if lvar is None:
        return None
    try:
        current = lvar.type()
        if current is None:
            return None
        return current.dstr()
    except Exception:  # noqa: BLE001 — unqueryable lvar type: nothing to restore
        return None


def _root_lvar_type_is(obj, expected_decl: str) -> bool:
    """True when the root lvar's current type already matches ``expected_decl``.

    Qualifier/spacing-insensitive (IDA decorates the same pointer type
    differently across hexrays runs), pointer-depth aware.
    """
    from forge.api.scan_object import _type_identity_key

    lvar = getattr(obj, "lvar", None)
    if lvar is None:
        return False
    try:
        current = lvar.type()
    except Exception:  # noqa: BLE001 — unqueryable lvar: assume mismatch
        return False
    if current is None:
        return False
    try:
        current_decl = current.dstr()
    except Exception:  # noqa: BLE001 — broken tinfo: assume mismatch
        return False
    return _type_identity_key(current_decl) == _type_identity_key(expected_decl)


def _restore_root_type(cfunc, obj, prior_decl: str) -> None:
    """Best-effort undo of ``_apply_root_retype`` (recovery-eval gap #3)."""
    if not prior_decl:
        return
    lvar = getattr(obj, "lvar", None)
    if lvar is None:
        return
    try:
        from forge.api.hexrays import set_lvar_type
        from forge.api.members import parse_user_tinfo

        tinfo = parse_user_tinfo(prior_decl)
        if tinfo is None:
            return
        if set_lvar_type(cfunc, lvar, tinfo):
            from forge.api.hexrays import mark_cfunc_dirty as _dirty

            _dirty(getattr(cfunc, "entry_ea", None) or 0)
    except Exception as exc:  # noqa: BLE001 — restore is best-effort
        from forge.util.logging import log_debug

        log_debug(f"root restore failed: {exc}")


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
        "ok": True,
        "structure": target.name,
        "members": [copy.deepcopy(_to_member_dict(member)) for member in target.members],
    }

def _refresh_scan_sites(target) -> None:
    """Recompute the structure's persisted scan-site rows (R3.6).

    Call after any scan merges evidence into ``target``: the rows land in
    the catalog's netnode payload on the next ``_mark_dirty``, so
    :func:`scan_sites` answers from the DB after any reopen/rebuild.
    Live member scan objects win; with none (reloaded catalog) the
    previously persisted rows are KEPT — a rowless refresh must not
    erase the DB's record (R3.8).
    """
    from forge.api.store import _scan_sites_payload

    target.scan_sites_rows = _scan_sites_payload(target)


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
    clear_first: bool = False,
    subobject: dict | None = None,
) -> dict:
    """Recover the structure's members by deep-scanning a decompiled function.
    Decompiles the function containing ``ea`` and runs the same
    ``NewDeepScanVisitor`` the GUI uses over the chosen root variable (default:
    the first argument; override with ``var_name``/``var_index``/``item_ea``).
    Members are merged into the target structure in the headless store.
    ``recurse_calls`` follows values passed into called functions; ``max_depth``
    caps recursion (None = unlimited). ``clear_first`` (E21) wipes the target
    structure's members before the scan, making repeated scans converge on
    the newest evidence instead of accumulating stale members. On an
    unresolvable root returns ``{"ok": False, "error": ...}``.

    With ``structure`` None a fresh auto-named store structure is created
    (``Structure``, then ``Structure Copy``, ...). ``root_type`` retypes the
    root lvar first (persisted via ``modify_user_lvar_info``); an integral
    scalar root (``__int64``/``int``/...) is auto-retyped to ``void *`` so
    pointer arithmetic produces ``memptr`` shapes — the fully-populated
    member set without caller-side retyping.

    ``subobject`` roots the scan at a nested subobject instead of the whole
    parent object: ``{"base_offset": 0x1B60, "var_name": "a1"}`` matches the
    subobject expression itself (``parent->m(0x1B60)`` or
    ``(child_t *)(parent + 0x1B60)``), so members land in child coordinates
    — parent base + 0x1B60 + 0x08 records child offset 0x08, never 0x1B68.
    Optional keys: ``var_index``/``item_ea`` (parent criteria, at most one
    of the three) and ``parent_type`` (required parent type-name match).
    See :mod:`forge.api.scan_subobject`. ``root_type`` is rejected with
    ``subobject`` — retyping the parent lvar to the CHILD type would break
    the base-offset addressing, and the automatic integral-scalar →
    ``void *`` retype is suppressed in subobject mode. When ``parent_type``
    IS supplied, the parent root is TEMPORARILY retyped to ``parent_type *``
    (never the child type) so hexrays materializes the matchable subobject
    expressions, and the original lvar type is restored on every path after
    the scan.

    Returns:
        ``{"structure": name, "members": [member dicts], "preserved":
        [same-offset merges]}`` (plus ``"subobject": base_offset`` when
        rooted at a subobject) or an ok:False dict.
    """
    _require_ida()
    descriptor = None
    if subobject is not None:
        from forge.api.scan_subobject import SubobjectRoot

        try:
            descriptor = SubobjectRoot.from_dict(subobject)
        except (TypeError, ValueError) as exc:
            return {"ok": False, "error": f"invalid subobject root: {exc}"}
        if root_type is not None:
            return {"ok": False, "error": "root_type is not supported with subobject"}
        var_name = descriptor.var_name
        var_index = descriptor.var_index
        item_ea = descriptor.item_ea
    from forge.api.hexrays import decompile as _decompile
    from forge.api.scanner import NewDeepScanVisitor

    target = _target_scan_structure(structure)
    cfunc = _decompile(ea)
    if cfunc is None:
        return {"ok": False, "error": f"could not decompile {hex(ea)}"}
    obj = _resolve_scan_root(cfunc, var_name=var_name, var_index=var_index, item_ea=item_ea)
    if obj is None:
        return {"ok": False, "error": "could not resolve a scan root (default: first argument)"}
    prior_type = _root_prior_type(obj)
    retype_applied = False
    subobject_retype = None
    if descriptor is not None:
        # Subobject mode suppresses the automatic integral->``void *`` retype:
        # the scan roots at the subobject expression INSIDE the parent object,
        # so retyping the parent lvar to the CHILD type would break the
        # base-offset addressing. An explicit ``root_type`` is already rejected
        # with ``subobject`` above.
        #
        # With ``parent_type`` the opposite retype is REQUIRED: hexrays only
        # materializes the subobject member accesses (``parent->m(0x1B60)``)
        # the SubobjectScanObject matches when the parent lvar carries the
        # parent structure pointer type — an integral/untyped root produces
        # no matchable expression and the scan lands zero members. Temporarily
        # retype the PARENT root to ``parent_type *`` (never the child type)
        # and restore the original lvar type on every path after the scan.
        if descriptor.parent_type is not None:
            wanted = f"{descriptor.parent_type} *"
            if not _root_lvar_type_is(obj, wanted):
                subobject_retype = wanted
        root_decl = subobject_retype
    else:
        root_decl = _root_retype_target(obj, root_type)
    if root_decl is not None:
        original_cfunc, original_obj = cfunc, obj
        try:
            refreshed = _apply_root_retype(cfunc, obj, root_decl)
        except Exception as exc:  # noqa: BLE001 — restore, then report
            _restore_root_type(cfunc, obj, prior_type)
            return {"ok": False, "error": f"root lvar retype failed: {exc}"}
        if refreshed is None:
            if root_type is not None or subobject_retype is not None:
                return {
                    "ok": False,
                    "error": f"root lvar retype to {root_decl!r} failed",
                }
            # The auto-retype is best-effort sugar: scan the un-retyped root.
        else:
            cfunc = refreshed
            obj = _resolve_scan_root(
                cfunc, var_name=var_name, var_index=var_index, item_ea=item_ea
            )
            if obj is None:
                # Re-resolution lost the retyped lvar: undo the retype on the
                # PRE-retype object — its lvar identity (entry_ea, location,
                # defea) still addresses the IDB's user-lvar entry — and
                # report a structured error instead of raising.
                _restore_root_type(original_cfunc, original_obj, prior_type)
                return {"ok": False, "error": "could not resolve a scan root after retype"}
            retype_applied = True
    if descriptor is not None:
        from forge.api.scan_subobject import SubobjectScanObject

        obj = SubobjectScanObject(obj, descriptor)
    # M4: clear ONLY when the scan is actually about to run — a
    # decompile/root-resolution/retype failure must not return ok:False
    # with the target's members already destroyed.
    if clear_first:
        target.clear_members()
    pre_count = len(target.members)
    visitor = NewDeepScanVisitor(
        cfunc,
        target.main_offset,
        obj,
        target,
        recurse_calls=recurse_calls,
        max_depth=max_depth,
    )
    if subobject_retype is not None:
        # The parent retype is temporary: restore the original lvar type on
        # EVERY path — success included — so a subobject scan never leaves
        # the parent re-typed.
        try:
            visitor.process()
        finally:
            _restore_root_type(cfunc, obj, prior_type)
    else:
        visitor.process()
        if retype_applied and prior_type and pre_count == 0 and len(target.members) == 0:
            # The retype produced no evidence at all — undo it so the lvar is
            # not silently re-typed by a failed scan (gap #3).
            _restore_root_type(cfunc, obj, prior_type)
    preserved = _preserve_authored_members(target)
    _refresh_scan_sites(target)
    _mark_dirty()
    result = _scan_result(target)
    if preserved:
        result["preserved"] = preserved
    if descriptor is not None:
        result["subobject"] = descriptor.base_offset
    return result

@api(
    group="build",
    returns="dict",
    example='r = forge_api.recover(0x1400020F0, var_name="v0", name="ChainNode")',
)
def recover(
    ea: int,
    *,
    var_name: str | None = None,
    var_index: int | None = None,
    name: str | None = None,
    commit: bool = True,
    clear_first: bool = True,
    max_depth: int | None = None,
) -> dict:
    """One-shot structure recovery pipeline (F.8 + E.13).

    Builds the target structure (``name`` or an auto ``Recovered`` name),
    deep-scans the function at ``ea`` from the root variable (default: the
    first argument; override with ``var_name``/``var_index``, E.19) with
    call recursion ON, optionally clears the structure first (E.21), then
    commits the type and retypes the root variable to the committed type
    pointer so re-decompiled pseudocode renders member access. On a commit
    failure the error carries the real reason (keyword/parser diagnostic).

    Returns:
        ``{"ok": True, "structure": str, "type": str, "members": int}``
        or an ok:False dict.
    """
    _require_ida()
    from forge.api.hexrays import decompile as _decompile
    from forge.api.structure import Structure

    # `name` is the structure to BUILD; create it when it is not in the
    # store yet (an existing entry is reused — clear_first governs).
    if name is not None and name not in _structures:
        target = Structure(name)
        _structures[name] = target
        _state.current = name
    else:
        target = _target_scan_structure(name)
    scan = deep_scan(
        ea,
        var_name=var_name,
        var_index=var_index,
        structure=target.name,
        recurse_calls=True,
        max_depth=max_depth,
        clear_first=clear_first,
    )
    if scan.get("ok") is False:
        return scan
    if commit:
        committed = create_type(target.name, overwrite=True)
        if not committed.get("ok", False):
            return {
                "ok": False,
                "error": committed.get("error") or "commit failed",
            }

    root_var = var_name
    if root_var is None:
        try:
            cfunc = _decompile(ea)
            if cfunc is not None:
                lvars = list(cfunc.get_lvars())
                argids = list(getattr(cfunc, "argidx", None) or [])
                if argids and 0 <= argids[0] < len(lvars):
                    root_var = lvars[argids[0]].name
                elif lvars:
                    root_var = lvars[0].name
        except Exception:  # noqa: BLE001 — retyping the root is best-effort
            root_var = None
    type_name = target.created_type_name or target.name
    if root_var and commit:
        with contextlib.suppress(Exception):
            set_lvar_types(ea, {root_var: f"{type_name} *"})
    if commit:
        with contextlib.suppress(Exception):
            reapply(target.name)
    return {
        "ok": True,
        "structure": target.name,
        "type": type_name,
        "members": len(scan.get("members", [])),
    }


@api(
    group="build",
    returns="dict",
    example='r = forge_api.reapply("Recovered"); r["applied"]',
)
def reapply(name: str | None = None) -> dict:
    """Re-apply the committed type to every scan-evidence variable (E.19).

    Re-runs the "apply globally" step of a commit: every recorded scan
    variable of the structure's structure (uniqueness via
    ``identity_key``) gets the structure's pointer type applied again —
    locals via ``modify_user_lvar_info``, globals via ``apply_tinfo``.
    Skips (and reports) the objects whose application raised.

    Returns:
        ``{"applied": int, "skipped": [names]}``.
    """
    _require_ida()
    import ida_typeinf

    from forge.api.structure import Structure

    target = _resolve_structure(name)
    type_name = target.created_type_name or target.name
    tinfo = ida_typeinf.tinfo_t()
    if not tinfo.get_named_type(ida_typeinf.get_idati(), type_name):
        return {"applied": 0, "skipped": [type_name]}
    pointer_of = ida_typeinf.tinfo_t()
    pointer_of.create_ptr(tinfo)

    applied = 0
    skipped = []
    applied_rows = []
    for scan_object in target.get_unique_scanned_variables(target.main_offset):
        if scan_object is None:
            continue
        try:
            scan_object.apply_type(pointer_of)
            applied += 1
            applied_rows.append(Structure._scan_site_row(scan_object))
        except Exception as exc:  # noqa: BLE001 — one bad object must not stop the rest
            skipped.append(getattr(scan_object, "name", "<unnamed>"))
            from forge.util.logging import log_debug

            log_debug(f"reapply failed for {scan_object!r}: {exc}")
    # R3.6: record the re-application in the netnode payload.
    target.last_apply_sites = applied_rows
    _refresh_scan_sites(target)
    _mark_dirty()
    return {"applied": applied, "skipped": skipped}


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
    clear_first: bool = False,
) -> dict:
    """Recover a structure's members with a single-pass shallow scan.

    Runs ``NewShallowScanVisitor`` over the chosen root variable (same root
    resolution and ``root_type`` retype semantics as :func:`deep_scan`; with
    ``structure`` None a fresh auto-named structure is created).
    ``clear_first`` (E21) wipes the target structure's members before the
    scan so repeated scans replace stale evidence.

    Returns:
        dict (see :func:`deep_scan`).
    """
    from forge.api.hexrays import decompile as _decompile
    from forge.api.scanner import NewShallowScanVisitor

    target = _target_scan_structure(structure)
    cfunc = _decompile(ea)
    if cfunc is None:
        return {"ok": False, "error": f"could not decompile {hex(ea)}"}
    obj = _resolve_scan_root(cfunc, var_name=var_name, var_index=var_index, item_ea=item_ea)
    if obj is None:
        return {"ok": False, "error": "could not resolve a scan root (default: first argument)"}
    prior_type = _root_prior_type(obj)
    root_decl = _root_retype_target(obj, root_type)
    if root_decl is not None:
        original_cfunc, original_obj = cfunc, obj
        try:
            refreshed = _apply_root_retype(cfunc, obj, root_decl)
        except Exception as exc:  # noqa: BLE001 — restore, then report
            _restore_root_type(cfunc, obj, prior_type)
            return {"ok": False, "error": f"root lvar retype failed: {exc}"}
        if refreshed is None:
            if root_type is not None:
                return {
                    "ok": False,
                    "error": f"root lvar retype to {root_decl!r} failed",
                }
            # The auto-retype is best-effort sugar: scan the un-retyped root.
        else:
            cfunc = refreshed
            obj = _resolve_scan_root(
                cfunc, var_name=var_name, var_index=var_index, item_ea=item_ea
            )
            if obj is None:
                # Undo the retype on the PRE-retype object — its lvar
                # identity still addresses the IDB's user-lvar entry — and
                # report a structured error instead of raising.
                _restore_root_type(original_cfunc, original_obj, prior_type)
                return {
                    "ok": False,
                    "error": "could not resolve a scan root after retype",
                }
    # M4: clear ONLY when the scan is actually about to run (same contract
    # as deep_scan) — a decompile/root-resolution/retype failure must not
    # return ok:False with the target's members already destroyed.
    if clear_first:
        target.clear_members()
    pre_count = len(target.members)
    visitor = NewShallowScanVisitor(cfunc, target.main_offset, obj, target)
    visitor.process()
    if prior_type and pre_count == 0 and len(target.members) == 0:
        _restore_root_type(cfunc, obj, prior_type)
    _refresh_scan_sites(target)
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
    deterministic members. ``span`` is an EXCLUSIVE tail (byte length):
    the range covers ``[ea, ea + span)``; when the item head at the
    boundary is data-referenced from a scanned function, the tail extends
    by that item's size so the boundary member is kept (E.25). ``span``
    defaults to the size of the item at ``ea``. Returns
    ``{"ok": False, "error": ...}`` when the address has no references.

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
    failed_functions = []
    for func_ea in xrefs:
        # m10: one bad function (decompile crash, visitor exception) must
        # not abort the whole global scan — mirror decompile_many's
        # per-row containment.
        try:
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
        except Exception as exc:  # noqa: BLE001 — one bad EA must not stop the rest
            from forge.util.logging import log_warning

            log_warning(f"global scan of {hex(func_ea)} failed: {exc}")
            failed_functions.append(func_ea)
            continue
        scanned += 1

    sub_head_failures = _add_named_sub_heads(
        target,
        ea,
        span if span is not None else ida_bytes.get_item_size(ea),
        scanned_funcs=set(xrefs),
    )
    _refresh_scan_sites(target)
    result = {
        "ok": True,
        "structure": struct_name,
        "functions_scanned": scanned,
        "members": _collapse_stride_runs(
            [_to_member_dict(member) for member in target.members]
        ),
    }
    if failed_functions:
        result["failed_functions"] = failed_functions
    if sub_head_failures:
        result["failed_members"] = sub_head_failures
    return result


def _collapse_stride_runs(members: list[dict]) -> list[dict]:
    """E16: collapse constant-stride same-type runs into one array member.

    Consecutive enabled members whose type string is identical and whose
    offsets advance by exactly the member size (``offset[i+1] -
    offset[i] == size``) are a stride run: count >= 2 collapses the run
    into ONE member at the run base with ``is_array=True`` and
    ``type``/``size`` expanded for ``count`` elements. Non-array residue
    (single members, gaps, mixed types) is preserved as-is. Operates on
    the JSON member dicts produced by the scan verbs.
    """
    members = copy.deepcopy(members)
    from forge.api.members import _build_array_tinfo

    enabled = [member for member in members if member.get("enabled", True)]
    collapsed: list[dict] = []
    index = 0
    while index < len(enabled):
        member = enabled[index]
        type_str = member.get("type")
        stride = member.get("size")
        if not type_str or not stride or stride <= 0:
            collapsed.append(member)
            index += 1
            continue
        run = [member]
        end_offset = member["offset"] + stride
        while index + len(run) < len(enabled):
            next_member = enabled[index + len(run)]
            if (
                next_member.get("type") != type_str
                or next_member.get("size") != stride
                or next_member["offset"] != end_offset
            ):
                break
            run.append(next_member)
            end_offset += stride
        if len(run) < 2:
            collapsed.append(member)
            index += 1
            continue
        count = len(run)
        array_type = f"{type_str}[{count}]"
        array_size = stride * count
        try:
            import ida_typeinf

            tinfo = _build_array_tinfo(type_str, count)
            if tinfo is not None:
                rendered = tinfo.dstr()
                if rendered:
                    array_type = rendered
                resolved_size = tinfo.get_size()
                if resolved_size is not None and resolved_size not in (
                    ida_typeinf.BADSIZE,
                ) and resolved_size > 0:
                    array_size = resolved_size
        except Exception as exc:  # noqa: BLE001 — tinfo rendering is best-effort
            from forge.util.logging import log_debug

            log_debug(f"stride collapse array tinfo failed for {type_str}: {exc}")
        collapsed.append(
            {
                "offset": run[0]["offset"],
                "name": run[0].get("name", ""),
                "type": array_type,
                "size": array_size,
                "enabled": True,
                "is_array": True,
                "comment": run[0].get("comment", ""),
                "origin": run[0].get("origin", 0),
                "score": run[0].get("score"),
                "array": count,
            }
        )
        index += count
    # disabled members never join runs but must stay in the listing
    disabled = [member for member in members if not member.get("enabled", True)]
    return sorted(collapsed + disabled, key=lambda member: member.get("offset", 0))


def _head_name_without_address(name: str) -> str:
    """``qword_140006128`` -> ``qword``; other names stay as-is."""
    import re as _re

    match = _re.match(r"^(.+?)_[0-9A-Fa-f]{4,}$", name)
    return match.group(1) if match else name


def _add_named_sub_heads(target, ea: int, span: int, scanned_funcs: set | None = None):
    """I.20: synthesize members for named sub-heads inside a global span.

    Every named item in ``[ea, ea + span)`` (excluding the base itself) that
    has no member yet becomes a ``u8``/``u16``/``u32``/``u64`` (or
    ``u8[N]``) member named after the head's short name without its address
    prefix. Deterministic superset of the GUI's stored-address handling.

    E.25: ``span`` is an EXCLUSIVE tail — ``[ea, ea + span)``. When the item
    head AT ``ea + span`` is data-referenced from one of ``scanned_funcs``
    (an address at the boundary feeding the scan), the end extends by that
    item's size so the boundary member is not lost.
    Returns:
        list of failed sub-head member rows (M3) — empty when every
        synthesized member landed.
    """
    def _record(sub_target, offset, size_type, head_name, failures):
        added = add_member(sub_target.name, offset, size_type, name=_head_name_without_address(head_name))
        # M3: a failed sub-head member must be reported, not dropped.
        if isinstance(added, dict) and added.get("ok") is False:
            failures.append(
                {
                    "offset": offset,
                    "name": _head_name_without_address(head_name),
                    "error": added.get("error"),
                }
            )

    failures: list[dict] = []
    sizes = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}
    database = _domain_database_or_none()
    if database is not None:
        bytes_api = getattr(database, "bytes", None)
        names_api = getattr(database, "names", None)
        if bytes_api is not None and names_api is not None:
            end = ea + span
            head = ea
            while True:
                head = bytes_api.get_next_head(head, end)
                if head in (None, -1) or head >= end:
                    break
                name = names_api.get_at(head)
                if not name:
                    continue
                item_size = bytes_api.get_data_size_at(head)
                size_type = sizes.get(item_size, f"u8[{item_size}]")
                if target.get_member_by_offset(head - ea) is None:
                    _record(target, head - ea, size_type, name, failures)
            return failures
    import ida_bytes
    import ida_funcs
    import ida_idaapi
    import ida_name
    import ida_xref
    sizes = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}
    end = ea + span
    if scanned_funcs:
        tail = ea + span
        reference = ida_xref.get_first_dref_to(tail)
        if reference not in (ida_idaapi.BADADDR, None):
            source_function = ida_funcs.get_func(reference)
            if source_function is not None and source_function.start_ea in scanned_funcs:
                tail_item_size = ida_bytes.get_item_size(tail)
                if tail_item_size and tail_item_size > 0:
                    end = tail + tail_item_size
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
            _record(target, head - ea, size_type, name, failures)
    return failures


@api(
    group="decompile",
    returns="list[dict]",
    example='rows = forge_api.scan_returned(0x1400020F0)',
)
def scan_returned(ea: int, *, max_depth: int = 4) -> list:
    """Return-value recon for the function at ``ea`` (F.3).

    Every ``return X`` whose value is pointer-typed (after cast-peel)
    becomes a row with ``return_ea`` (the return's EA), ``type`` (the
    value's declared type), ``var`` (the returned local's name, None for
    arbitrary expressions), ``allocation`` (the allocator-assignment
    guess feeding the value — ``{"ea", "size", "var"}`` or None when the
    guesser finds nothing), and ``callers`` — every calling function
    with the lvar that receives the result
    (``[{"func_ea", "lvar_name"}]``). The caller-driven deep_scan stays
    caller-side; :func:`recover` runs the one-shot pipeline.

    Returns:
        list of row dicts.
    """
    _require_ida()
    from forge.api.hexrays import ctype as _ct
    from forge.api.hexrays import decompile as _decompile
    from forge.api.hexrays import get_funcs_calling_address, iter_returned_exprs
    from forge.features.guess_allocation.guess_allocation import GuessAllocationVisitor

    cfunc = _decompile(ea)
    if cfunc is None:
        return []
    asg_op = getattr(_ct, "asg", None)
    cast_op = getattr(_ct, "cast", None)
    allocator_finder = GuessAllocationVisitor.__new__(GuessAllocationVisitor)
    rows = []
    for returned in iter_returned_exprs(cfunc):
        if returned is None:
            continue
        value_node = returned
        while (
            cast_op is not None
            and getattr(value_node, "op", None) == cast_op
            and getattr(value_node, "x", None) is not None
        ):
            value_node = value_node.x
        tinfo = getattr(returned, "type", None)
        if tinfo is None:
            tinfo = getattr(value_node, "type", None)
        is_ptr = getattr(tinfo, "is_ptr", None)
        if not callable(is_ptr) or not is_ptr():
            continue
        try:
            type_str = tinfo.dstr()
        except Exception:  # noqa: BLE001 — degraded tinfos degrade to None
            type_str = None
        var_node = getattr(value_node, "v", None)
        var_name = getattr(var_node, "name", None)

        allocation = None
        try:
            alloc_obj = allocator_finder._find_allocator_assignment(
                cfunc, value_node, asg_op
            )
            if alloc_obj is not None:
                allocation = {
                    "ea": getattr(alloc_obj, "ea", None),
                    "size": getattr(alloc_obj, "size", None),
                    "var": var_name,
                }
        except Exception:  # noqa: BLE001 — allocation guessing is best-effort
            allocation = None

        callers = []
        for caller_ea in sorted(get_funcs_calling_address(ea)):
            caller_cfunc = _decompile(caller_ea)
            if caller_cfunc is None:
                continue
            assigned = _assigned_lvar_for_call(caller_cfunc, ea)
            if assigned is not None:
                callers.append({"func_ea": caller_ea, "lvar_name": assigned})

        rows.append(
            {
                "return_ea": getattr(returned, "ea", None),
                "type": type_str,
                "var": var_name,
                "allocation": allocation,
                "callers": callers,
            }
        )
    return rows


# --------------------------------------------------------------------------- #
# build / apply / finalize
# --------------------------------------------------------------------------- #
_C_RESERVED_KEYWORDS = frozenset(
    {
        "_Alignas", "_Alignof", "auto", "bool", "break", "case", "char",
        "const", "continue", "default", "do", "double", "else", "enum",
        "extern", "float", "for", "goto", "if", "inline", "int", "long",
        "register", "restrict", "return", "short", "signed", "sizeof",
        "static", "struct", "switch", "typedef", "union", "unsigned",
        "void", "volatile", "while",
    }
)


_C_KEYWORDS = frozenset(
    {
        "alignas", "alignof", "and", "asm", "auto", "bool", "break", "case",
        "char", "const", "continue", "default", "do", "double", "else",
        "enum", "extern", "float", "for", "goto", "if", "inline", "int",
        "long", "register", "restrict", "return", "short", "signed",
        "sizeof", "static", "struct", "switch", "typedef", "union",
        "unsigned", "void", "volatile", "while",
    }
)


@api(
    group="scan",
    returns="list[dict]",
    example='sites = forge_api.scan_sites("ChainNode")',
)
def scan_sites(name: str | None = None) -> list:
    """The scan-evidence sites of a store structure, from the IDB (R3.6).

    Every location the scans attached to members of ``name`` — the same
    sites `create_type` applies the committed pointer type to. The rows
    are persisted in the database's netnodes (catalog payload), so they
    survive worker drops, warm reopens and store rebuilds. Coverage
    check for the scan → auto_resolve → commit flow: after scanning,
    list the sites; if the struct is used elsewhere (other allocation
    sites, callers of the runner, globals by xref) and the list misses
    them, scan those roots INTO the same structure before committing.
    Empty for hand-built structures that were never scanned into —
    commit then reports ``applied_sites: []``.

    Each row is ``{"func_ea", "var", "ea", "type", "member_offset"}``.
    Returns:
        list of site dicts.
    """

    target = _resolve_structure(name)
    persisted = getattr(target, "scan_sites_rows", None) or []
    if persisted:
        return copy.deepcopy(list(persisted))
    from forge.api.store import _live_scan_site_rows
    return copy.deepcopy(_live_scan_site_rows(target))


def _validate_member_name(name: str) -> None:
    """Reject C-keyword member names (R2.6).

    The IDB parser silently drops members whose names are reserved words
    (``inline``, ``int``, ...) — the member vanishes from the committed
    cdecl with no error. A loud failure up front beats a phantom member.
    """
    if name in _C_KEYWORDS:
        raise ForgeApiError(f"{name} is a C keyword — rename the member")


def _validate_pack(pack: int | None) -> None:
    """Reject pack values the pragma verb cannot express (R3.2 F1).

    ``#pragma pack(push, N)`` requires ``N`` a positive integer; None is
    the natural-alignment opt-out.
    """
    if pack is not None and (not isinstance(pack, int) or pack < 1):
        raise ForgeApiError(
            f"pack must be an int >= 1 or None, got {pack!r}"
        )


def _commit_failure_reason(cdecl: str, name: str) -> str:
    """Explain why committing ``cdecl`` as ``name`` failed.

    Recovery-eval gap #1 (2026-08-13): a store struct named ``inline``
    committed nothing while the facade reported only "failed to recreate
    type after delete" — the IDB parser rejects reserved-keyword tags
    (and other malformed declarations) without an error channel. Probe
    the parser and name to hand back a real reason.
    """
    import ida_typeinf

    if name in _C_RESERVED_KEYWORDS:
        return (
            f"{name!r} is a C keyword — the IDB type parser rejects it; "
            "rename the structure (e.g. inline -> inline_node)"
        )
    errors = 0
    try:
        errors = ida_typeinf.idc_parse_types(cdecl, 0) or 0
    except Exception:  # noqa: BLE001 — parser probe is best-effort
        errors = -1
    if errors > 0:
        # R3.8: IDA's parser prints "Void type is forbidden here" for
        # bare-void members without naming them — find them in the text
        # so the failure is actionable. ``void *``/``void **`` are legal;
        # only a member whose TYPE token resolves to bare void is not.
        void_members = []
        for line in cdecl.splitlines():
            body = line.strip().rstrip(";").strip()
            if not body or body.startswith(("struct", "#")):
                continue
            # "u64 gap_4[4];" -> name token(s) after the type; only bare
            # "void NAME" members are forbidden — "void *p" is legal.
            head = body.split()
            if len(head) >= 2 and head[0] == "void" and not head[1].startswith("*"):
                void_members.append(head[1].lstrip("*").split("[")[0])
        extra = ""
        if void_members:
            extra = (
                f" — {len(void_members)} void-typed member(s): "
                f"{', '.join(void_members)} (IDA forbids bare void; "
                "set a real type or disable the member)"
            )
        return (
            f"IDB type parser rejected the declaration "
            f"({errors} error(s)) — reserved keyword or unresolved member type{extra}"
        )
    return "type parser accepted the declaration but no type materialized"


def _UNDO_STORE():
    """Netnode-backed snapshot store for :func:`undo_type` (E17)."""
    from forge.api.storage import Storage

    return Storage("ForgeTypeSnapshots")


def _named_type_declaration(name: str) -> str | None:
    """The IDB named type's full declaration text, parseable by set_cdecl.

    ``type_of(name)["type"]`` is the bare type name (``Recovered2``), not
    a restorable declaration; printing the tinfo the same way
    :meth:`Structure.build_cdecl` does yields ``struct Recovered2 { ... };``.
    Returns None when the type is missing or the print fails.
    """
    try:
        import ida_typeinf

        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.get_named_type(ida_typeinf.get_idati(), name):
            return None
        return (
            ida_typeinf.print_tinfo(
                None,
                4,
                5,
                ida_typeinf.PRTYPE_MULTI
                | ida_typeinf.PRTYPE_TYPE
                | ida_typeinf.PRTYPE_SEMI,
                tinfo,
                name,
                None,
            )
            or None
        )
    except Exception:  # noqa: BLE001 — version/format tolerance
        return None


def _snapshot_type_before_commit(name: str, after_decl: str | None = None) -> None:
    """Record the type's pre-commit declaration for :func:`undo_type`.

    E17: the facade snapshots the prior cdecl BEFORE every commit that
    changes a type, so ``undo_type`` can restore it without an IDA undo
    queue. A type that did not exist yet records ``before: None`` —
    ``undo_type`` then removes it. Best-effort: any read/write failure
    degrades to no snapshot, never a failed commit.
    """
    prior_decl = _named_type_declaration(name)
    try:
        _UNDO_STORE()[name] = {"before": prior_decl, "after": after_decl}
    except Exception as exc:  # noqa: BLE001 — cache write must never break commits
        from forge.util.logging import log_warning

        log_warning(f"could not write undo snapshot for {name}: {exc}")


def _is_forge_placeholder_type(name: str) -> bool:
    """True when ``name`` is a lazy placeholder this plugin seeded earlier.

    E10 (eval review 2026-08-13): placeholders (``struct X { char
    _placeholder; };``, see ``_ensure_placeholder_type``) are forge's own
    scaffolding, not a user type — ``create_type(overwrite=False)`` must
    not treat them as an existing type, or the default scan→commit flow
    breaks on every self-referencing struct.
    """
    database = _domain_database_or_none()
    if database is not None:
        types_api = getattr(database, "types", None)
        getter = getattr(types_api, "get_by_name", None)
        members_getter = getattr(types_api, "get_udt_members", None)
        if callable(getter) and callable(members_getter):
            tinfo = getter(name)
            is_udt = getattr(tinfo, "is_udt", None)
            if tinfo is None or not callable(is_udt) or not is_udt():
                return False
            members = list(members_getter(tinfo) or ())
            return len(members) == 1 and getattr(members[0], "name", "") == "_placeholder"
    import ida_typeinf

    tinfo = ida_typeinf.tinfo_t()
    if not tinfo.get_named_type(ida_typeinf.get_idati(), name):
        return False
    udt = ida_typeinf.udt_type_data_t()
    if not tinfo.get_udt_details(udt):
        return False
    return len(udt) == 1 and getattr(udt[0], "name", "") == "_placeholder"


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
    exists. Never shows a dialog. The post-commit reference refresh is
    change-gated like :func:`push_type`: only a commit that actually
    changed the IDB type re-applies recorded sites; an unchanged re-commit
    reports ``references: {"skipped": "unchanged"}`` so manual applied-site
    changes survive.

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
            if _is_forge_placeholder_type(name):
                # E10: forge's own lazy placeholder — replace it wholesale,
                # as if this were the first commit.
                overwrite = True
            else:
                return {"ok": False, "error": "type already exists (overwrite disabled)"}
    elif overwrite is True and not Structure._declaration_parses(cdecl):
        # Validate before the destructive delete so a malformed edit cannot
        # destroy the existing type (the DB would end up with no type at all).
        return {"ok": False, "error": "declaration could not be parsed for overwrite"}

    # Gap #9 pack-readiness gate: refuse to pack when an enabled member's
    # authored declaration would silently degrade to a placeholder — the
    # caller gets a structured unresolved-types error instead of a
    # silently degraded type.
    readiness = catalog.pack_readiness(target.name)
    if not readiness.ok:
        report = readiness.to_dict()
        return {
            "ok": False,
            "error": report.get("error") or "pack readiness gate refused the pack",
            "code": "unresolved_references",
            "unresolved_types": report.get("unresolved_types", []),
            "blocked_members": report.get("blocked", []),
        }
    # E17: record the pre-commit declaration so undo_type can restore it.
    _snapshot_type_before_commit(target.name, cdecl)
    # Ordinal refresh gate (gap #10, change-gated like push_type): snapshot
    # the IDB's UDT rows BEFORE the write so the post-commit refresh only
    # fires when the commit actually changed the type. An unqueryable IDB
    # degrades to the conservative always-refresh behavior.
    try:
        _, prior_idb_rows = _idb_udt_snapshot(target.name)
    except Exception:  # noqa: BLE001 — unqueryable IDB: refresh conservatively
        prior_idb_rows = None
    created = target.set_cdecl(cdecl, target.main_offset, overwrite=overwrite)
    if created is None:
        if overwrite is True:
            return {
                "ok": False,
                "error": "failed to recreate type after delete — "
                + _commit_failure_reason(cdecl, target.name),
            }
        return {"ok": False, "error": "type already exists (overwrite disabled)"}
    # R3.6: persist the commit's applied-site record in the netnode
    # payload (survives drops; the eval can check the DB outcome).
    _refresh_scan_sites(target)
    _mark_dirty()
    # Ordinal refresh gate (gap #10): only a commit that CHANGED the IDB
    # type re-landed it with a fresh ordinal, so dependent store structures
    # re-commit and recorded application sites re-apply through the
    # ordinary hook. One level deep: nested commits re-enter the
    # refreshing_references guard and are skipped. An unchanged re-commit
    # must NOT re-apply recorded sites — that would clobber manual
    # applied-site changes made between commits.
    try:
        _, current_idb_rows = _idb_udt_snapshot(target.name)
    except Exception:  # noqa: BLE001 — unqueryable IDB: refresh conservatively
        current_idb_rows = None
    if (
        prior_idb_rows is None
        or current_idb_rows is None
        or not prior_idb_rows
        or sorted(prior_idb_rows) != sorted(current_idb_rows)
    ):
        references_report = _refresh_type_references(target.name)
    else:
        references_report = {"skipped": "unchanged"}
    return {
        "ok": True,
        "type_name": target.created_type_name,
        "declaration": cdecl,
        "skipped": [m.name for m in target.members if not m.enabled],
        # R3.5: every scan-evidence site the pointer type was applied to
        # on this commit (GUI-parity: the same apply step the form runs).
        # Empty when no scans were recorded into THIS structure — re-scan
        # (deep_scan with structure=<name>) before committing.
        "applied_sites": list(getattr(target, "last_apply_sites", [])),
        # Gap #10: what the refresh gate did after this commit.
        "references": references_report,
    }


@api(
    group="build",
    returns="dict",
    example='r = forge_api.commit_declaration("Outer", "struct Outer { int x; };")',
)
def commit_declaration(
    name: str, declaration: str, *, overwrite: bool = True
) -> dict:
    """Commit a declaration TEXT as the structure's type (R3.9).

    The API form of the GUI pack dialog: the exact cdecl (as edited in
    the form's ``ask_text`` dialog) is committed through the same
    ``Structure.set_cdecl`` chain the headless build path uses — the
    layout build is skipped, the declaration must name the structure,
    and the apply-at-scan-sites step runs identically. ``#pragma pack``
    wrapping is applied the same way (missing wrapper is added when the
    structure packs). No dialogs ever (``overwrite=True`` default).

    Returns:
        ``{"ok": True, "type_name", "applied_sites"}`` or an error dict.
    """
    from forge.api.structure import Structure

    _require_ida()
    target = _resolve_structure(name)
    declared = Structure._extract_type_name(declaration)
    if declared != target.name:
        return {
            "ok": False,
            "error": (
                f"declaration names {declared!r}, not the store "
                f"structure {target.name!r}"
            ),
        }
    # Gap #9 pack-readiness gate (same contract as create_type): surface
    # unresolved member references as a structured error instead of
    # committing a silently degraded type.
    readiness = catalog.pack_readiness(target.name)
    if not readiness.ok:
        report = readiness.to_dict()
        return {
            "ok": False,
            "error": report.get("error") or "pack readiness gate refused the commit",
            "code": "unresolved_references",
            "unresolved_types": report.get("unresolved_types", []),
            "blocked_members": report.get("blocked", []),
        }
    _snapshot_type_before_commit(target.name, declaration)
    created = target.set_cdecl(declaration, target.main_offset, overwrite=overwrite)
    if created is None:
        return {
            "ok": False,
            "error": "failed to commit declaration — "
            + _commit_failure_reason(declaration, target.name),
        }
    _refresh_scan_sites(target)
    _mark_dirty()
    return {
        "ok": True,
        "type_name": target.created_type_name,
        "applied_sites": list(getattr(target, "last_apply_sites", [])),
    }


def _typedef_declarator_name(declaration: str, name: str) -> str | None:
    """Insert ``name`` after the pointer star of a function-pointer
    declarator (R3.2 F3).

    IDA's parser rejects the abstract-declarator-then-name form
    (``typedef int (__cdecl *)(void *, unsigned int) NAME;``); naming the
    pointer declarator directly (``int (__cdecl *NAME)(void *, unsigned
    int)``) parses. Returns None when the declaration has no
    function-pointer declarator to rewrite.
    """
    if not re.search(r"\(\s*(?:__\w+\s+)?\*", declaration):
        return None
    return re.sub(
        r"(\(\s*(?:__\w+\s+)?\*)(\s*)\)",
        lambda m: f"{m.group(1)}{name}{m.group(2)})",
        declaration,
        count=1,
    )


@api(
    group="types",
    returns="dict",
    example='r = forge_api.create_typedef("DispatchFn", "int (__cdecl *)(void *, unsigned int)")',
)
def create_typedef(name: str, declaration: str) -> dict:
    """Create an IDB named type for a non-UDT C type (E29).

    ``declaration`` is the typedef body: a function pointer, scalar alias,
    enum, ... (``"int (__cdecl *)(void *, unsigned int)"``). Parsed through
    the same member-parse path — an unparseable declaration fails loudly.
    The typedef commits as ``typedef <declaration> <name>;`` through
    ``forge_types.create_type`` (the pure IDB-write path used by every
    commit — no pseudocode-view dependency); when that write fails, the
    declarator-name form (``typedef int (__cdecl *NAME)(...);``) is tried
    — IDA's parser rejects abstract declarators — and then the
    ``ida_hexrays.create_typedef`` mechanism (the templated-types path)
    materializes the named type as a last-resort fallback. Typedefs live
    in the type table like any other named type (:func:`type_of` reads
    them back).

    Returns:
        ``{"ok": bool, "type": str}``, or an error dict when the
        declaration does not parse.
    """
    _require_ida()
    database = _domain_database_or_none()
    if database is not None:
        _validate_member_name(name)
        types_api = getattr(database, "types", None)
        parser = getattr(types_api, "parse_one_declaration", None)
        if callable(parser):
            try:
                parsed = parser(None, declaration, name)
            except Exception:
                parsed = None
            if parsed is not None:
                return {"ok": True, "type": name}
            return {
                "ok": False,
                "error": f"could not parse typedef declaration {declaration!r}",
            }
    from forge.api.members import parse_user_tinfo

    _validate_member_name(name)
    if parse_user_tinfo(declaration) is None:
        return {
            "ok": False,
            "error": f"could not parse typedef declaration {declaration!r}",
        }

    import ida_hexrays

    import forge.api.types as forge_types

    if forge_types.create_type(name, f"typedef {declaration} {name};"):
        return {"ok": True, "type": name}

    declarator_name = _typedef_declarator_name(declaration, name)
    if declarator_name is not None and forge_types.create_type(
        name, f"typedef {declarator_name};"
    ):
        return {"ok": True, "type": name}

    create_typedef_fn = getattr(ida_hexrays, "create_typedef", None)
    if callable(create_typedef_fn):
        try:
            create_typedef_fn(name)
        except Exception as exc:  # noqa: BLE001 — version/format tolerance
            return {"ok": False, "type": name, "error": f"typedef write failed: {exc}"}
        if is_type(name):
            return {"ok": True, "type": name}
    return {"ok": False, "type": name, "error": "typedef write failed"}


@api(
    group="types",
    returns="dict",
    example='r = forge_api.rename_member("Outer", 0x10, "bag_fixed")',
)
def rename_member(name: str, offset: int, new_name: str) -> dict:
    """Rename a member of a COMMITTED IDB named struct type at byte
    ``offset`` (recovery-eval round 2 F2: the ``gap_*`` auto-fill entries
    the store never had, which reappear on every re-commit).

    The store is NOT changed — this renames the live IDB type only. A
    later ``create_type(overwrite=True)`` re-commits the store's member
    set, losing the rename: rename AFTER the last re-commit.

    Returns:
        ``{"ok": True, "type", "offset", "from", "to"}``, or an error
        dict when the type is missing, the offset has no member, or the
        IDB write fails.
    """
    _require_ida()
    database = _domain_database_or_none()
    if database is not None:
        _validate_member_name(new_name)
        types_api = getattr(database, "types", None)
        getter = getattr(types_api, "get_by_name", None)
        members_getter = getattr(types_api, "get_udt_members", None)
        if callable(getter) and callable(members_getter):
            tinfo = getter(name)
            if tinfo is None:
                return {"ok": False, "error": f"no type {name}"}
            members = list(members_getter(tinfo) or ())
            member = next((item for item in members if getattr(item, "offset", None) == offset), None)
            if member is None:
                return {"ok": False, "error": f"no member at offset {hex(offset)}"}
            previous = getattr(member, "name", "")
            if previous == new_name:
                return {"ok": True, "type": name, "offset": offset, "from": previous, "to": new_name}
            # M2: the real ida-domain member row is a plain dataclass with
            # NO rename-persistence mechanism — mutating the detached row
            # cannot reach the IDB. When no persistence exists (or the
            # write reports failure), fall through to the definitive SDK
            # rename path and record the fallback.
            setter = getattr(member, "set_name", None)
            if callable(setter):
                try:
                    if setter(new_name):
                        return {"ok": True, "type": name, "offset": offset, "from": previous, "to": new_name}
                except Exception:  # noqa: BLE001 — try the SDK path instead
                    pass
            _sdk_fallback(
                "types.rename_member",
                "ida-domain member rename persistence unavailable",
            )
    _validate_member_name(new_name)

    import ida_typeinf

    tinfo = ida_typeinf.tinfo_t()
    if not tinfo.get_named_type(ida_typeinf.get_idati(), name):
        return {"ok": False, "error": f"no type {name}"}

    udt = ida_typeinf.udt_type_data_t()
    if not tinfo.get_udt_details(udt):
        return {"ok": False, "error": f"{name} is not a struct/union type"}

    # Live 9.4 finding: get_udt_details reports offsets in BITS (the
    # byte-vs-bit convention differs across builds) — accept the byte
    # offset when the raw value is bit-clean (same rule as type_of).
    index = None
    for idx, member in enumerate(udt):
        raw = getattr(member, "offset", None)
        if raw == offset or (
            raw is not None and raw % 8 == 0 and raw // 8 == offset
        ):
            index = idx
            break
    if index is None:
        return {"ok": False, "error": f"no member at offset {hex(offset)}"}

    prev = udt[index].name
    if prev == new_name:
        return {
            "ok": True,
            "type": name,
            "offset": offset,
            "from": prev,
            "to": new_name,
        }

    # Live 9.4 finding (R3.2 probe): tinfo_t.rename_udm mutates the named
    # type IN PLACE — the rename is til-persistent and the packed layout
    # survives (no commit verb, no udt rebuild; the 9.4 build has no
    # update_named_type, and create_udt on pack-derived offsets errors).
    rename_udm = getattr(tinfo, "rename_udm", None)
    if callable(rename_udm):
        code = None
        rename_err = None
        try:
            code = rename_udm(index, new_name)
        except Exception as exc:  # noqa: BLE001 — version/format tolerance
            rename_err = str(exc)
        if code == getattr(ida_typeinf, "TERR_OK", 0):
            return {
                "ok": True,
                "type": name,
                "offset": offset,
                "from": prev,
                "to": new_name,
            }
        return {
            "ok": False,
            "type": name,
            "error": f"rename failed ({code if code is not None else rename_err})",
        }

    # Older builds / stubs: get_udt_details COPIES the member data out;
    # bake the mutation back into the tinfo (preserving the pack
    # attribute) and commit via update_named_type, else delete+re-file.
    prev_pack = getattr(udt, "pack", None)
    udt[index].name = new_name
    is_union = getattr(tinfo, "is_union", None)
    if callable(is_union) and is_union():
        udt_flags = getattr(ida_typeinf, "BTF_UNION", None) or 0
    else:
        udt_flags = getattr(ida_typeinf, "BTF_STRUCT", None) or 0
    try:
        rebuilt = tinfo.create_udt(udt, udt_flags)
    except Exception:  # noqa: BLE001 — unrebuildable udt degrades loudly
        rebuilt = False
    if not rebuilt:
        return {
            "ok": False,
            "type": name,
            "error": f"failed to rebuild {name} with the renamed member",
        }
    try:
        if prev_pack not in (None, 0, -1):
            set_pack = getattr(tinfo, "set_udt_pack", None)
            if callable(set_pack):
                set_pack(prev_pack)
    except Exception as exc:  # noqa: BLE001 — pack rescue is best-effort
        from forge.util.logging import log_debug

        log_debug(f"pack rescue after rename failed: {exc}")

    update_fn = getattr(ida_typeinf, "update_named_type", None)
    if callable(update_fn):
        try:
            if update_fn(ida_typeinf.get_idati(), name, tinfo):
                return {
                    "ok": True,
                    "type": name,
                    "offset": offset,
                    "from": prev,
                    "to": new_name,
                }
        except Exception as exc:  # noqa: BLE001 — fall back to delete+re-file
            from forge.util.logging import log_debug

            log_debug(f"rename_member in-place update unavailable: {exc}")

    # Fallback (stubs / older IDA): serialize the edited udt and re-file it,
    # mirroring the apply_new_field tail (live-proven on 9.4).
    import idaapi as _idaapi

    cdecl = _idaapi.print_tinfo(
        None,
        4,
        5,
        _idaapi.PRTYPE_MULTI | _idaapi.PRTYPE_TYPE | _idaapi.PRTYPE_SEMI,
        tinfo,
        name,
        None,
    )
    if not cdecl:
        return {
            "ok": False,
            "type": name,
            "error": f"failed to serialize {name} after rename",
        }
    previous_ordinal = _idaapi.get_type_ordinal(_idaapi.cvar.idati, name)
    if previous_ordinal:
        _idaapi.del_numbered_type(_idaapi.cvar.idati, previous_ordinal)
        ordinal = _idaapi.idc_set_local_type(
            previous_ordinal, cdecl, _idaapi.PT_TYP
        )
    else:
        ordinal = _idaapi.idc_set_local_type(-1, cdecl, _idaapi.PT_TYP)
    if not ordinal:
        return {
            "ok": False,
            "type": name,
            "error": f"failed to re-file {name} after rename",
        }
    return {
        "ok": True,
        "type": name,
        "offset": offset,
        "from": prev,
        "to": new_name,
    }


@api(
    group="types",
    returns="dict",
    example='r = forge_api.undo_type("Recovered")',
)
def undo_type(name: str) -> dict:
    """Revert a type to its pre-commit declaration (E17).

    :func:`create_type`, :func:`finalize` and :func:`push_type` snapshot
    the prior cdecl before every commit that changes a type; ``undo_type``
    restores it via :meth:`Structure.set_cdecl` (``overwrite=True``,
    dialog-free) and consumes the snapshot. When the type did not exist
    before the commit, there is nothing to restore to — the revert is
    REFUSED with an error instead of deleting: a committed type is
    updated, never deleted (an applied/comitted type must not dangle).
    Returns an error dict when no snapshot exists.

    Returns:
        ``{"ok": True, "restored_declaration": str}``, or an error dict.
    """
    _require_ida()
    from forge.api.structure import Structure

    try:
        entry = _UNDO_STORE().get(name)
    except Exception:  # noqa: BLE001 — snapshot reads are best-effort
        entry = None
    if entry is None or "before" not in entry:
        return {"ok": False, "error": f"no undo snapshot for {name!r}"}
    prior = entry.get("before")
    with contextlib.suppress(Exception):
        mirror = _UNDO_STORE()
        if name in mirror:
            del mirror[name]
    if prior is None:
        return {
            "ok": False,
            "error": f"no prior declaration for {name!r} — the type was created "
            "by the commit. Update it instead: edit the store structure "
            "(remove_members/add_member/set_member) and re-commit with "
            "create_type(..., overwrite=True).",
        }
    structure = Structure(name)
    restored = structure.set_cdecl(prior, structure.main_offset, overwrite=True)
    if restored is None:
        return {
            "ok": False,
            "error": "restore failed — "
            + _commit_failure_reason(prior, name),
        }
    return {"ok": True, "restored_declaration": prior}


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
    # E17: snapshot the pre-commit declaration for undo_type.
    _snapshot_type_before_commit(target.name)
    tinfo = target.create_type_if_ready(_structures, headless=True)
    if tinfo is None:
        if unresolved:
            return {"ok": False, "unresolved": unresolved}
        return {
            "ok": False,
            "error": "failed to create type — "
            + _commit_failure_reason(
                f"struct {target.name} {{ }};", target.name
            ),
        }
    # R3.6: persist the commit's applied-site record (netnode payload).
    _refresh_scan_sites(target)
    _mark_dirty()
    return {
        "ok": True,
        "type_name": target.created_type_name,
        "skipped": [m.name for m in target.members if not m.enabled],
        # R3.5: sites the pointer type got applied to on this commit.
        "applied_sites": list(getattr(target, "last_apply_sites", [])),
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
        list of ``{"structure": name, "ok": bool, "created": bool,
        "created_names": [str], "error": str|None}``.
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
        # E9 (eval review 2026-08-13): the old bool hid partial successes
        # and the reason for failure ("see IDA log" is unreachable via the
        # facade) — the subtree walk now reports created names + the first
        # failure reason.
        ok, created_names, error = root.create_subtree_types_postorder(
            _structures, headless=True
        )
        results.append(
            {
                "structure": root_name,
                "ok": ok,
                "created": root.created_type_name is not None,
                "created_names": created_names,
                "error": error,
            }
        )
    return results


# --------------------------------------------------------------------------- #
# naming
# --------------------------------------------------------------------------- #
_SPECIFIER_RE = re.compile(
    r"%(?:[+ #0\-]*)?(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh|h|ll|l|z|t|j|L)?([a-zA-Z%])"
)
_WORD_TAIL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*[=:]?\s*$")
_SYNTHESIZED_NAME_RE = re.compile(r"(?:i|u|f)[0-9a-fA-F_]*")


def _is_synthesized_member_name(name: str) -> bool:
    """True when ``name`` is forge's auto-generated form (``u32_10``,
    ``i64_a``) or the generic ``field`` fallback — never a user name."""
    return bool(_SYNTHESIZED_NAME_RE.fullmatch(name)) or bool(
        re.fullmatch(r"field_[0-9a-fA-F_]*", name)
    )


def _format_token_labels(format_bytes) -> list[str | None]:
    """The word preceding each conversion specifier in a printf literal.

    ``"score=%d flags=%x"`` → ``["score", "flags"]``; a specifier that is
    not preceded by an identifier (``"%d"``) yields None — the slot still
    counts (arg ORDER is what matters), only the name is undecidable.
    ``%%`` is not a slot. Other specifiers (``%n``, ``%e``...) consume a
    slot too — the member then keeps its synthesized name.
    """
    if isinstance(format_bytes, (bytes, bytearray, memoryview)):
        try:
            text = bytes(format_bytes).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 — undecodable literals yield no labels
            return []
    else:
        text = str(format_bytes or "")
    tokens: list[str | None] = []
    cursor = 0
    for match in _SPECIFIER_RE.finditer(text):
        if match.group(1) == "%":
            cursor = match.end()
            continue
        label = text[cursor : match.start()]
        cursor = match.end()
        word = _WORD_TAIL_RE.search(label)
        tokens.append(word.group(1) if word else None)
    return tokens


def _unwrap_treeitem(item):
    """The specific ctree object behind a treeitems entry.

    ``to_specific_type`` is a METHOD on some builds' wrappers and a
    PROPERTY (already-returned object) on the live 9.4 build; test
    doubles use callables. Plain items pass through.
    """
    to_specific = getattr(item, "to_specific_type", None)
    if callable(to_specific):
        return to_specific()
    if to_specific is not None:
        return to_specific
    return getattr(item, "it", None) or item


def _iter_ctree_calls(cfunc):
    """Yield every call cexpr in ``cfunc`` (treeitems or visitor walk).

    Shared by the printf naming (E14) and scan_returned (F.3) call-site
    walks. Treeitems is empty on the live 9.4 build — the ctree-visitor
    fallback covers it (same pattern as the E.22 walkers).
    """
    import ida_hexrays

    ctype_mod = getattr(ida_hexrays, "ctype", None)
    if ctype_mod is None:
        from forge.api.hexrays import ctype as ctype_mod

    call_op = getattr(ctype_mod, "call", None)

    def _is_call(cexpr) -> bool:
        return call_op is None or getattr(cexpr, "op", None) == call_op

    treeitems = getattr(cfunc, "treeitems", None)
    if treeitems:
        for item in treeitems:
            specific = _unwrap_treeitem(item)
            if _is_call(specific):
                yield specific
        return

    walker_cls = getattr(ida_hexrays, "ctree_visitor_t", None)
    if walker_cls is None:
        return

    class _CallWalker(walker_cls):
        def __init__(self):
            try:
                walker_cls.__init__(self, 0)
            except TypeError:  # pragma: no cover — binding drift
                walker_cls.__init__(self, None)
            self.found = []

        def visit_expr(self, expr):
            if _is_call(expr):
                self.found.append(expr)
            return 0

    walker = _CallWalker()
    body = getattr(cfunc, "body", None)
    if body is not None:
        try:
            walker.apply_to(body, None)
        except Exception:  # noqa: BLE001 — walk is best-effort
            return
    yield from walker.found


def _printf_call_expressions(cfunc) -> list:
    """The call cexprs of printf-family targets in ``cfunc`` (E14).

    A call counts when its target is an imported name ending in
    ``printf``/``sprintf``/``snprintf``/``vsnprintf``, or a function
    whose name contains ``printf`` / starts with ``log`` (local wrappers
    like the fixture's ``log_msg`` — the call-site argument shape is the
    same: format literal + varargs).
    """
    import ida_funcs
    database = _domain_database_or_none()
    domain_functions = getattr(database, "functions", None) if database is not None else None
    domain_get_at = getattr(domain_functions, "get_at", None)
    domain_get_name = getattr(domain_functions, "get_name", None)

    import_name_by_ea = {row["ea"]: row["name"] or "" for row in imports()}
    printf_suffixes = ("printf", "sprintf", "snprintf", "vsnprintf")
    calls: list = []
    for call in _iter_ctree_calls(cfunc):
        callee_ea = getattr(getattr(call, "x", None), "obj_ea", None)
        name = import_name_by_ea.get(callee_ea) or ""
        if not name and callee_ea not in (None, -1) and callable(domain_get_at) and callable(domain_get_name):
            try:
                name = domain_get_name(domain_get_at(callee_ea)) or ""
            except Exception:  # noqa: BLE001
                name = ""
        if not name and callee_ea not in (None, -1):
            try:
                name = ida_funcs.get_func_name(callee_ea) or ""
            except Exception:  # noqa: BLE001 — name resolution is best-effort
                name = ""
        if name.endswith(printf_suffixes) or (
            name and ("printf" in name or name.startswith("log"))
        ):
            calls.append(call)
    return calls


def _assigned_lvar_for_call(cfunc, target_ea) -> str | None:
    """The lvar name a call's result is assigned to (F.3).

    Finds the call of ``target_ea`` in ``cfunc`` and, when its parent
    statement is an assignment (``v = f(...)``), returns ``v``'s name.
    """
    from forge.api.hexrays import ctype as _ctype

    asg_op = getattr(_ctype, "asg", None)
    for call in _iter_ctree_calls(cfunc):
        if getattr(getattr(call, "x", None), "obj_ea", None) != target_ea:
            continue
        parent = None
        body = getattr(cfunc, "body", None)
        find_parent = getattr(body, "find_parent_of", None)
        if callable(find_parent):
            try:
                parent = find_parent(call)
            except Exception:  # noqa: BLE001 — parent lookup is best-effort
                parent = None
        if parent is None:
            continue
        target_node = getattr(parent, "x", None)
        if (
            asg_op is None or getattr(parent, "op", None) == asg_op
        ) and getattr(target_node, "v", None) is not None:
            name = getattr(target_node, "v", None).name
            if name:
                return name
    return None


@api(
    group="naming",
    returns="dict",
    example='r = forge_api.name_members_from_printf("Player", 0x1400014F0)',
)
def name_members_from_printf(structure: str, ea: int) -> dict:
    """Name members from the function's printf format strings (E14).

    is a ``memptr`` (``obj->member``) and lands on a store member whose
    name is still the synthesized pattern (``u32_10`` / ``field_8``) is
    named after the label the literal gives that slot (``score=%d
    flags=%x`` → members ``score``, ``flags``). Calls are merged: the
    first call's resolvable slots win, later calls only fill slots the
    earlier calls left unnamed. User-named members are NEVER
    overwritten; unresolvable slots are skipped.

    Returns:
        ``{"ok": True, "renamed": [names]}`` or an error dict.
    """
    from forge.api.hexrays import ctype as _ctype
    from forge.api.hexrays import decompile as _decompile

    target = _resolve_structure(structure)
    cfunc = _decompile(ea)
    if cfunc is None:
        return {"ok": False, "error": f"could not decompile {hex(ea)}"}
    calls = _printf_call_expressions(cfunc)
    if not calls:
        return {
            "ok": False,
            "error": "no printf-family call found in the function",
        }

    database = _domain_database_or_none()
    bytes_api = getattr(database, "bytes", None) if database is not None else None
    import ida_bytes
    renamed = []
    for call in calls:
        args = list(getattr(call, "a", []) or [])
        if not args:
            continue
        format_arg = args[0]
        format_expr = format_arg
        for _ in range(4):
            op = getattr(format_expr, "op", None)
            if op in (_ctype.cast, _ctype.ref):
                inner = getattr(format_expr, "x", None)
                if inner is None:
                    break
                format_expr = inner
                continue
            break
        format_ea = getattr(format_expr, "obj_ea", None) if getattr(format_expr, "op", None) in (_ctype.obj, _ctype.str) else None
        if format_ea is None:
            format_ea = getattr(format_expr, "obj", None)
        if format_ea in (None, -1):
            continue
        if bytes_api is not None and hasattr(bytes_api, "get_cstring_at"):
            format_bytes = bytes_api.get_cstring_at(format_ea)
        else:
            try:
                format_bytes = ida_bytes.get_strlit_contents(format_ea, -1, 0)
            except TypeError:
                format_bytes = ida_bytes.get_strlit_contents(format_ea, -1)
        if format_bytes is None:
            continue

        tokens = _format_token_labels(format_bytes)
        for slot, token in enumerate(tokens):
            if token is None:
                continue
            argument_index = 1 + slot
            if argument_index >= len(args):
                break
            argument = args[argument_index]
            # only x->member varargs carry naming evidence
            if getattr(argument, "op", None) != _ctype.memptr:
                continue
            member_offset = getattr(argument, "m", None)
            if not isinstance(member_offset, int) or member_offset < 0:
                continue
            base_expr = getattr(argument, "x", None)
            base_var = getattr(base_expr, "v", None)
            base_name = getattr(base_var, "name", None)
            if not base_name:
                base_name = getattr(base_expr, "name", None)
            if not base_name and base_var is not None:
                # live 9.4: var_ref_t exposes the idx, not the name
                var_index = getattr(base_var, "idx", None)
                if isinstance(var_index, int):
                    lvars = list(cfunc.get_lvars())
                    if 0 <= var_index < len(lvars):
                        base_name = lvars[var_index].name
            if not base_name:
                continue
            try:
                _resolve_scan_root(cfunc, var_name=base_name)
            except ForgeApiError:
                continue
            member = target.get_member_by_offset(member_offset)
            if member is None or not _is_synthesized_member_name(member.name):
                continue
            member.name = token
            renamed.append(token)
    _mark_dirty()
    return {"ok": True, "renamed": renamed}


@api(
    group="decompile",
    returns="dict",
    example='r = forge_api.rename_ea(0x140001000, "run_struct_sections"); r["name"]',
)
def rename_ea(ea: int, name: str) -> dict:
    """Rename a function or global at ``ea`` (naming-core verb).

    Eval review round 2, request #1: the one mandatory workflow verb with
    no forge path — 14 function renames plus the dispatch-table name all
    had to escape to raw ``ida_name``. Wraps ``ida_name.set_name`` with
    ``SN_NOCHECK`` (never silently auto-uniqueifies); a rename that IDA
    rejects fails loudly.

    Returns:
        ``{"ok": True, "ea": int, "name": str}`` or
        ``{"ok": False, "error": str}``.
    """
    _require_ida()
    database = _domain_database_or_none()
    names_api = getattr(database, "names", None) if database is not None else None
    domain_set_name = getattr(names_api, "set_name", None)
    if callable(domain_set_name):
        if domain_set_name(ea, name, 1):
            return {"ok": True, "ea": ea, "name": name}
        return {"ok": False, "error": f"could not set name {name!r} at {hex(ea)}"}
    import ida_name

    sno_check = getattr(ida_name, "SN_NOCHECK", 0)
    if ida_name.set_name(ea, name, sno_check):
        return {"ok": True, "ea": ea, "name": name}
    return {"ok": False, "error": f"could not set name {name!r} at {hex(ea)}"}


# --------------------------------------------------------------------------- #
# templated types
# --------------------------------------------------------------------------- #
def _templated_instance():
    if _state.templated is None:
        from forge.features.templated_types.templated_types import TemplatedTypes

        _state.templated = TemplatedTypes()
    return _state.templated


def _templated_args_with_suffixes(args: list) -> list:
    """Expand facade type args to the TOML format-token pairs.

    Each template parameter consumes TWO format tokens in the template
    table (the C type + a name suffix, per ``templated_types.toml``).
    The facade contract takes plain type arguments (``["u32"]``), so the
    suffix is synthesized from the type — otherwise every multi-arg key
    fails on the ``2N == len(args)`` guard (eval review round 2 §3.5).
    """
    import re as _re

    expanded = []
    for arg in args:
        expanded.append(arg)
        expanded.append(_re.sub(r"[^A-Za-z0-9_]", "_", str(arg)))
    return expanded


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

    ``args`` are the template type arguments; name suffixes are derived
    automatically (each template parameter also formats a suffix token).
    Returns ``None`` when the key is unknown or the argument count is
    wrong.

    Returns:
        ``{"name": str, "cdecl": str}`` or None.
    """
    _require_ida()
    result = _templated_instance().get_decl_str(
        key, _templated_args_with_suffixes(list(args))
    )
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
    expanded = _templated_args_with_suffixes(list(args))
    if template.get_decl_str(key, expanded) is None:
        return False
    template.set_type(key, expanded)
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
    returns="dict",
    example='r = forge_api.backfill_lumina(limit=20)',
)
def backfill_lumina(
    eas: list | None = None,
    *,
    pattern: str | None = None,
    limit: int | None = None,
) -> dict:
    """Apply Lumina metadata to functions (F.7).

    ``eas`` is an explicit list of function EAs; without it, every
    function in the database is a candidate. ``pattern`` filters by name
    (case-folded substring); ``limit`` caps the number of applications.
    Each target gets ``ida_hexrays.calc_func_metadata`` +
    ``apply_metadata``; per-target failures accumulate in ``errors``.
    When the build lacks the Lumina metadata API the verb says so
    explicitly.

    Returns:
        ``{"applied": int, "errors": [...]}``, or an error dict when the
        API is missing.
    """
    _require_ida()
    import ida_hexrays
    import ida_name

    calc = getattr(ida_hexrays, "calc_func_metadata", None)
    apply_meta = getattr(ida_hexrays, "apply_metadata", None)
    if not callable(calc) or not callable(apply_meta):
        return {
            "ok": False,
            "error": "lumina metadata API not available on this build",
        }

    if eas is None:
        try:
            import idautils

            functions = list(idautils.Functions())
        except Exception as exc:  # noqa: BLE001 — enumerate across builds
            return {"ok": False, "error": f"could not enumerate functions: {exc}"}
    else:
        functions = [int(ea) for ea in eas]

    if pattern:
        folded = pattern.casefold()
        functions = [
            ea
            for ea in functions
            if folded in (ida_name.get_name(ea) or "").casefold()
        ]
    if limit is not None and limit >= 0:
        functions = functions[:limit]

    applied = 0
    errors = []
    for ea in functions:
        try:
            result = calc(ea)
            if result is None or result == -1:
                errors.append(f"{hex(ea)}: metadata unavailable")
                continue
            apply_meta(ea)
            applied += 1
        except Exception as exc:  # noqa: BLE001 — one failure must not abort the batch
            errors.append(f"{hex(ea)}: {exc}")
    return {"applied": applied, "errors": errors}


@api(
    group="structures",
    returns="dict",
    example='r = forge_api.split_flags("Flags", 0x10, [("visible", 8), ("opts", 32)])',
)
def split_flags(
    structure: str | None = None, offset: int = 0, fields: list = ()
) -> dict:
    """Split one byte-aligned flag member into named fields (E.18).

    The enabled member at ``offset`` must exist and its size must equal
    ``sum(bits) / 8``; every width must be a multiple of 8 (bit-fields are
    NOT supported — a non-byte-aligned spec fails with
    ``"bit-fields not byte-aligned"``). The original member is removed
    and ``fields`` are added at ``offset``, ``offset + width/8``, ... as
    ``u8``/``u16``/``u32``/``u64`` per width (mirror of the create_field
    byte-aligned view).

    Returns:
        ``{"ok": True, "members": [member dicts], "bit_spec_ok": True}``
        or ``{"ok": False, "error": str}``.
    """
    target = _resolve_structure(structure)
    member = target.get_member_by_offset(offset)
    if member is None or not getattr(member, "enabled", True):
        return {"ok": False, "error": f"no enabled member at offset 0x{offset:x}"}
    fields = list(fields or [])
    for _name, bits in fields:
        if bits <= 0 or bits % 8 != 0:
            return {"ok": False, "error": "bit-fields not byte-aligned"}
    total_bytes = sum(bits for _name, bits in fields) // 8
    effective_size = (
        member.effective_size() if hasattr(member, "effective_size") else member.size
    )
    if effective_size != total_bytes:
        return {
            "ok": False,
            "error": (
                f"member at 0x{offset:x} is {effective_size} byte(s), "
                f"fields need {total_bytes}"
            ),
        }

    index_of_member = next(
        index for index, candidate in enumerate(target.members) if candidate is member
    )
    target.remove_members([index_of_member])
    created = []
    cursor = offset
    for name, bits in fields:
        width_bytes = bits // 8
        type_decl = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}.get(width_bytes)
        if type_decl is None:
            return {
                "ok": False,
                "error": f"unsupported field width {bits} bits",
            }
        created.append(add_member(target.name, cursor, type_decl, name=name))
        cursor += width_bytes
    _mark_dirty()
    return {"ok": True, "members": created, "bit_spec_ok": True}


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

    from forge.api.hexrays import decompile as _decompile
    from forge.features.swap_if.helper import inverse_if as _inverse_if
    from forge.features.swap_if.storage import set_inverted

    cfunc = _decompile(ea)
    if cfunc is None:
        return False

    # E6 (eval review 2026-08-13): the treeitems/eamap lookup silently
    # found nothing on the live 9.4 build (treeitems is empty and
    # closest-addr resolution missed the if), so inverse_if always
    # returned False. Walk the ctree instead and pick the ``cit_if`` with
    # an else branch nearest to ``insn_ea`` — the same visitor fallback
    # the I.25 scanners use.
    cif = None
    treeitems = getattr(cfunc, "treeitems", None)
    ci_if_op = getattr(ida_hexrays, "cit_if", None)
    if ci_if_op is not None:
        if treeitems:
            candidates = []
            for item in treeitems:
                # treeitems are ctree_item_t wrappers: unwrap .it, then
                # invoke to_specific_type (it is a method — ``or item``
                # would keep the bound method and never match).
                specific = getattr(item, "it", None) or item
                to_specific = getattr(specific, "to_specific_type", None)
                if callable(to_specific):
                    specific = to_specific()
                candidate = getattr(specific, "cif", None)
                if (
                    getattr(specific, "op", None) == ci_if_op
                    and candidate is not None
                    and getattr(candidate, "ielse", None) is not None
                ):
                    candidates.append(candidate)
            if candidates:
                cif = min(
                    candidates,
                    key=lambda c: abs(getattr(c, "ea", insn_ea) - insn_ea),
                )
        else:
            walker_cls = getattr(ida_hexrays, "ctree_visitor_t", None)
            if walker_cls is not None:

                class _IfWalker(walker_cls):
                    def __init__(self, target_ea):
                        try:
                            walker_cls.__init__(self, 0)
                        except TypeError:  # pragma: no cover — binding drift
                            walker_cls.__init__(self, None)
                        self.target_ea = target_ea
                        self.closest = None
                        self.closest_distance = None

                    def visit_insn(self, insn):
                        # statements are visited through visit_insn (O1
                        # finding: cit_return/visit_statement mismatch)
                        if getattr(insn, "op", None) != ci_if_op:
                            return 0
                        candidate = getattr(insn, "cif", None)
                        if candidate is None or getattr(
                            candidate, "ielse", None
                        ) is None:
                            return 0
                        distance = abs(
                            getattr(candidate, "ea", self.target_ea)
                            - self.target_ea
                        )
                        if (
                            self.closest is None
                            or distance < self.closest_distance
                        ):
                            self.closest = candidate
                            self.closest_distance = distance
                        return 0

                finder = _IfWalker(insn_ea)
                body = getattr(cfunc, "body", None)
                if body is not None:
                    from contextlib import suppress

                    with suppress(Exception):
                        finder.apply_to(body, None)
                cif = finder.closest
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


def _helper_allocation_row(callee_ea: int) -> dict | None:
    """Teleport target for helper-mediated allocations (R3.2 F4).

    When an allocation is invisible at the call site (the variable is
    assigned the result of a non-allocator helper, E.22), the REAL
    allocator may live inside the helper's body. Decompile the callee
    and resolve each ``return <var>`` through the same machinery the
    caller-side guesser uses (direct assignment match, then the ≤2-hop
    ``v = w`` alias chain, then a pointer-typed-return fallback row).
    Returns the first resolved HEAP row, else None. Live finding
    (9.4, 2026-08-15): re-rooting a whole ``GuessAllocationVisitor`` at
    the returned lvar yields nothing — its upward walk stops at the
    ``v = cast(w)`` chain — the alias-chain pass is the proven shape.
    """
    from forge.api.hexrays import ctype as _ct
    from forge.api.hexrays import decompile as _decompile
    from forge.api.hexrays import iter_returned_exprs
    from forge.features.guess_allocation.guess_allocation import GuessAllocationVisitor

    cfunc = _decompile(callee_ea)
    if cfunc is None:
        return None
    asg_op = getattr(_ct, "asg", None)
    finder = GuessAllocationVisitor.__new__(GuessAllocationVisitor)

    def _resolved(returned):
        alloc_obj = finder._find_allocator_assignment(cfunc, returned, asg_op)
        if alloc_obj is not None:
            return alloc_obj
        hop_source = returned
        for _hop in range(2):
            hop_target = finder._aliased_hop_target(cfunc, hop_source, asg_op)
            if hop_target is None:
                break
            alloc_obj = finder._find_allocator_assignment(
                cfunc, hop_target, asg_op
            )
            if alloc_obj is not None:
                return alloc_obj
            hop_source = hop_target
        return None

    for returned in iter_returned_exprs(cfunc):
        if returned is None:
            continue
        var_node = getattr(returned, "v", None)
        var_name = getattr(var_node, "name", None)
        alloc_obj = _resolved(returned)
        if alloc_obj is None and not finder._expr_type_is_pointer(returned):
            continue
        return {
            "ea": getattr(alloc_obj, "ea", None) if alloc_obj is not None else callee_ea,
            "var": var_name,
            "line": f"return value of {hex(callee_ea)}",
            "kind": "HEAP",
            "size_hint": getattr(alloc_obj, "size", None) if alloc_obj is not None else None,
            "callee": None,
        }
    return None


def _merge_member_rows(base: list[dict], extra: list[dict]) -> list[dict]:
    """Offset-union of two member-row sets (R3.2 F4).

    Same-offset duplicates keep the higher ``score``; ties keep
    ``extra``'s row (the callee's real init writes).
    """
    merged: dict[int, dict] = {}
    for row in base:
        merged.setdefault(row.get("offset"), copy.deepcopy(row))
    for row in extra:
        offset = row.get("offset")
        existing = merged.get(offset)
        if existing is None:
            merged[offset] = copy.deepcopy(row)
            continue
        rank_new = row.get("score")
        rank_old = existing.get("score")
        if (rank_new if rank_new is not None else 0) >= (rank_old if rank_old is not None else 0):
            merged[offset] = copy.deepcopy(row)
    return list(merged.values())


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

    R3.2 (F4): when the chosen allocation row is helper-mediated
    (``callee`` set — the allocator lives inside the helper body), the
    helper's body is ALSO scanned — the real allocator inside the callee
    (found via its first returned lvar) yields evidence the call site
    cannot show; both evidence sets are merged by byte offset.

    Returns:
        dict.
    """
    rows = guess_allocation(ea, var_name=var_name, var_index=var_index, item_ea=item_ea)
    allocation = next((row for row in rows if row["kind"] == "HEAP"), None)
    if allocation is None:
        # E.22: a helper-mediated row always carries kind HEAP with
        # callee set; when the direct HEAP row is missing but a callee
        # row exists, treat it as the allocation row.
        allocation = next((row for row in rows if row.get("callee")), None)
    if allocation is None:
        return {
            "ok": False,
            "error": f"no heap allocation found for variable in {hex(ea)}",
        }

    struct_name = name or _unique_structure_name("Allocation")
    create_structure(struct_name)
    # O1: heap buffers whose root variable is already typed as a struct
    # pointer (e.g. ``ArrayCell *cells``) scan as typed memptr chains and
    # collapse to offset-0 noise; a byte-level void * root recovers the
    # element lattice. Retype only when no explicit root_type was given,
    # and restore the analyst's type afterwards. Helper-mediated rows
    # (E.22: ``size_hint is None``) SKIP the void * retype — the helper's
    # return is already a typed pointer and the analyst-owned type stays.
    restore_type = None
    if root_type is None and allocation.get("size_hint") is not None:
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

    # R3.2 (F4): helper-mediated rows — teleport into the helper body:
    # scan the callee's returned-allocation root and compose both
    # evidence sets (offset union, higher score wins, ties to the callee).
    # Live 9.4 finding: helper rows can carry a folded size_hint (the
    # guesser resolves the calloc THROUGH the callee) — the gate is the
    # callee itself, not size_hint.
    if allocation.get("callee"):
        callee_row = _helper_allocation_row(allocation["callee"])
        if callee_row is not None:
            callee_scan = deep_scan(
                allocation["callee"],
                var_name=callee_row["var"],
                structure=struct_name,
                recurse_calls=True,
                root_type=root_type,
            )
            members = _merge_member_rows(
                members, callee_scan.get("members", [])
            )

    _refresh_scan_sites(_structures[struct_name])
    _mark_dirty()

    if vtable_addr is not None:
        to_vtable(struct_name, 0, vtable_addr)

    if commit:
        create_type(struct_name, overwrite=True)

    return {
        "ok": True,
        "allocation": copy.deepcopy(allocation),
        "structure": struct_name,
        "members": _collapse_stride_runs(members),
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
        the assignment went through a non-allocator helper (I.25). Helper-
        mediated rows (E.22) may carry ``size_hint=None`` with ``callee``
        set: the helper's return was pointer-typed but the allocator
        assignment inside it could not be proven statically — the scan
        then proceeds from the returned variable.
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
