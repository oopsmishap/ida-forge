from __future__ import annotations

import copy
from dataclasses import dataclass
from types import SimpleNamespace

import ida_hexrays
import idaapi

from forge.api import hexrays as hexrays_api
from forge.api.hexrays import ctype, decompile, is_legal_type
from forge.api.members import AbstractMember, materialize_linked_child_member_type
from forge.api.scan_object import (
    ObjectType,
    ScanObject,
    StructurePointerObject,
    StructureReferenceObject,
    _extract_offset_expression,
    _make_offset_scan_object,
 )
from forge.api.scanner import NewDeepScanVisitor
from forge.api.structure import Structure
from forge.util.logging import log_debug, log_info, log_warning





from .dialogs import ScannedVariableChooser



def _form_module():
    from importlib import import_module

    return import_module("forge.features.structure_builder.form")

@dataclass(frozen=True)
class ChildScanPlan:
    scan_object: ScanObject
    function_eas: tuple[int, ...]
    relation_kind: str
    root_object_name: str
    root_object_ea: int | None
    root_function_ea: int | None
    has_multiple_roots: bool
    scan_variables: tuple[ScanObject, ...] = ()

@dataclass(frozen=True)
class ChildScanInferenceSeed:
    function_ea: int
    evidence_ea: int
    scan_object: ScanObject
    parent_object: ScanObject
    caller_path: tuple[int, ...] = ()


@dataclass(frozen=True)
class ChildScanRootCandidate:
    function_ea: int
    evidence_ea: int
    root: ScanObject
    caller_path: tuple[int, ...] = ()

@dataclass(frozen=True)
class ChildScanResolvedMemberAnchor:
    evidence_expr: object
    member_expr: object
    parent_expr: object
    member_offset: int


def _get_argument_index(cfunc: ida_hexrays.cfunc_t, lvar_idx: int) -> int | None:
    getter = getattr(hexrays_api, "get_argument_index", None)
    if callable(getter):
        return getter(cfunc, lvar_idx)

    for idx, candidate in enumerate(getattr(cfunc, "argidx", ())):
        if candidate == lvar_idx:
            return idx
    return None


def _get_funcs_calling_address(ea: int) -> set[int]:
    getter = getattr(hexrays_api, "get_funcs_calling_address", None)
    if callable(getter):
        return getter(ea)
    return set()





class ChildScanMixin:
    @staticmethod
    def _warn_unimplemented(action_name: str) -> None:
        log_warning(f"{action_name} is not implemented yet.", True)

    @staticmethod
    def _prepare_scan_cfunc(func_ea: int):
        try:
            cfunc = decompile(func_ea)
        except ida_hexrays.DecompilationFailure:
            log_warning(f"Failed to decompile function at {hex(func_ea)}", True)
            return None
        if cfunc is None:
            log_warning(f"Failed to decompile function at {hex(func_ea)}", True)
            return None

        from forge.api.visitor import refresh_function_tree_postorder

        return refresh_function_tree_postorder(cfunc) or cfunc

    @staticmethod
    def _resolve_scan_variable_target(
        cfunc: ida_hexrays.cfunc_t, scan_variable: ScanObject
    ) -> ScanObject | None:
        target_ea = getattr(scan_variable, "ea", idaapi.BADADDR)
        if target_ea == idaapi.BADADDR:
            return None

        candidates = []
        for item in getattr(cfunc, "treeitems", []):
            if getattr(item, "ea", idaapi.BADADDR) == target_ea:
                candidates.append(item)

        eamap = getattr(cfunc, "eamap", None)
        if not candidates and eamap is not None:
            try:
                candidates.extend(list(eamap.get(target_ea, [])))
            except Exception:
                pass

        if not candidates:
            body = getattr(cfunc, "body", None)
            if body is not None and hasattr(body, "find_closest_addr"):
                try:
                    closest_item = body.find_closest_addr(target_ea)
                except Exception:
                    closest_item = None
                if closest_item is not None:
                    candidates.append(closest_item)

        for item in candidates:
            resolved = ScanObject.create(cfunc, item)
            if resolved is not None:
                return resolved

        return None

    @staticmethod
    def _normalize_scan_variable(scan_variable: ScanObject) -> ScanObject:
        if getattr(scan_variable, "id", None) is not None:
            return scan_variable

        proxy = SimpleNamespace(
            name=getattr(scan_variable, "name", None),
            ea=getattr(scan_variable, "ea", idaapi.BADADDR),
            func_ea=getattr(scan_variable, "func_ea", idaapi.BADADDR),
            tinfo=getattr(scan_variable, "tinfo", None),
            scan_root_ea=getattr(scan_variable, "scan_root_ea", idaapi.BADADDR),
            scan_root_function_ea=getattr(
                scan_variable, "scan_root_function_ea", idaapi.BADADDR
            ),
            scan_root_function_name=getattr(scan_variable, "scan_root_function_name", None),
        )

        legacy_lvar = getattr(scan_variable, "_ScannedVariableObject__lvar", None)
        if legacy_lvar is not None:
            proxy.id = ObjectType.local_variable
            proxy.lvar = legacy_lvar
            return proxy

        legacy_obj_ea = getattr(scan_variable, "_ScannedGlobalObject__obj_ea", None)
        if legacy_obj_ea is not None:
            proxy.id = ObjectType.global_object
            proxy.object_ea = legacy_obj_ea
            return proxy

        legacy_struct_name = getattr(scan_variable, "_ScannedStructureMemberObject__struct_name", None)
        legacy_struct_offset = getattr(
            scan_variable, "_ScannedStructureMemberObject__struct_offset", None
        )
        if legacy_struct_name is not None and legacy_struct_offset is not None:
            proxy.id = ObjectType.structure_reference
            proxy.struct_name = legacy_struct_name
            proxy.offset = legacy_struct_offset
            return proxy

        return proxy

    @staticmethod
    def _seed_scan_object_from_evidence(
        scan_object: ScanObject, evidence: ScanObject
    ) -> ScanObject | None:
        evidence_ea = getattr(evidence, "ea", idaapi.BADADDR)
        evidence_func_ea = getattr(evidence, "func_ea", idaapi.BADADDR)
        if evidence_ea == idaapi.BADADDR or evidence_func_ea == idaapi.BADADDR:
            return None

        seeded = copy.copy(scan_object)
        seeded.ea = evidence_ea
        seeded.func_ea = evidence_func_ea
        seeded.scan_root_ea = getattr(
            evidence, "scan_root_ea", getattr(seeded, "scan_root_ea", idaapi.BADADDR)
        )
        seeded.scan_root_function_ea = getattr(
            evidence,
            "scan_root_function_ea",
            getattr(seeded, "scan_root_function_ea", idaapi.BADADDR),
        )
        seeded.scan_root_function_name = getattr(
            evidence,
            "scan_root_function_name",
            getattr(seeded, "scan_root_function_name", None),
        )
        return seeded

    @staticmethod
    def _seed_evidence(scan_variable: ScanObject) -> ScanObject:
        seeded = copy.copy(scan_variable)
        root_ea = getattr(scan_variable, "scan_root_ea", idaapi.BADADDR)
        if root_ea != idaapi.BADADDR:
            seeded.ea = root_ea
        root_func_ea = getattr(scan_variable, "scan_root_function_ea", idaapi.BADADDR)
        if root_func_ea != idaapi.BADADDR:
            seeded.func_ea = root_func_ea
        return seeded


    @staticmethod
    def _coerce_ctree_expr(item):
        expr = getattr(item, "e", None)
        if expr is None:
            expr = getattr(item, "cexpr", None)
        if expr is not None and hasattr(expr, "op"):
            return expr
        if hasattr(item, "op"):
            return item
        return None

    @classmethod
    def _iter_items_near_ea(cls, cfunc: ida_hexrays.cfunc_t, target_ea: int) -> tuple[object, ...]:
        if target_ea == idaapi.BADADDR:
            return ()

        items: list[object] = []
        seen: set[int] = set()

        def add(item) -> None:
            if item is None:
                return
            item_id = id(item)
            if item_id in seen:
                return
            seen.add(item_id)
            items.append(item)

        for item in getattr(cfunc, "treeitems", []):
            if getattr(item, "ea", idaapi.BADADDR) == target_ea:
                add(item)

        eamap = getattr(cfunc, "eamap", None)
        if eamap is not None:
            try:
                for item in eamap.get(target_ea, []):
                    add(item)
            except Exception:
                pass

        body = getattr(cfunc, "body", None)
        if body is not None and hasattr(body, "find_closest_addr"):
            try:
                add(body.find_closest_addr(target_ea))
            except Exception:
                pass

        return tuple(items)

    @staticmethod
    def _expression_ea(cfunc: ida_hexrays.cfunc_t, expr) -> int:
        if expr is None:
            return idaapi.BADADDR

        expr_ea = getattr(expr, "ea", idaapi.BADADDR)
        if expr_ea != idaapi.BADADDR:
            return expr_ea

        try:
            return ScanObject.get_expression_address(cfunc, expr)
        except Exception:
            return idaapi.BADADDR

    @classmethod
    def _iter_assignment_expressions(cls, cfunc: ida_hexrays.cfunc_t):
        asg_op = getattr(ctype, "asg", None)
        if asg_op is None:
            return

        for item in getattr(cfunc, "treeitems", []):
            expr = cls._coerce_ctree_expr(item)
            if expr is not None and getattr(expr, "op", None) == asg_op:
                yield expr

    @classmethod
    def _iter_call_expressions(cls, cfunc: ida_hexrays.cfunc_t, callee_ea: int):
        call_op = getattr(ctype, "call", None)
        if call_op is None:
            return

        for item in getattr(cfunc, "treeitems", []):
            expr = cls._coerce_ctree_expr(item)
            if expr is None or getattr(expr, "op", None) != call_op:
                continue
            callee = getattr(getattr(expr, "x", None), "obj_ea", idaapi.BADADDR)
            if callee == callee_ea:
                yield expr

    @staticmethod
    def _parse_member_assignment_target(expr, offset: int = 0, scale: int = 1):
        if expr is None:
            return None

        cast_op = getattr(ctype, "cast", None)
        ref_op = getattr(ctype, "ref", None)
        memref_op = getattr(ctype, "memref", None)
        memptr_op = getattr(ctype, "memptr", None)
        ptr_op = getattr(ctype, "ptr", None)
        idx_op = getattr(ctype, "idx", None)
        add_op = getattr(ctype, "add", None)
        sub_op = getattr(ctype, "sub", None)
        num_op = getattr(ctype, "num", None)

        if expr.op in tuple(op for op in (cast_op, ref_op) if op is not None) and getattr(expr, "x", None) is not None:
            return ChildScanMixin._parse_member_assignment_target(expr.x, offset, scale)

        if expr.op in tuple(op for op in (memref_op, memptr_op) if op is not None) and getattr(expr, "x", None) is not None:
            return expr.x, offset + getattr(expr, "m", 0)

        if expr.op in tuple(op for op in (ptr_op, idx_op) if op is not None) and getattr(expr, "x", None) is not None:
            next_scale = scale
            expr_type = getattr(expr, "type", None)
            get_ptrarr_objsize = getattr(expr_type, "get_ptrarr_objsize", None)
            if callable(get_ptrarr_objsize):
                try:
                    next_scale = get_ptrarr_objsize() or scale
                except Exception:
                    next_scale = scale

            index_expr = getattr(expr, "y", None)
            if expr.op == idx_op and index_expr is not None and getattr(index_expr, "op", None) == num_op:
                return ChildScanMixin._parse_member_assignment_target(
                    expr.x, offset + index_expr.numval() * next_scale, next_scale
                )
            return ChildScanMixin._parse_member_assignment_target(expr.x, offset, next_scale)

        if expr.op in tuple(op for op in (add_op, sub_op) if op is not None):
            left = getattr(expr, "x", None)
            right = getattr(expr, "y", None)
            if left is not None and getattr(left, "op", None) == num_op and right is not None:
                delta = left.numval()
                if expr.op == sub_op:
                    delta = -delta
                return ChildScanMixin._parse_member_assignment_target(
                    right, offset + delta * scale, scale
                )
            if right is not None and getattr(right, "op", None) == num_op and left is not None:
                delta = right.numval()
                if expr.op == sub_op:
                    delta = -delta
                return ChildScanMixin._parse_member_assignment_target(
                    left, offset + delta * scale, scale
                )

        return expr, offset

    @classmethod
    def _member_expression_matches(cls, scan_object: ScanObject, expr) -> bool:
        matcher = getattr(scan_object, "is_target", None)
        if callable(matcher):
            try:
                if matcher(expr):
                    return True
            except Exception:
                pass

        parsed_target = cls._parse_member_assignment_target(expr)
        if parsed_target is None:
            return False

        _parent_expr, member_offset = parsed_target
        return member_offset == getattr(scan_object, "offset", None)

    @staticmethod
    def _iter_expr_children(expr):
        for attr in ("x", "y", "z"):
            child = getattr(expr, attr, None)
            if child is not None and hasattr(child, "op"):
                yield child

        for child in getattr(expr, "a", ()) or ():
            if child is not None and hasattr(child, "op"):
                yield child

    @classmethod
    def _iter_descendant_expressions(cls, expr):
        stack = list(cls._iter_expr_children(expr))
        seen: set[int] = set()
        while stack:
            current = stack.pop()
            current_id = id(current)
            if current_id in seen:
                continue
            seen.add(current_id)
            yield current
            stack.extend(cls._iter_expr_children(current))

    @classmethod
    def _iter_parent_expressions(cls, cfunc: ida_hexrays.cfunc_t, expr):
        body = getattr(cfunc, "body", None)
        if body is None or not hasattr(body, "find_parent_of"):
            return

        current = expr
        seen: set[int] = set()
        while current is not None:
            specific = getattr(current, "to_specific_type", current)
            try:
                parent_item = body.find_parent_of(specific)
            except Exception:
                break
            parent_expr = cls._coerce_ctree_expr(parent_item)
            if parent_expr is None or parent_expr is current or id(parent_expr) in seen:
                break
            seen.add(id(parent_expr))
            yield parent_expr
            current = parent_expr

    @classmethod
    def _iter_related_member_expressions(cls, cfunc: ida_hexrays.cfunc_t, expr):
        seen: set[int] = set()

        def emit(candidate):
            if candidate is None or not hasattr(candidate, "op"):
                return None
            candidate_id = id(candidate)
            if candidate_id in seen:
                return None
            seen.add(candidate_id)
            return candidate

        first = emit(expr)
        if first is not None:
            yield first

        for candidate in cls._iter_descendant_expressions(expr):
            emitted = emit(candidate)
            if emitted is not None:
                yield emitted

        for candidate in cls._iter_parent_expressions(cfunc, expr):
            emitted = emit(candidate)
            if emitted is not None:
                yield emitted

    @classmethod
    def _expand_matching_member_anchor(
        cls, cfunc: ida_hexrays.cfunc_t, expr, target_offset: int
    ):
        anchor_expr = expr
        for parent_expr in cls._iter_parent_expressions(cfunc, expr):
            parsed_target = cls._parse_member_assignment_target(parent_expr)
            if parsed_target is None:
                break
            _base_expr, member_offset = parsed_target
            if member_offset != target_offset:
                break
            anchor_expr = parent_expr
        return anchor_expr

    @classmethod
    def _resolve_member_anchor(
        cls, cfunc: ida_hexrays.cfunc_t, scan_object: ScanObject
    ) -> ChildScanResolvedMemberAnchor | None:
        target_ea = getattr(scan_object, "ea", idaapi.BADADDR)
        if target_ea == idaapi.BADADDR:
            return None

        target_offset = getattr(scan_object, "offset", None)
        if target_offset is None:
            return None

        for item in cls._iter_items_near_ea(cfunc, target_ea):
            evidence_expr = cls._coerce_ctree_expr(item)
            if evidence_expr is None:
                continue
            for candidate in cls._iter_related_member_expressions(cfunc, evidence_expr):
                parsed_target = cls._parse_member_assignment_target(candidate)
                if parsed_target is None:
                    continue
                _base_expr, member_offset = parsed_target
                if member_offset != target_offset:
                    continue
                anchor_expr = cls._expand_matching_member_anchor(
                    cfunc, candidate, target_offset
                )
                parsed_anchor = cls._parse_member_assignment_target(anchor_expr)
                if parsed_anchor is None:
                    continue
                parent_expr, anchor_offset = parsed_anchor
                return ChildScanResolvedMemberAnchor(
                    evidence_expr=evidence_expr,
                    member_expr=anchor_expr,
                    parent_expr=parent_expr,
                    member_offset=anchor_offset,
                )

        return None

    @classmethod
    def _create_scan_object_from_expr(
        cls, cfunc: ida_hexrays.cfunc_t, expr
    ) -> ScanObject | None:
        if expr is None:
            return None

        scan_object = ScanObject.create(cfunc, expr)
        if scan_object is None:
            base_expr, offset = _extract_offset_expression(expr)
            if base_expr is None:
                return None
            base_object = ScanObject.create(cfunc, base_expr)
            if base_object is None:
                return None
            scan_object = _make_offset_scan_object(base_object, offset)

        setattr(scan_object, "func_ea", getattr(cfunc, "entry_ea", idaapi.BADADDR))
        return scan_object

    @staticmethod
    def _scan_object_matches_expr(scan_object: ScanObject, expr) -> bool:
        matcher = getattr(scan_object, "is_target", None)
        if callable(matcher):
            try:
                return bool(matcher(expr))
            except Exception:
                return False

        obj_ea = getattr(scan_object, "ea", idaapi.BADADDR)
        expr_ea = getattr(expr, "ea", idaapi.BADADDR)
        return obj_ea != idaapi.BADADDR and expr_ea != idaapi.BADADDR and obj_ea == expr_ea

    @staticmethod
    def _resolve_parent_argument_index(
        cfunc: ida_hexrays.cfunc_t, parent_object: ScanObject
    ) -> int | None:
        if getattr(parent_object, "id", None) != ObjectType.local_variable:
            return None

        lvar = getattr(parent_object, "lvar", None)
        if lvar is not None and hasattr(lvar, "is_arg_var") and not lvar.is_arg_var:
            return None

        index = getattr(parent_object, "index", None)
        if index is None:
            return None

        return _get_argument_index(cfunc, index)

    @classmethod
    def _build_child_scan_inference_seed(
        cls,
        cfunc: ida_hexrays.cfunc_t,
        scan_object: ScanObject,
        *,
        parent_expr=None,
        evidence_ea: int | None = None,
        caller_path: tuple[int, ...] = (),
    ) -> ChildScanInferenceSeed | None:
        if parent_expr is None:
            resolved_anchor = cls._resolve_member_anchor(cfunc, scan_object)
            if resolved_anchor is None:
                return None
            parent_expr = resolved_anchor.parent_expr
            evidence_ea = cls._expression_ea(cfunc, resolved_anchor.member_expr)
            source_ea = cls._expression_ea(cfunc, resolved_anchor.evidence_expr)
            function_ea = getattr(cfunc, "entry_ea", idaapi.BADADDR)
            if resolved_anchor.member_expr is resolved_anchor.evidence_expr:
                log_debug(
                    "Child scan resolved parent-member anchor "
                    f"0x{resolved_anchor.member_offset:X} directly at {hex(evidence_ea)} in {hex(function_ea)}"
                )
            else:
                log_debug(
                    "Child scan recovered parent-member anchor "
                    f"0x{resolved_anchor.member_offset:X} at {hex(evidence_ea)} from descendant evidence {hex(source_ea)} in {hex(function_ea)}"
                )

        parent_object = cls._create_scan_object_from_expr(cfunc, parent_expr)
        if parent_object is None:
            log_debug(
                "Child scan failed to derive a parent object from "
                f"{hex(cls._expression_ea(cfunc, parent_expr))} in {hex(getattr(cfunc, 'entry_ea', idaapi.BADADDR))}"
            )
            return None

        seeded_scan_object = copy.copy(scan_object)
        seeded_scan_object.func_ea = getattr(cfunc, "entry_ea", idaapi.BADADDR)
        if evidence_ea is None or evidence_ea == idaapi.BADADDR:
            evidence_ea = cls._expression_ea(cfunc, parent_expr)
        seeded_scan_object.ea = evidence_ea

        return ChildScanInferenceSeed(
            function_ea=getattr(cfunc, "entry_ea", idaapi.BADADDR),
            evidence_ea=evidence_ea,
            scan_object=seeded_scan_object,
            parent_object=parent_object,
            caller_path=caller_path,
        )

    @classmethod
    def _infer_direct_child_roots(
        cls, cfunc: ida_hexrays.cfunc_t, seed: ChildScanInferenceSeed
    ) -> tuple[ChildScanRootCandidate, ...]:
        target_offset = getattr(seed.scan_object, "offset", None)
        if target_offset is None:
            return ()

        candidates: list[ChildScanRootCandidate] = []
        for assignment in cls._iter_assignment_expressions(cfunc):
            parsed_target = cls._parse_member_assignment_target(getattr(assignment, "x", None))
            if parsed_target is None:
                continue

            parent_expr, member_offset = parsed_target
            if member_offset != target_offset:
                continue
            if not cls._scan_object_matches_expr(seed.parent_object, parent_expr):
                continue

            root = cls._create_scan_object_from_expr(cfunc, getattr(assignment, "y", None))
            if root is None:
                continue

            candidates.append(
                ChildScanRootCandidate(
                    function_ea=getattr(cfunc, "entry_ea", idaapi.BADADDR),
                    evidence_ea=cls._expression_ea(cfunc, assignment),
                    root=root,
                    caller_path=seed.caller_path,
                )
            )

        if candidates:
            log_debug(
                "Child scan found "
                f"{len(candidates)} assignment-source root(s) for offset 0x{target_offset:X} in {hex(getattr(cfunc, 'entry_ea', idaapi.BADADDR))}"
            )

        return tuple(candidates)

    def _propagate_child_scan_seed(
        self,
        cfunc: ida_hexrays.cfunc_t,
        seed: ChildScanInferenceSeed,
    ) -> tuple[ChildScanInferenceSeed, ...]:
        arg_idx = self._resolve_parent_argument_index(cfunc, seed.parent_object)
        if arg_idx is None:
            return ()

        propagated: list[ChildScanInferenceSeed] = []
        for caller_ea in sorted(_get_funcs_calling_address(seed.function_ea)):
            caller_cfunc = self._prepare_scan_cfunc(caller_ea)
            if caller_cfunc is None:
                continue

            for call_expr in self._iter_call_expressions(caller_cfunc, seed.function_ea):
                args = getattr(call_expr, "a", ())
                if arg_idx < 0 or arg_idx >= len(args):
                    continue

                parent_expr = args[arg_idx]
                caller_seed = self._build_child_scan_inference_seed(
                    caller_cfunc,
                    seed.scan_object,
                    parent_expr=parent_expr,
                    evidence_ea=self._expression_ea(caller_cfunc, parent_expr),
                    caller_path=seed.caller_path + (seed.function_ea,),
                )
                if caller_seed is not None:
                    log_debug(
                        "Child scan propagated parent argument "
                        f"{arg_idx} from {hex(seed.function_ea)} to caller {hex(caller_ea)}"
                    )
                    propagated.append(caller_seed)

        return tuple(propagated)

    @staticmethod
    def _scan_object_key(scan_object: ScanObject) -> tuple[object, ...]:
        return (
            getattr(scan_object, "id", None),
            getattr(scan_object, "index", None),
            getattr(scan_object, "object_ea", None),
            getattr(scan_object, "struct_name", None),
            getattr(scan_object, "offset", None),
            getattr(scan_object, "arg_idx", None),
            getattr(scan_object, "func_ea", None),
            getattr(scan_object, "ea", None),
            getattr(scan_object, "name", None),
        )

    @classmethod
    def _child_scan_seed_key(cls, seed: ChildScanInferenceSeed) -> tuple[object, ...]:
        return (
            seed.function_ea,
            seed.evidence_ea,
            cls._scan_object_key(seed.scan_object),
            cls._scan_object_key(seed.parent_object),
        )

    @classmethod
    def _child_scan_root_key(
        cls, candidate: ChildScanRootCandidate
    ) -> tuple[object, ...]:
        return candidate.function_ea, cls._scan_object_key(candidate.root)

    def _infer_child_scan_roots(
        self, cfunc: ida_hexrays.cfunc_t, scan_object: ScanObject
    ) -> tuple[ScanObject, ...]:
        initial_seed = self._build_child_scan_inference_seed(cfunc, scan_object)
        if initial_seed is None:
            log_debug(
                "Child scan could not resolve a parent-member inference seed for "
                f"offset 0x{getattr(scan_object, 'offset', -1):X} at {hex(getattr(cfunc, 'entry_ea', idaapi.BADADDR))}"
            )
            return ()

        pending = [initial_seed]
        visited = {self._child_scan_seed_key(initial_seed)}
        candidates: list[ChildScanRootCandidate] = []

        while pending:
            seed = pending.pop(0)
            seed_cfunc = (
                cfunc
                if seed.function_ea == getattr(cfunc, "entry_ea", idaapi.BADADDR)
                else self._prepare_scan_cfunc(seed.function_ea)
            )
            if seed_cfunc is None:
                continue

            direct_roots = self._infer_direct_child_roots(seed_cfunc, seed)
            if direct_roots:
                candidates.extend(direct_roots)
                continue

            for caller_seed in self._propagate_child_scan_seed(seed_cfunc, seed):
                seed_key = self._child_scan_seed_key(caller_seed)
                if seed_key in visited:
                    continue
                visited.add(seed_key)
                pending.append(caller_seed)

        if not candidates:
            log_debug(
                "Child scan found no assignment-source roots for "
                f"{getattr(scan_object, 'name', '<unnamed>')} starting in {hex(getattr(cfunc, 'entry_ea', idaapi.BADADDR))}"
            )

        inferred_roots: list[ScanObject] = []
        seen_roots: set[tuple[object, ...]] = set()
        for candidate in candidates:
            root_key = self._child_scan_root_key(candidate)
            if root_key in seen_roots:
                continue
            seen_roots.add(root_key)
            inferred_roots.append(candidate.root)

        return tuple(inferred_roots)







    def _build_child_scan_plan(
        self,
        member: AbstractMember | None,
        *,
        show_warnings: bool = False,
    ) -> ChildScanPlan | None:
        if self.current_structure is None or member is None:
            return None

        def warn(message: str) -> None:
            if show_warnings:
                log_warning(message, True)

        scanned_variables = sorted(
            getattr(member, "scanned_variables", set()),
            key=lambda scan_variable: (
                getattr(scan_variable, "func_ea", idaapi.BADADDR),
                getattr(scan_variable, "ea", idaapi.BADADDR),
                str(getattr(scan_variable, "name", "")),
            ),
        )
        if not scanned_variables:
            warn("The selected row does not have scan evidence for child scanning yet.")
            return None

        seeded_scan_variables = tuple(
            self._seed_evidence(self._normalize_scan_variable(scan_variable))
            for scan_variable in scanned_variables
        )

        tinfo = getattr(member, "tinfo", None)
        if tinfo is None:
            warn("The selected row does not have enough type information to scan a child structure.")
            return None

        try:
            legal_type = is_legal_type(tinfo)
        except Exception:
            legal_type = False
        if not legal_type:
            warn("The selected row uses a type that cannot be scanned as a child structure.")
            return None

        if hasattr(tinfo, "is_ptr") and tinfo.is_ptr():
            relation_kind = "pointer"
            scan_object = StructurePointerObject(
                self.current_structure.created_type_name or self.current_structure.name,
                member.offset,
            )
        else:
            relation_kind = "embedded"
            scan_object = StructureReferenceObject(
                self.current_structure.created_type_name or self.current_structure.name,
                member.offset,
            )

        parent_struct_name = self.current_structure.created_type_name or self.current_structure.name
        if not parent_struct_name:
            parent_struct_names = sorted(
                {
                    candidate
                    for candidate in (
                        getattr(scan_variable, "_name", None)
                        for scan_variable in scanned_variables
                    )
                    if isinstance(candidate, str) and candidate
                }
            )
            if len(parent_struct_names) != 1:
                warn(
                    "Child scan currently requires a typed parent structure or unambiguous member evidence.",
                )
                return None
            parent_struct_name = parent_struct_names[0]
            scan_object = type(scan_object)(parent_struct_name, member.offset)

        function_eas = tuple(
            sorted(
                {
                    getattr(scan_variable, "func_ea", idaapi.BADADDR)
                    for scan_variable in seeded_scan_variables
                    if getattr(scan_variable, "func_ea", idaapi.BADADDR) != idaapi.BADADDR
                }
            )
        )
        if not function_eas:
            warn("The selected row does not have any decompilable function evidence for child scanning.")
            return None

        scan_object.name = member.name
        scan_object.tinfo = tinfo
        representative = seeded_scan_variables[0]
        expression_eas = {
            getattr(scan_variable, "ea", idaapi.BADADDR)
            for scan_variable in seeded_scan_variables
            if getattr(scan_variable, "ea", idaapi.BADADDR) != idaapi.BADADDR
        }
        member_name = member.name or f"member_{member.offset:X}"
        root_object_ea = getattr(representative, "ea", idaapi.BADADDR)
        root_function_ea = getattr(representative, "func_ea", idaapi.BADADDR)
        return ChildScanPlan(
            scan_object=scan_object,
            function_eas=function_eas,
            relation_kind=relation_kind,
            root_object_name=f"{self.current_structure.name}.{member_name}",
            root_object_ea=root_object_ea if root_object_ea != idaapi.BADADDR else None,
            root_function_ea=(
                root_function_ea if root_function_ea != idaapi.BADADDR else None
            ),
            has_multiple_roots=len(function_eas) > 1 or len(expression_eas) > 1,
            scan_variables=seeded_scan_variables,
        )



    def _create_or_get_child_structure(
        self,
        member: AbstractMember,
    ) -> tuple[Structure | None, bool]:
        linked_child_name = getattr(member, "linked_child_structure_name", None)
        if linked_child_name:
            existing_child = self.structures.get(linked_child_name)
            if existing_child is not None:
                return existing_child, False
            return self.create_structure(linked_child_name), True
        return self.create_structure(""), True

    def _execute_child_scan_plan(
        self,
        child_structure: Structure,
        plan: ChildScanPlan,
    ) -> bool:
        scanned_any = False
        visitor_cls = getattr(_form_module(), "NewDeepScanVisitor", NewDeepScanVisitor)
        evidence_by_function: dict[int, list[ScanObject]] = {}
        for scan_variable in getattr(plan, "scan_variables", ()) or ():
            normalized = self._normalize_scan_variable(scan_variable)
            func_ea = getattr(normalized, "func_ea", idaapi.BADADDR)
            if func_ea == idaapi.BADADDR:
                continue
            evidence_by_function.setdefault(func_ea, []).append(normalized)

        for func_ea in plan.function_eas:
            cfunc = self._prepare_scan_cfunc(func_ea)
            if cfunc is None:
                continue

            scan_variables = evidence_by_function.get(func_ea) or [plan.scan_object]
            for scan_variable in scan_variables:
                seeded_scan_object = self._seed_scan_object_from_evidence(
                    plan.scan_object, scan_variable
                )
                if seeded_scan_object is None:
                    log_warning(
                        f"Skipping child scan evidence without a usable location in {hex(func_ea)}",
                        True,
                    )
                    continue

                inferred_roots = self._infer_child_scan_roots(cfunc, seeded_scan_object)
                if inferred_roots:
                    log_info(
                        "Child scan inferred "
                        f"{len(inferred_roots)} assignment root(s) for "
                        f"{getattr(seeded_scan_object, 'name', '<unnamed>')} in {hex(func_ea)}"
                    )
                    roots = inferred_roots
                else:
                    log_warning(
                        "Child scan fell back to seeded member evidence for "
                        f"{getattr(seeded_scan_object, 'name', '<unnamed>')} in {hex(func_ea)}"
                    )
                    roots = (seeded_scan_object,)

                for root in roots:
                    root_cfunc = self._prepare_scan_cfunc(
                        getattr(root, "func_ea", idaapi.BADADDR)
                    ) or cfunc
                    visitor = visitor_cls(
                        root_cfunc,
                        child_structure.main_offset,
                        root,
                        child_structure,
                        recurse_calls=True,
                    )
                    visitor.process()
                    scanned_any = True

        return scanned_any




    @staticmethod
    def _materialize_child_member_type(
        member: AbstractMember,
        child_structure: Structure,
        relation_kind: str,
    ) -> None:
        child_type_name = child_structure.created_type_name
        if not child_type_name:
            log_debug(
                "Deferring child member type materialization until "
                f"{child_structure.name} has a created type name"
            )
            return

        if not materialize_linked_child_member_type(
            member, child_type_name, relation_kind
        ):
            log_warning(
                "Failed to materialize linked child member type "
                f"{child_type_name} for {member.name or f'member_{member.offset:X}'}",
                True,
            )

    @staticmethod
    def _child_scan_origin(member: AbstractMember) -> int:
        return getattr(member, "origin", 0) + member.offset

    @staticmethod
    def _link_child_structure(
        parent_structure: Structure,
        child_structure: Structure,
        member: AbstractMember,
        relation_kind: str,
    ) -> None:
        parent_member_name = member.name or f"member_{member.offset:X}"
        relationship = parent_structure.add_child_relationship(
            child_structure_name=child_structure.name,
            parent_member_offset=member.offset,
            parent_member_name=parent_member_name,
            relation_kind=relation_kind,
        )
        child_structure.add_parent_relationship(relationship)
        member.linked_child_structure_name = child_structure.name
        member.child_relation_kind = relation_kind
        ChildScanMixin._materialize_child_member_type(member, child_structure, relation_kind)

    @staticmethod
    def _set_child_scan_provenance(
        child_structure: Structure,
        member: AbstractMember,
        plan: ChildScanPlan,
    ) -> None:
        child_structure.set_provenance(
            kind="child_scan",
            root_object_name=plan.root_object_name,
            root_object_ea=plan.root_object_ea,
            root_function_ea=plan.root_function_ea,
            source_member_offset=member.offset,
            has_multiple_roots=plan.has_multiple_roots,
        )

    def scan_child_structure(self):
        if self.current_structure is None:
            log_warning("No structure selected!", True)
            return

        selected_member = self.get_selected_member()
        if selected_member is None:
            log_warning("No structure row selected!", True)
            return

        parent_structure = self.current_structure
        plan = self._build_child_scan_plan(selected_member, show_warnings=True)
        if plan is None:
            return

        child_structure, created_now = self._create_or_get_child_structure(selected_member)
        if child_structure is None:
            return

        child_origin = self._child_scan_origin(selected_member)
        if child_structure.main_offset != child_origin:
            child_structure.set_main_offset(child_origin)

        existing_member_count = len(child_structure.members)
        scanned_any = self._execute_child_scan_plan(child_structure, plan)

        scan_produced_results = len(child_structure.members) > existing_member_count
        if not scanned_any or (created_now and not scan_produced_results):
            if created_now and child_structure.name in self.structures:
                del self.structures[child_structure.name]
            self.current_structure = parent_structure
            if self.ui is not None:
                self.reload_structure_list()
                self._select_structure_in_tree(parent_structure.name)
            self.update_action_states()
            log_warning(
                "Unable to derive child structure scan results from the selected row.",
                True,
            )
            return

        self._link_child_structure(
            parent_structure,
            child_structure,
            selected_member,
            plan.relation_kind,
        )
        if created_now or (
            child_structure.provenance.kind == "manual" and existing_member_count == 0
        ):
            self._set_child_scan_provenance(
                child_structure,
                selected_member,
                plan,
            )

        self.current_structure = child_structure
        if self.ui is not None:
            self.reload_structure_list()
            if self._select_structure_in_tree(child_structure.name):
                self.ui.tree_structures.setFocus()
        self.update_action_states()

    def show_scanned_variables(self):
        if self.current_structure is None:
            return

        selected_members = self.get_selected_members()
        if selected_members:
            scanned_variables = {
                scan_object
                for member in selected_members
                for scan_object in member.scanned_variables
            }
        else:
            scanned_variables = set(
                self.current_structure.get_unique_scanned_variables(
                    self.current_structure.main_offset
                )
            )

        if not scanned_variables:
            log_warning("No scanned variables available for the current selection.", True)
            return

        chooser = ScannedVariableChooser(
            sorted(
                scanned_variables,
                key=lambda scan_object: (
                    getattr(scan_object, "func_ea", idaapi.BADADDR),
                    getattr(scan_object, "ea", idaapi.BADADDR),
                    scan_object.name,
                ),
            )
        )
        chooser.Show()
