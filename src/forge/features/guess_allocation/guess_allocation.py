from typing import ClassVar

import ida_hexrays
import ida_idaapi
import ida_kernwin

from forge.api.hexrays import ctype, find_expr_address, to_function_offset_str
from forge.api.scan_object import MemoryAllocationObject, ObjectType, ScanObject
from forge.api.ui_actions import HexRaysPopupAction, register_action
from forge.api.visitor import RecursiveUpwardsObjectVisitor


def _make_allocation_chooser(items):
    """Build the allocations chooser for a scan's collected rows.

    ``forge.api.ui`` pulls in Qt, which only exists in GUI IDA sessions, so it
    is imported lazily: the headless ``forge_api`` facade runs the visitor with
    ``interactive=False`` and never constructs the chooser at all.
    """
    from forge.api.ui import Choose

    class StructureAllocationChoose(Choose):
        title = "Possible structure allocations"
        cols: ClassVar[list] = [["Function", 30], ["Variable", 10], ["Line", 50], ["Type", 10]]

        def __init__(self, items):
            super().__init__(items)

        def OnSelectLine(self, n):
            ida_kernwin.jumpto(self.items[n][0])

        def OnGetLine(self, n):
            func_ea, var, line, alloc_type = self.items[n][:4]
            return [to_function_offset_str(func_ea), var, line, alloc_type]

    return StructureAllocationChoose(items)


class GuessAllocationVisitor(RecursiveUpwardsObjectVisitor):
    def __init__(self, cfunc, obj: ScanObject, *, interactive: bool = True):
        super().__init__(cfunc, obj, skip_until_object=True)
        self._data = []
        self._interactive = interactive

    def _matches_object(self, obj: ScanObject, cexpr) -> bool:
        base_matcher = getattr(super(), "_matches_object", None)
        if callable(base_matcher):
            return base_matcher(obj, cexpr)

        target_matches = getattr(obj, "is_target", None)
        if callable(target_matches):
            return target_matches(cexpr)

        obj_ea = getattr(obj, "ea", ida_idaapi.BADADDR)
        if obj_ea == ida_idaapi.BADADDR:
            return False

        return obj_ea == find_expr_address(cexpr, getattr(self, "parents", []))
    
    def _discover_allocation_via_callee(self, call_expr, obj):
        """Cross-function allocation discovery (I.25, E.22/I.25 alias chain).

        ``parent.y = AllocHelper(args)`` where ``AllocHelper`` is not itself an
        allocator: decompile the callee one level (hard cap, never recursed)
        and look for a ``return X`` where ``X`` is a local assigned from a
        real allocator call. First hit wins; any failure degrades to no row.
        External (IAT) callees have no body — skipped.

        When the direct return match fails, an **alias-chain** pass follows
        the return value back through up to two plain ``v = w`` var moves
        (``return v`` where ``v = w; w = alloc(...)``), still looking for a
        real allocator assignment. When even that finds nothing but the
        return value is pointer-typed, a HEAP row with ``size_hint=None``
        is still emitted — the caller scans from the returned variable
        (documented limitation: the allocation itself is not statically
        provable through the helper, so the size stays unknown).

        Returns a ``[ea, var, line, kind, size_hint, callee_ea]`` row or
        ``None``.
        """
        import ida_funcs

        from forge.api.hexrays import decompile as _decompile

        try:
            callee_ea = getattr(getattr(call_expr, "x", None), "obj_ea", None)
            if callee_ea is None or callee_ea == ida_idaapi.BADADDR:
                return None
            function = ida_funcs.get_func(callee_ea)
            if function is None:
                # IAT slot / external import — no body to decompile (E.22
                # mandate); the slot itself is not an allocation provider.
                return None
            cfunc = _decompile(getattr(function, "start_ea", callee_ea))
            if cfunc is None:
                return None

            # match the ctree's return expressions to the var nodes they
            # return, then find the defining allocation assignment
            asg_op = getattr(ctype, "asg", None)
            for returned in self._iter_returned_exprs(cfunc):
                if returned is None:
                    continue
                alloc_obj = self._find_allocator_assignment(cfunc, returned, asg_op)
                if alloc_obj is not None:
                    return [
                        alloc_obj.ea,
                        obj.name,
                        self.get_line(),
                        "HEAP",
                        alloc_obj.size,
                        callee_ea,
                    ]

            # E.22: alias-chain pass — `return v` where the allocator result
            # reaches `v` through ≤2 `v = w` var moves.
            for returned in self._iter_returned_exprs(cfunc):
                if returned is None:
                    continue
                hop_source = returned
                for _hop in range(2):
                    hop_target = self._aliased_hop_target(cfunc, hop_source, asg_op)
                    if hop_target is None:
                        break
                    alloc_obj = self._find_allocator_assignment(
                        cfunc, hop_target, asg_op
                    )
                    if alloc_obj is not None:
                        return [
                            alloc_obj.ea,
                            obj.name,
                            self.get_line(),
                            "HEAP",
                            alloc_obj.size,
                            callee_ea,
                        ]
                    hop_source = hop_target

            # E.22 fallback: pointer-typed return with no provable allocator —
            # emit a HEAP row carrying `callee` + size_hint None so
            # scan_from_allocation still scans from the returned variable.
            for returned in self._iter_returned_exprs(cfunc):
                if returned is None:
                    continue
                if self._expr_type_is_pointer(returned):
                    return [
                        find_expr_address(call_expr, self.parents),
                        obj.name,
                        self.get_line(),
                        "HEAP",
                        None,
                        callee_ea,
                    ]
        except Exception:  # noqa: BLE001 — cross-function recon is best-effort
            return None
        return None

    @staticmethod
    def _as_single_var(expr):
        """The var node under cast-peel, or None when ``expr`` is not a var."""
        while (
            getattr(expr, "op", None) == getattr(ctype, "cast", None)
            and getattr(expr, "x", None) is not None
        ):
            expr = expr.x
        if getattr(expr, "op", None) == getattr(ctype, "var", None):
            return expr
        return None

    @staticmethod
    def _expr_type_is_pointer(expr) -> bool:
        """True when the expression (or its var) carries a pointer type."""
        tinfo = getattr(expr, "type", None)
        if tinfo is None:
            tinfo = getattr(getattr(expr, "v", None), "type", None)
        is_ptr = getattr(tinfo, "is_ptr", None)
        return callable(is_ptr) and bool(is_ptr())

    def _aliased_hop_target(self, cfunc, source, asg_op):
        """The var assigned THROUGH ``source``: ``v = w`` with ``v`` the
        same lvar as ``source`` — returns the `w` node (single var after
        cast-peel), or None. Same identity matching as
        :meth:`_find_allocator_assignment` (lvar index, EA fallback)."""
        source_idx = getattr(getattr(source, "v", None), "idx", None)
        source_ea = getattr(source, "ea", None)
        for target, rhs in self._iter_assignment_sites(cfunc):
            if target is None:
                continue
            target_idx = getattr(getattr(target, "v", None), "idx", None)
            if target_idx is not None and source_idx is not None:
                if target_idx != source_idx:
                    continue
            elif source_ea not in (None, 0) and getattr(target, "ea", None) != source_ea:
                continue
            rhs_var = self._as_single_var(rhs)
            if rhs_var is not None:
                return rhs_var
        return None

    @staticmethod
    def _iter_returned_exprs(cfunc):
        """Yield the expression of every ``return <expr>`` statement.

        Same treeitems → ctree-visitor fallback as
        :meth:`_iter_assignment_sites` (treeitems is empty on the live
        9.4 build, O1 finding 2026-08-13).
        """
        # Returns are statements — the forge enum spells it ``cit_return``
        # (80 on this build; older SDK docs say 78 — never hardcode, O1
        # live finding 2026-08-13).
        ret_op = (
            getattr(ctype, "ret", None)
            or getattr(ctype, "cit_ret", None)
            or getattr(ctype, "cit_return", None)
        )
        treeitems = getattr(cfunc, "treeitems", None)
        if treeitems:
            for item in treeitems:
                # to_specific_type is a method; ``or item`` would keep the
                # bound method and never match (same trap as inverse_if E6).
                specific = getattr(item, "it", None) or item
                to_specific = getattr(specific, "to_specific_type", None)
                if callable(to_specific):
                    specific = to_specific()
                if ret_op is not None and getattr(specific, "op", None) == ret_op:
                    yield getattr(specific, "x", None)
            return

        walker_cls = getattr(ida_hexrays, "ctree_visitor_t", None)
        if walker_cls is None or ret_op is None:
            return

        class _ReturnWalker(walker_cls):
            def __init__(self):
                try:
                    walker_cls.__init__(self, 0)
                except TypeError:
                    walker_cls.__init__(self, None)  # pragma: no cover — binding drift
                self.returned = []

            def visit_insn(self, insn):
                # the binding hook for statements is visit_insn, not
                # visit_statement (O1 live finding, 2026-08-13)
                if getattr(insn, "op", None) == ret_op:
                    self.returned.append(getattr(insn, "x", None))
                return 0

        walker = _ReturnWalker()
        body = getattr(cfunc, "body", None)
        if body is not None:
            try:
                walker.apply_to(body, None)
            except Exception:  # noqa: BLE001 — walk is best-effort
                return
        yield from walker.returned

    def _find_allocator_assignment(self, cfunc, returned, asg_op):
        """The ``var = allocator(...)`` assignment feeding the returned value.

        Matches the returned expression to an assignment target by **lvar
        index** (``v.idx``), falling back to expression EAs — the EA of the
        ``return node`` use differs from the EA of ``node = calloc(...)``
        (O1 live finding, 2026-08-13), so EA-only matching misses the common
        define-then-return shape. First hit wins.
        """
        returned_idx = getattr(getattr(returned, "v", None), "idx", None)
        returned_ea = getattr(returned, "ea", None)
        # `return (T *)root;` surfaces a cast node (v=None, ea=0) — peel so
        # the var identity under the cast drives the match (O1 live, 2026-08-13).
        while (
            getattr(returned, "op", None) == getattr(ctype, "cast", None)
            and getattr(returned, "x", None) is not None
        ):
            returned = returned.x
            returned_idx = getattr(getattr(returned, "v", None), "idx", None)
            returned_ea = getattr(returned, "ea", None) or returned_ea
        for target, rhs in self._iter_assignment_sites(cfunc):
            if target is None:
                continue
            target_idx = getattr(getattr(target, "v", None), "idx", None)
            if target_idx is not None and returned_idx is not None:
                if target_idx != returned_idx:
                    continue
            elif returned_ea not in (None, 0) and getattr(target, "ea", None) != returned_ea:
                continue
            alloc_obj = MemoryAllocationObject.create(cfunc, rhs)
            if alloc_obj is not None:
                return alloc_obj
        return None

    @staticmethod
    def _iter_assignment_sites(cfunc):
        """Yield ``(target, rhs)`` for every assignment expression.

        Prefers ``cfunc.treeitems``; when that is empty — which is the live
        case on this build (O1 finding: freshly decompiled functions report
        no tree items) — falls back to a ctree visitor walk over the body.
        """
        asg_op = getattr(ctype, "asg", None)
        treeitems = getattr(cfunc, "treeitems", None)
        if treeitems:
            for item in treeitems:
                specific = getattr(item, "it", None) or item
                to_specific = getattr(specific, "to_specific_type", None)
                if callable(to_specific):
                    specific = to_specific()
                if asg_op is not None and getattr(specific, "op", None) == asg_op:
                    yield getattr(specific, "x", None), getattr(specific, "y", None)
            return

        walker_cls = getattr(ida_hexrays, "ctree_visitor_t", None)
        if walker_cls is None or asg_op is None:
            return

        class _AssignmentWalker(walker_cls):
            def __init__(self):
                try:
                    walker_cls.__init__(self, 0)
                except TypeError:
                    walker_cls.__init__(self, None)  # pragma: no cover — binding drift
                self.sites = []

            def visit_expr(self, expr):
                if getattr(expr, "op", None) == asg_op:
                    self.sites.append((getattr(expr, "x", None), getattr(expr, "y", None)))
                return 0

        walker = _AssignmentWalker()
        body = getattr(cfunc, "body", None)
        if body is not None:
            try:
                walker.apply_to(body, None)
            except Exception:  # noqa: BLE001 — walk is best-effort
                return
        yield from walker.sites

    def _manipulate(self, cexpr, obj: ScanObject):
        if obj.id == ObjectType.local_variable:
            parent = self.parent_expr()
            if parent is None:
                return
            if parent.op == ctype.asg:
                alloc_obj = MemoryAllocationObject.create(self._cfunc, parent.y)
                if alloc_obj:
                    self._data.append(
                        [alloc_obj.ea, obj.name, self.get_line(), "HEAP", alloc_obj.size, None]
                    )
                else:
                    callee_row = self._discover_allocation_via_callee(parent.y, obj)
                    if callee_row is not None:
                        self._data.append(callee_row)
            elif parent.op == ctype.ref:
                self._data.append(
                    [
                        find_expr_address(cexpr, self.parents),
                        obj.name,
                        self.get_line(),
                        "STACK",
                        None,
                        None,
                    ]
                )
        elif obj.id == ObjectType.global_object:
            self._data.append(
                [
                    find_expr_address(cexpr, self.parents),
                    obj.name,
                    self.get_line(),
                    "GLOBAL",
                    None,
                    None,
                ]
            )

    def _finish(self):
        if self._interactive:
            chooser = _make_allocation_chooser(self._data)
            chooser.Show(True)


@register_action
class GuessAllocation(HexRaysPopupAction):
    name = "GuessAllocation"
    description = "Guess allocation"
    hotkey = ""

    def __init__(self):
        super().__init__()
    def check(self, hx_view):
        if hx_view.item.citype != ida_hexrays.VDI_EXPR:
            return False
        return ScanObject.create(hx_view.cfunc, hx_view.item) is not None

    def activate(self, ctx):
        hx_view = ida_hexrays.get_widget_vdui(ctx.widget)
        obj = ScanObject.create(hx_view.cfunc, hx_view.item)
        if obj:
            visitor = GuessAllocationVisitor(hx_view.cfunc, obj)
            visitor.process()
