"""Ctree statement transforms — the swap-if DSL core (F.6).

Split out of ``forge/features/swap_if/helper.py`` (eval review round 2):
the ctree statement walk with a WINDOW of the visited statements is the
base other statement transforms build on. The public contracts:

- :class:`CtreeStatementVisitor` — a ctree visitor whose ``window``
  tracks the statements already visited; override ``handle_statement``.
- :class:`StatementTransform` — the transform contract: hold a cfunc,
  implement ``transform() -> bool``. This is the DSL base for new
  feature classes: subclass it, override :meth:`transform`, compose
  visitors from :class:`CtreeStatementVisitor`.

The swap-if feature's facade ``inverse_if`` keeps its own API and
behavior (``forge.features.swap_if.helper``); :class:`SilentIfSwapper`
(the Hex-Rays hook that re-applies inverted ifs after re-decompilation)
moved here so the feature's hook logic and the shared transform DSL live
together. :class:`IfInverter` is a ``StatementTransform`` wrapper around
the same inversion, for feature code that wants the object contract.
"""

import contextlib

import ida_hexrays

from forge.api.hexrays import ctype
from forge.api.hooks import HexRaysHook
from forge.util.logging import log_debug

__all__ = ["CtreeStatementVisitor", "IfInverter", "SilentIfSwapper", "StatementTransform"]


class CtreeStatementVisitor(ida_hexrays.ctree_visitor_t):
    """A ctree visitor that keeps a WINDOW of the statements it visits.

    ``visit_insn`` pushes every statement into ``self.window`` (cap 64)
    and dispatches to :meth:`handle_statement`; subclasses override the
    latter to react to statements near ``ea``. The window makes
    "nearest statement to X" transforms trivial: search
    ``reversed(self.window)``.
    """

    window_cap = 64

    def __init__(self, ea: int = -1):
        try:
            ida_hexrays.ctree_visitor_t.__init__(self, 0)
        except TypeError:  # pragma: no cover — binding drift
            ida_hexrays.ctree_visitor_t.__init__(self, None)
        self.target_ea = ea
        self.window: list = []

    def visit_insn(self, insn):
        # statements arrive through visit_insn (O1 live finding:
        # cit_return/visit_statement mismatch)
        if len(self.window) >= self.window_cap:
            del self.window[: self.window_cap // 2]
        self.window.append(insn)
        self.handle_statement(insn)
        return 0

    def handle_statement(self, insn):
        """Hook for subclasses; the traversal decision stays in
        ``visit_insn``."""


class StatementTransform:
    """Transform contract: ``transform() -> bool`` (F.6).

    The DSL base for ctree features: construct with the decompiled
    cfunc (or None for pure helpers), run :meth:`transform`, get a bool
    back — True when the tree was changed and IDA should re-decompile.
    Subclasses implement statement walks with
    :class:`CtreeStatementVisitor` windows.
    """

    def __init__(self, cfunc):
        self.cfunc = cfunc

    def transform(self) -> bool:
        raise NotImplementedError


class IfInverter(StatementTransform):
    """``StatementTransform`` exposing one if-inversion (F.6).

    Locates the ``cit_if`` statement nearest to ``insn_ea`` that has an
    else branch and inverts it (condition negated, then/else swapped) —
    the same semantics as the facade ``inverse_if``, exposed through the
    transform DSL so feature classes can compose it.
    """

    def __init__(self, cfunc, insn_ea: int):
        super().__init__(cfunc)
        self.insn_ea = insn_ea

    @staticmethod
    def _nearest_if_with_else(cfunc, insn_ea: int):
        """The cit_if with an else branch nearest to ``insn_ea``, or None."""
        ci_if_op = getattr(
            ida_hexrays, "cit_if", None
        ) or getattr(ctype, "cit_if", None)
        candidates = []
        treeitems = getattr(cfunc, "treeitems", None)
        if treeitems:
            for item in treeitems:
                specific = getattr(item, "it", None) or item
                to_specific = getattr(specific, "to_specific_type", None)
                if callable(to_specific):
                    specific = to_specific()
                candidate = getattr(specific, "cif", None)
                if (
                    ci_if_op is not None
                    and getattr(specific, "op", None) == ci_if_op
                    and candidate is not None
                    and getattr(candidate, "ielse", None) is not None
                ):
                    candidates.append(candidate)
        else:
            walker_cls = getattr(ida_hexrays, "ctree_visitor_t", None)
            if walker_cls is not None:
                found = []

                class _IfFinder(walker_cls):
                    def __init__(self):
                        try:
                            walker_cls.__init__(self, 0)
                        except TypeError:  # pragma: no cover — binding drift
                            walker_cls.__init__(self, None)

                    def visit_insn(self, insn):
                        if getattr(insn, "op", None) == ci_if_op:
                            cif = getattr(insn, "cif", None)
                            if cif is not None and getattr(cif, "ielse", None) is not None:
                                found.append(cif)
                        return 0

                finder = _IfFinder()
                body = getattr(cfunc, "body", None)
                if body is not None:
                    with contextlib.suppress(Exception):
                        finder.apply_to(body, None)
                candidates = found
        if not candidates:
            return None
        return min(
            candidates,
            key=lambda c: abs(getattr(c, "ea", insn_ea) - insn_ea),
        )

    def transform(self) -> bool:
        cif = self._nearest_if_with_else(self.cfunc, self.insn_ea)
        if cif is None:
            return False
        from forge.features.swap_if.helper import inverse_if

        inverse_if(cif)
        return True


class SilentIfSwapper(HexRaysHook):
    """Re-apply inverted if conditions after each re-decompilation.

    Moved from ``forge.features.swap_if.actions`` (F.6) so the hook logic
    lives with the transform DSL; registration stays in the swap-if
    feature module, as before.
    """

    name = "SilentIfSwapper"

    def __init__(self):
        super().__init__()

    def maturity(self, *args):
        import ida_nalt

        from forge.features.swap_if.storage import get_inverted, has_inverted
        from forge.features.swap_if.visitor import (
            SpaghettiVisitor,
            SwapThenElseVisitor,
        )

        cfunc, level_of_maturity = args

        if level_of_maturity == ida_hexrays.CMAT_TRANS1 and has_inverted(
            cfunc.entry_ea
        ):
            log_debug(f"Swapping then/else in {hex(cfunc.entry_ea)}")
            inverted = [
                name + ida_nalt.get_imagebase()
                for name in get_inverted(cfunc.entry_ea)
            ]
            log_debug(f"Got inverted: {inverted}")
            visitor = SwapThenElseVisitor(inverted)
            visitor.apply_to(cfunc.body, None)

        elif level_of_maturity == ida_hexrays.CMAT_TRANS2:
            visitor = SpaghettiVisitor()
            visitor.apply_to(cfunc.body, None)

        return 0