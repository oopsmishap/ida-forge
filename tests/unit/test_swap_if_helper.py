"""Behavior tests for forge.features.swap_if.helper."""

from __future__ import annotations

from types import SimpleNamespace

from forge.features.swap_if import helper


def _fake_cif():
    return SimpleNamespace(
        expr=SimpleNamespace(swapped_with=None, swap=lambda other: None),
        ithen=SimpleNamespace(side="then"),
        ielse=SimpleNamespace(side="else"),
    )


def test_inverse_if_condition_negates_and_swaps_in_place(monkeypatch):
    events = {"lnot_arg": None, "swap_arg": None}

    class _FakeTmpCExpr:
        def __init__(self):
            self.assigned = None

        def assign(self, other):
            self.assigned = other

    def fake_lnot(cexpr):
        events["lnot_arg"] = cexpr
        return SimpleNamespace(negated=cexpr)

    monkeypatch.setattr(helper.ida_hexrays, "cexpr_t", _FakeTmpCExpr, raising=False)
    monkeypatch.setattr(helper.ida_hexrays, "lnot", fake_lnot, raising=False)

    cif = _fake_cif()

    def fake_swap(other):
        events["swap_arg"] = other

    cif.expr.swap = fake_swap
    helper.inverse_if_condition(cif)

    # tmp got the original condition
    assert events["lnot_arg"].assigned is cif.expr
    # the negated expression replaced the condition
    assert events["swap_arg"].negated is events["lnot_arg"]


def test_inverse_if_swaps_then_else_branches(monkeypatch):
    swapped = []

    class _FakeTmpCExpr:
        def assign(self, other):
            pass

        def swap(self, other):
            pass

    monkeypatch.setattr(helper.ida_hexrays, "cexpr_t", _FakeTmpCExpr, raising=False)
    monkeypatch.setattr(helper.ida_hexrays, "lnot", lambda cexpr: SimpleNamespace(negated=cexpr), raising=False)
    monkeypatch.setattr(
        helper.ida_hexrays, "qswap", lambda a, b: swapped.append((a, b)), raising=False
    )

    cif = _fake_cif()
    helper.inverse_if(cif)

    assert len(swapped) == 1
    assert swapped[0][0].side == "then"
    assert swapped[0][1].side == "else"