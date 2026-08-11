from __future__ import annotations

from types import SimpleNamespace

import forge.plugin
from forge.plugin import (
    _GET_STATE_NAME,
    _SET_STATE_NAME,
    register_idc_func,
    unregister_idc_func,
)


class _FakePlugmod:
    def __init__(self):
        self.states = []

    def get_state(self, index: int) -> str:
        if 0 <= index < len(self.states):
            return self.states[index]
        return ""

    def add_state(self, value: str) -> int:
        self.states.append(value or "")
        return len(self.states) - 1


def _capture_calls(monkeypatch):
    calls = []
    deleted = []

    def add_idc_func(name, fp, args, *extra, **kwargs):
        calls.append(
            {
                "name": name,
                "fp": fp,
                "args": args,
            }
        )
        return True

    def del_idc_func(name):
        deleted.append(name)

    monkeypatch.setattr(forge.plugin.ida_expr, "add_idc_func", add_idc_func)
    monkeypatch.setattr(forge.plugin.ida_expr, "del_idc_func", del_idc_func)
    return calls, deleted


def test_register_idc_func_registers_documented_argument_shape(monkeypatch):
    """Regression guard for the IDC registration ABI.

    Verified against real IDA 9.x bindings: ``add_idc_func`` expects a tuple of
    ``VT_*`` codes as the third argument (a plain str raises TypeError). This
    test pins the exact shape so stub drift is caught in CI.
    """
    calls, deleted = _capture_calls(monkeypatch)
    plugmod = _FakePlugmod()

    register_idc_func(plugmod)

    assert deleted == [_GET_STATE_NAME, _SET_STATE_NAME]

    assert len(calls) == 2
    get_call, add_call = calls

    assert get_call["name"] == _GET_STATE_NAME
    assert get_call["fp"] == plugmod.get_state
    assert get_call["args"] == (forge.plugin.ida_expr.VT_LONG,)

    assert add_call["name"] == _SET_STATE_NAME
    assert add_call["fp"] == plugmod.add_state
    assert add_call["args"] == (forge.plugin.ida_expr.VT_STR,)


def test_register_idc_func_survives_registration_failure(monkeypatch):
    """A registration failure must not abort plugin init."""
    calls, _ = _capture_calls(monkeypatch)

    def failing_add_idc_func(*args, **kwargs):
        raise TypeError("simulated binding mismatch")

    monkeypatch.setattr(forge.plugin.ida_expr, "add_idc_func", failing_add_idc_func)
    plugmod = _FakePlugmod()

    register_idc_func(plugmod)  # must not raise

    assert calls == []


def test_register_idc_func_del_failure_is_tolerated(monkeypatch):
    """Stale registrations may already be gone; del failures are fine."""
    calls, _ = _capture_calls(monkeypatch)

    def failing_del_idc_func(*args, **kwargs):
        raise RuntimeError("no such function")

    monkeypatch.setattr(forge.plugin.ida_expr, "del_idc_func", failing_del_idc_func)
    plugmod = _FakePlugmod()

    register_idc_func(plugmod)

    assert len(calls) == 2


def test_unregister_idc_func_removes_both_accessors(monkeypatch):
    _, deleted = _capture_calls(monkeypatch)

    unregister_idc_func()

    assert deleted == [_GET_STATE_NAME, _SET_STATE_NAME]


def test_idc_state_round_trip_via_plugmod(monkeypatch):
    """The accessors the IDC funcs wrap behave as documented."""
    calls, _ = _capture_calls(monkeypatch)
    plugmod = _FakePlugmod()

    index = plugmod.add_state("first")
    assert index == 0
    assert plugmod.get_state(0) == "first"
    assert plugmod.get_state(7) == ""

    register_idc_func(plugmod)
    # The registered callbacks are exactly these bound methods.
    assert calls[0]["fp"] == plugmod.get_state
    assert calls[1]["fp"] == plugmod.add_state