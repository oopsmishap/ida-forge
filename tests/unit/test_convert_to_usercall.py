"""Behavior tests for forge.features.convert_to_usercall."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from forge.features.convert_to_usercall import convert_to_usercall as module


@pytest.fixture(autouse=True)
def _stub_ida_constants(monkeypatch):
    """The conftest stub lacks the calling-convention constants."""
    ida_typeinf = module.ida_typeinf
    for name, value in (
        ("CM_CC_MASK", 0xF),
        ("CM_CC_CDECL", 1),
        ("CM_CC_STDCALL", 2),
        ("CM_CC_FASTCALL", 3),
        ("CM_CC_THISCALL", 4),
        ("CM_CC_PASCAL", 5),
        ("CM_CC_ELLIPSIS", 7),
        ("CM_CC_SPECIAL", 8),
        ("CM_CC_SPECIALP", 9),
        ("CM_CC_SPECIALE", 10),
        ("TINFO_DEFINITE", 0x100),
        ("VDI_FUNC", 5),
        ("VDI_EXPR", 3),
    ):
        if not hasattr(ida_typeinf, name):
            monkeypatch.setattr(ida_typeinf, name, value, raising=False)
        if not hasattr(module.ida_hexrays, name):
            monkeypatch.setattr(module.ida_hexrays, name, value, raising=False)


def _make_action():
    return module.ConvertToUsercall()


def _make_view(citype):
    return SimpleNamespace(item=SimpleNamespace(citype=citype))


def _make_vu():
    return SimpleNamespace(
        cfunc=SimpleNamespace(entry_ea=0x140001000),
        refresh_view=lambda dirty: None,
    )


def test_check_requires_func_item(monkeypatch):
    action = _make_action()
    assert action.check(_make_view(module.ida_hexrays.VDI_FUNC))
    assert not action.check(_make_view(module.ida_hexrays.VDI_EXPR))


def test_check_respects_enabled_config(monkeypatch):
    action = _make_action()
    action.config["enabled"] = False
    assert not action.check(_make_view(module.ida_hexrays.VDI_FUNC))


def _prepare_activation(monkeypatch, cc_name):
    ida_typeinf = module.ida_typeinf

    captured = {"applied": [], "refreshed": [], "details_cc": None, "log": []}

    class _FakeFuncTypeData:
        def __init__(self):
            self.cc = getattr(ida_typeinf, cc_name)

    func_type_data = _FakeFuncTypeData()

    class _FakeTInfo:
        def get_func_details(self, details):
            details.cc = func_type_data.cc

        def create_func(self, details):
            func_type_data.cc = details.cc

    vdui = _make_vu()
    monkeypatch.setattr(module.ida_hexrays, "get_widget_vdui", lambda widget: vdui, raising=False)
    monkeypatch.setattr(ida_typeinf, "func_type_data_t", _FakeFuncTypeData, raising=False)
    monkeypatch.setattr(ida_typeinf, "tinfo_t", _FakeTInfo, raising=False)
    monkeypatch.setattr(
        ida_typeinf,
        "apply_tinfo",
        lambda ea, tinfo, flags: captured["applied"].append((ea, flags)),
        raising=False,
    )
    vdui.cfunc.get_func_type = lambda tinfo: True
    vdui.refresh_view = lambda dirty: captured["refreshed"].append(dirty)

    import logging

    class _Capture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records = []
            self.setLevel(logging.DEBUG)

        def emit(self, record):
            self.records.append(record.getMessage())

    handler = _Capture()
    forge_logger = logging.getLogger("forge")
    forge_logger.addHandler(handler)
    captured["log"] = handler

    return captured, func_type_data, vdui


@pytest.mark.parametrize(
    "cc, expected_cc, label",
    [
        ("CM_CC_CDECL", "CM_CC_SPECIAL", "__usercall"),
        ("CM_CC_STDCALL", "CM_CC_SPECIALP", "__usercall_"),
        ("CM_CC_FASTCALL", "CM_CC_SPECIALP", "__usercall_"),
        ("CM_CC_THISCALL", "CM_CC_SPECIALP", "__usercall_"),
        ("CM_CC_PASCAL", "CM_CC_SPECIALP", "__usercall_"),
        ("CM_CC_ELLIPSIS", "CM_CC_SPECIALE", "__usercalle_"),
    ],
)
def test_activate_converts_calling_convention(monkeypatch, cc, expected_cc, label):
    captured, details, _vdui = _prepare_activation(monkeypatch, cc)

    action = _make_action()
    action.activate(SimpleNamespace(widget=object()))

    assert details.cc == getattr(module.ida_typeinf, expected_cc)
    assert captured["applied"] == [
        (0x140001000, module.ida_typeinf.TINFO_DEFINITE)
    ]
    assert captured["refreshed"] == [True]
    assert any(f"Converted to {label}" in m for m in captured["log"].records)


def test_activate_unknown_convention_does_nothing(monkeypatch):
    captured, details, _vdui = _prepare_activation(monkeypatch, "CM_CC_CDECL")
    details.cc = 0xEE

    action = _make_action()
    action.activate(SimpleNamespace(widget=object()))

    assert captured["applied"] == []
    assert captured["refreshed"] == []


def test_activate_missing_func_type_does_nothing(monkeypatch):
    captured, _details, vdui = _prepare_activation(monkeypatch, "CM_CC_CDECL")
    vdui.cfunc.get_func_type = lambda tinfo: False

    action = _make_action()
    action.activate(SimpleNamespace(widget=object()))

    assert captured["applied"] == []
    assert captured["refreshed"] == []