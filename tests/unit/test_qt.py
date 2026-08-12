"""Behavior tests for forge.util.qt's cross-binding flag helpers."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

_QT_SRC = Path(__file__).resolve().parents[2] / "src" / "forge" / "util" / "qt.py"


class _PyQt5StyleEnum:
    """PyQt5 enum member: int-convertible, no ``.value``."""

    def __init__(self, value):
        self._value = value

    def __int__(self):
        return self._value


@pytest.fixture
def qt_module(monkeypatch):
    """Load the real qt.py under the PyQt5 branch (no PySide6 installed)."""
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)
    pyqt5 = types.ModuleType("PyQt5")
    pyqt5.QtCore = SimpleNamespace(
        Qt=SimpleNamespace(ItemFlags=lambda value: value),
        pyqtSignal=lambda *a, **k: None,
    )
    monkeypatch.setitem(sys.modules, "PyQt5", pyqt5)

    spec = importlib.util.spec_from_file_location("forge.util.qt_flag_test", _QT_SRC)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_qt_flag_value_extracts_pyside6_value(qt_module):
    flag = SimpleNamespace(value=4)
    assert qt_module.qt_flag_value(flag) == 4


def test_qt_flag_value_accepts_int_like(qt_module):
    assert qt_module.qt_flag_value(8) == 8


def test_qt_flag_value_pyqt5_enum_via_int(qt_module):
    assert qt_module.qt_flag_value(_PyQt5StyleEnum(256)) == 256


def test_qt_flag_value_none_is_zero(qt_module):
    assert qt_module.qt_flag_value(None) == 0


def test_qt_item_flags_combines_value_members(qt_module):
    # EditTrigger-style members with .value (PySide6) combine without the
    # shim: this is the operation the RuntimeWarning used to swallow.
    combined = qt_module.qt_item_flags(
        SimpleNamespace(value=4), SimpleNamespace(value=8)
    )
    assert combined == 12


def test_qt_item_flags_mixed_enum_shapes(qt_module):
    combined = qt_module.qt_item_flags(
        SimpleNamespace(value=4), _PyQt5StyleEnum(8)
    )
    assert combined == 12