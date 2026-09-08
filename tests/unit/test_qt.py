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
    # The PyQt5 branch imports all three submodules, so the fake must
    # provide them or the fixture would silently degrade to stub mode.
    pyqt5.QtGui = SimpleNamespace()
    pyqt5.QtWidgets = SimpleNamespace()
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


def test_qt_combined_flags_wraps_typed_flag(qt_module):
    """R3.4: typed setters (PySide6 setEditTriggers) reject plain ints —
    qt_combined_flags wraps the combined value in the binding's type."""
    wrapped = []

    def _flag_type(value):
        wrapped.append(value)
        return ("EditTriggers", value)

    result = qt_module.qt_combined_flags(
        SimpleNamespace(value=4),
        SimpleNamespace(value=8),
        flags_type=_flag_type,
    )
    assert result == ("EditTriggers", 12)
    assert wrapped == [12]


def test_qt_combined_flags_falls_back_when_type_rejects_int(qt_module):
    """R3.4: a flags type that cannot be constructed from the int (or is
    missing) leaves the plain int — PyQt5 accepts that form."""
    class _RejectingType:
        def __call__(self, value):
            raise TypeError("int form not supported")

    result = qt_module.qt_combined_flags(
        SimpleNamespace(value=4), flags_type=_RejectingType()
    )
    assert result == 4

    result = qt_module.qt_combined_flags(SimpleNamespace(value=2))
    assert result == 2


def test_qt_combined_flags_ignores_none_and_int_members(qt_module):
    result = qt_module.qt_combined_flags(
        None, SimpleNamespace(value=16), _PyQt5StyleEnum(4)
    )
    assert result == 20


@pytest.fixture
def qt_stub_module(monkeypatch):
    """Load the real qt.py in headless stub mode: PySide6 absent, PyQt5
    import halted. This is the binding headless idalib workers run under."""
    monkeypatch.setattr(importlib.util, "find_spec", lambda _name: None)
    monkeypatch.setitem(sys.modules, "PyQt5", None)  # import raises ImportError
    return _load_qt_module(monkeypatch, "forge.util.qt_stub_test")


def _load_qt_module(monkeypatch, name):
    spec = importlib.util.spec_from_file_location(name, _QT_SRC)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _BrokenQtModule(types.ModuleType):
    """A module whose Qt submodule attribute raises at access time.

    ``from <mod> import Qt`` propagates whatever the attribute lookup
    raises, so these fakes exercise the broadened ``except Exception``
    fallbacks (RuntimeError from idalib prerequisite checks, OSError from
    Windows DLL load failures) — neither is an ImportError.
    """

    def __init__(self, exc):
        super().__init__("broken")
        self._exc = exc

    @property
    def QtCore(self):
        raise self._exc


def test_stub_binding_loads_headless(qt_stub_module):
    assert qt_stub_module.QT_BINDING == "stub"
    namespace = qt_stub_module.QtCore
    assert isinstance(namespace, qt_stub_module._DummyQtNamespace)
    assert qt_stub_module.QtGui is namespace
    assert qt_stub_module.QtWidgets is namespace


def test_stub_dummy_classes_are_subclassable_and_declare_signals(qt_stub_module):
    class _FakeWidget(qt_stub_module.QtWidgets.QWidget):
        changed = qt_stub_module.Signal()

    assert issubclass(_FakeWidget, qt_stub_module._DummyQtClass)
    assert isinstance(_FakeWidget.changed, qt_stub_module._DummyQtClass)
    # Class-attribute enum lookups (``QMessageBox.Yes``) resolve via the
    # metaclass — the contract GUI-only dialog paths rely on.
    assert qt_stub_module.QtWidgets.QMessageBox.Yes is qt_stub_module._DummyQtClass


def test_pyside6_runtime_failure_falls_back_to_pyqt5(monkeypatch):
    """A PySide6 import that dies on a non-ImportError (idalib prerequisite
    RuntimeError) must fall through to PyQt5 instead of killing the import."""
    monkeypatch.setattr(importlib.util, "find_spec", lambda _name: object())
    monkeypatch.setitem(sys.modules, "PySide6", _BrokenQtModule(RuntimeError("idalib prerequisite")))
    pyqt5 = types.ModuleType("PyQt5")
    pyqt5.QtCore = SimpleNamespace(pyqtSignal=lambda *a, **k: None)
    pyqt5.QtGui = SimpleNamespace()
    pyqt5.QtWidgets = SimpleNamespace()
    monkeypatch.setitem(sys.modules, "PyQt5", pyqt5)

    module = _load_qt_module(monkeypatch, "forge.util.qt_fallback_test")

    assert module.QT_BINDING == "PyQt5"
    assert module.QtCore is pyqt5.QtCore
    assert module.QtGui is pyqt5.QtGui
    assert module.QtWidgets is pyqt5.QtWidgets


def test_dll_failure_and_missing_pyqt5_degrade_to_stub(monkeypatch):
    """OSError (Windows DLL load) at the PySide6 site and a PyQt5 import
    that fails the same way both land on the inert stub, not a crash."""
    monkeypatch.setattr(importlib.util, "find_spec", lambda _name: object())
    monkeypatch.setitem(sys.modules, "PySide6", _BrokenQtModule(OSError("DLL load failed")))
    monkeypatch.setitem(sys.modules, "PyQt5", _BrokenQtModule(OSError("DLL load failed")))

    module = _load_qt_module(monkeypatch, "forge.util.qt_dll_test")

    assert module.QT_BINDING == "stub"
    assert module.QtWidgets is module.QtCore
