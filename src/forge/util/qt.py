"""Qt compatibility helpers for IDA versions using PyQt5 or PySide6."""

from __future__ import annotations

import importlib.util as _import_util

QT_BINDING: str


class _DummyQtMeta(type):
    """Metaclass so class-attribute lookups (``QMessageBox.Yes``) work."""

    def __getattr__(cls, _name):
        return cls


class _DummyQtClass(metaclass=_DummyQtMeta):
    """Inert stand-in for any Qt class/enum used by GUI-only dialog paths.

    Must be a real class (not an instance): GUI modules define subclasses of
    Qt widgets at import time (``class ClickableQLabel(QtWidgets.QLabel)``),
    which requires a class base.
    """

    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, *args, **kwargs):
        return self

    def __getattr__(self, _name):
        return self

    def __and__(self, other):
        return self

    def __or__(self, other):
        return self


class _DummyQtNamespace:
    """Returns dummy classes for any Qt attribute (QtCore/QtGui/QtWidgets)."""

    def __getattr__(self, name):
        return _DummyQtClass


def _load_qt_binding():
    """Import the active Qt binding, degrading to inert stubs when headless.

    IDA ships PySide6 inside the install tree, but PySide6 refuses to load
    unless running in the GUI build of IDA (idalib raises at its own
    prerequisite check). Headless workers never reach the GUI dialog paths,
    so a stub namespace keeps every module importable; it is the same
    degradation the unit-test conftest applies. In GUI IDA or with PyQt5
    present the real binding is used, so plugin behavior is unchanged.
    """
    if _import_util.find_spec("PySide6"):
        try:
            from PySide6 import (
                QtCore,
                QtGui,
                QtWidgets,
            )

            return QtCore, QtGui, QtWidgets, QtCore.Signal, "PySide6"
        except (ImportError, NotImplementedError):
            pass

    try:
        from PyQt5 import QtCore

        return QtCore, QtCore, QtCore, QtCore.pyqtSignal, "PyQt5"
    except (ImportError, NotImplementedError):
        namespace = _DummyQtNamespace()
        return namespace, namespace, namespace, _dummy_signal, "stub"


def _dummy_signal(*args, **kwargs):
    """Stand-in for Qt's ``Signal`` factory used in widget class bodies."""
    return _DummyQtClass()


QtCore, QtGui, QtWidgets, Signal, QT_BINDING = _load_qt_binding()


def qt_flag_value(flag):
    """Return the integer value of a Qt enum/flag member across bindings.

    PySide6's enums do not support bitwise ``|`` directly (the PyQt5 shim
    that provides legacy class-attribute access warns about it); every
    consumer that ORs Qt flags must go through this helper (or
    :func:`qt_combined_flags`) so the operation happens on plain ints.
    """
    if flag is None:
        return 0
    return int(getattr(flag, "value", flag))


def qt_combined_flags(*flags, flags_type=None):
    """Combine Qt flag members into a value a typed setter accepts.

    ORs :func:`qt_flag_value` ints — never the enum members themselves,
    so the PyQt5-shim RuntimeWarning stays silent — then wraps the
    result in ``flags_type`` when it is callable. PySide6 rejects plain
    ints for typed setters (``setEditTriggers(int)`` raises TypeError),
    while the flag type constructed from the int is accepted silently.
    Bindings without an int-constructible type (PyQt5 accepts the int
    directly) fall back to the plain int.
    """
    combined = 0
    for flag in flags:
        combined |= qt_flag_value(flag)

    if callable(flags_type):
        try:
            return flags_type(combined)
        except (TypeError, ValueError):
            pass
    return combined


def qt_item_flags(*flags):
    """Combine Qt item flags into a value compatible with ``QTableWidgetItem.setFlags``.

    Uses :func:`qt_combined_flags` so the combination works on plain
    ints in both bindings; the integer form is accepted by ``setFlags``
    either way.
    """
    item_flags = getattr(QtCore.Qt, "ItemFlags", None)
    return qt_combined_flags(*flags, flags_type=item_flags)


def qt_exec(widget, *args, **kwargs):
    """Call exec()/exec_() depending on the active Qt binding."""
    if hasattr(widget, "exec"):
        return widget.exec(*args, **kwargs)
    return widget.exec_(*args, **kwargs)
