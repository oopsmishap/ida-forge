"""Qt compatibility helpers for IDA versions using PyQt5 or PySide6."""

from __future__ import annotations

import importlib.util as _import_util

QT_BINDING: str

if _import_util.find_spec("PySide6"):
    from PySide6 import QtCore, QtGui, QtWidgets  # noqa: F401 — importing QtGui/QtWidgets registers the submodules

    QT_BINDING = "PySide6"
    Signal = QtCore.Signal
else:
    from PyQt5 import QtCore

    QT_BINDING = "PyQt5"
    Signal = QtCore.pyqtSignal


def qt_flag_value(flag):
    """Return the integer value of a Qt enum/flag member across bindings.

    PySide6's enums do not support bitwise ``|`` directly (the PyQt5 shim
    that provides legacy class-attribute access warns about it); every
    consumer that ORs Qt flags must go through this helper (or
    :func:`qt_item_flags`) so the operation happens on plain ints.
    """
    if flag is None:
        return 0
    return int(getattr(flag, "value", flag))


def qt_item_flags(*flags):
    """Combine Qt item flags into a value compatible with ``QTableWidgetItem.setFlags``.

    Uses :func:`qt_flag_value` so the combination works on plain ints in both
    bindings; the integer form is accepted by ``setFlags`` either way.
    """
    combined = 0
    for flag in flags:
        combined |= qt_flag_value(flag)

    item_flags = getattr(QtCore.Qt, "ItemFlags", None)
    if callable(item_flags):
        return item_flags(combined)
    return combined


def qt_exec(widget, *args, **kwargs):
    """Call exec()/exec_() depending on the active Qt binding."""
    if hasattr(widget, "exec"):
        return widget.exec(*args, **kwargs)
    return widget.exec_(*args, **kwargs)
