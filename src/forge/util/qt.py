"""Qt compatibility helpers for IDA versions using PyQt5 or PySide6."""

from __future__ import annotations

QT_BINDING: str

try:
    from PySide6 import QtCore, QtGui, QtWidgets

    QT_BINDING = "PySide6"
    Signal = QtCore.Signal
except ImportError:
    from PyQt5 import QtCore, QtGui, QtWidgets

    QT_BINDING = "PyQt5"
    Signal = QtCore.pyqtSignal


def qt_item_flags(*flags):
    """Combine Qt item flags into a QFlags bitmask."""
    combined = None
    for flag in flags:
        if flag is None:
            continue
        combined = flag if combined is None else combined | flag

    if combined is None:
        combined = 0

    item_flags = getattr(QtCore.Qt, "ItemFlags", None)
    if callable(item_flags):
        return item_flags(combined)
    return combined


def qt_exec(widget, *args, **kwargs):
    """Call exec()/exec_() depending on the active Qt binding."""
    if hasattr(widget, "exec"):
        return widget.exec(*args, **kwargs)
    return widget.exec_(*args, **kwargs)
