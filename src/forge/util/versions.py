from __future__ import annotations

import sys

import ida_kernwin


MIN_PYTHON: tuple[int, int] = (3, 9)
MIN_IDA: tuple[int, int] = (9, 0)


def is_python_version_supported() -> bool:
    """Return ``True`` when the running Python is at least 3.9."""
    return sys.version_info >= MIN_PYTHON


def is_ida_version_supported() -> bool:
    """Return ``True`` when the running IDA kernel is at least 9.0."""
    version = tuple(int(part) for part in ida_kernwin.get_kernel_version().split("."))
    return version >= MIN_IDA
