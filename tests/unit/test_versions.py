from __future__ import annotations

from forge.util import versions


def test_python_version_support_boundary(monkeypatch):
    monkeypatch.setattr(versions.sys, "version_info", (3, 6, 0))
    assert versions.is_python_version_supported() is True

    monkeypatch.setattr(versions.sys, "version_info", (3, 5, 9))
    assert versions.is_python_version_supported() is False


def test_ida_version_support_boundary(monkeypatch):
    monkeypatch.setattr(versions.ida_kernwin, "get_kernel_version", lambda: "7.4")
    assert versions.is_ida_version_supported() is True

    monkeypatch.setattr(versions.ida_kernwin, "get_kernel_version", lambda: "7.3")
    assert versions.is_ida_version_supported() is False
