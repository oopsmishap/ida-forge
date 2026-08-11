"""Behavior tests for forge.util.logging."""

from __future__ import annotations

import importlib
import logging

import pytest

from forge.util import logging as forge_logging


@pytest.fixture(autouse=True)
def _capture_kernwin(monkeypatch):
    """Route ida_kernwin.msg/warning into lists for assertions."""
    calls = {"msg": [], "warning": []}

    import ida_kernwin

    monkeypatch.setattr(ida_kernwin, "msg", lambda text: calls["msg"].append(text))
    monkeypatch.setattr(
        ida_kernwin, "warning", lambda text: calls["warning"].append(text)
    )
    return calls


def test_log_debug_and_info_go_to_output_window(_capture_kernwin):
    forge_logging.log_debug("debug msg")
    forge_logging.log_info("info msg")
    assert any("debug msg" in line for line in _capture_kernwin["msg"])
    assert any("info msg" in line for line in _capture_kernwin["msg"])


def test_log_warning_prefixes_with_ida_warning_tag(_capture_kernwin):
    forge_logging.log_warning("careful")
    assert any(line.startswith("WARNING: ") and "careful" in line for line in _capture_kernwin["msg"])


def test_log_warning_message_box_only_when_requested(_capture_kernwin):
    forge_logging.log_warning("no box")
    assert _capture_kernwin["warning"] == []

    forge_logging.log_warning("boxed", display_messagebox=True)
    assert any("boxed" in line for line in _capture_kernwin["warning"])


def test_log_error_message_box_only_when_requested(_capture_kernwin):
    forge_logging.log_error("err no box")
    assert _capture_kernwin["warning"] == []

    forge_logging.log_error("err boxed", display_messagebox=True)
    assert any("err boxed" in line for line in _capture_kernwin["warning"])


def test_empty_message_never_shows_message_box(_capture_kernwin):
    forge_logging.log_warning(None, display_messagebox=True)
    forge_logging.log_error("", display_messagebox=True)
    assert _capture_kernwin["warning"] == []


def test_message_formatting_is_brittle_proof(_capture_kernwin):
    """Percent-style strings must not crash formatting."""
    forge_logging.log_info("100%% of %s values")
    assert any("100%% of %s values" in line for line in _capture_kernwin["msg"])


def test_reload_dedupes_handlers():
    """The marker attribute keeps exactly one handler across reloads."""
    logger = logging.getLogger("forge")

    importlib.reload(forge_logging)
    importlib.reload(forge_logging)

    marker_handlers = [h for h in logger.handlers if getattr(h, "_forge_marker", False)]
    assert len(marker_handlers) == 1