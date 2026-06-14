from __future__ import annotations

import logging

import ida_kernwin

from forge.plugin import PLUGIN_NAME


_logger = logging.getLogger("forge")
_logger.addHandler(logging.NullHandler())


def _format(message: str | None) -> str:
    if not message:
        return f"{PLUGIN_NAME}:"
    return f"{PLUGIN_NAME}: {message}"


def log_debug(message: str | None = None) -> None:
    """Log a debug-level message under the ``forge`` logger."""
    _logger.debug(_format(message))


def log_info(message: str | None = None) -> None:
    """Log an info-level message under the ``forge`` logger."""
    _logger.info(_format(message))


def log_warning(message: str | None = None, display_messagebox: bool = False) -> None:
    """Log a warning-level message under the ``forge`` logger.

    When ``display_messagebox`` is true, additionally surface the message in
    an IDA warning dialog so it reaches the user.
    """
    formatted = _format(message)
    _logger.warning(formatted)
    if display_messagebox and message:
        ida_kernwin.warning(formatted)


def log_error(message: str | None = None, display_messagebox: bool = False) -> None:
    """Log an error-level message under the ``forge`` logger.

    When ``display_messagebox`` is true, additionally surface the message in
    an IDA warning dialog so it reaches the user.
    """
    formatted = _format(message)
    _logger.error(formatted)
    if display_messagebox and message:
        ida_kernwin.warning(formatted)
