from __future__ import annotations

import logging

import ida_kernwin

from forge.plugin import PLUGIN_NAME

_logger = logging.getLogger("forge")
_logger.setLevel(logging.DEBUG)


class _IDAMsgHandler(logging.Handler):
    """Forward :mod:`logging` records to IDA's Output window.

    Level mapping:

    * ``DEBUG``/``INFO``  → ``ida_kernwin.msg`` (plain)
    * ``WARNING``/``ERROR`` → ``ida_kernwin.msg`` with the ``IDAWARNING`` tag
    """

    # Marker so we can dedupe handlers even after ``importlib.reload``
    # creates a fresh class object (the old handler's ``__class__`` no
    # longer matches the new class, so ``isinstance`` filtering alone
    # is not enough).
    _forge_marker = True

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
        except Exception:  # noqa: BLE001
            message = record.getMessage()

        if record.levelno >= logging.WARNING:
            ida_kernwin.msg(f"{IDAWARNING}{message}\n")
        else:
            ida_kernwin.msg(f"{message}\n")

# ``IDAWARNING`` is exported by ``ida_kernwin`` (e.g. the string ``"WARNING: "``);
# guard the lookup so the module also works under standalone unit-test stubs
# that don't define it.
IDAWARNING = getattr(ida_kernwin, "IDAWARNING", "WARNING: ")

# Drop any handlers from prior loads of this module (the class identity
# changes across ``importlib.reload`` so ``isinstance`` filtering alone
# is unreliable — we use a marker attribute).
_logger.handlers = [h for h in _logger.handlers if not getattr(h, "_forge_marker", False)]
_handler = _IDAMsgHandler()
_handler.setFormatter(logging.Formatter(f"{PLUGIN_NAME}: %(message)s"))
_logger.addHandler(_handler)


def _format(message: str | None) -> str:
    return message or ""



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
