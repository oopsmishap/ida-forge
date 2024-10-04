import ida_kernwin

from forge.plugin import PLUGIN_NAME

# Global logging prefix, used when logging messages
logging_prefix = f"[{PLUGIN_NAME}]"


def log_info(message=None):
    """
    Logs an informational message.

    :param message: The message to be logged.
    """
    if message:
        # logging.info(f"{logging_prefix}: {message}")
        ida_kernwin.msg(f"{logging_prefix}[INFO]: {message}\n")


def log_error(message=None, display_messagebox=False):
    """
    Logs an error message.

    :param message: The message to be logged.
    :param display_messagebox: Whether to display a message box to the user or not.
    """
    if message:
        # logging.error(f"{logging_prefix}: {message}")
        ida_kernwin.msg(f"{logging_prefix}[ERROR]: {message}\n")

        if display_messagebox:
            ida_kernwin.warning(f"{logging_prefix}: {message}")


def log_warning(message=None, display_messagebox=False):
    """
    Logs a warning message.

    :param message: The message to be logged.
    :param display_messagebox: Whether to display a message box to the user or not.
    """
    if message:
        # logging.warning(f"{logging_prefix}: {message}")
        ida_kernwin.msg(f"{logging_prefix}[WARNING]: {message}\n")

        if display_messagebox:
            ida_kernwin.warning(f"{logging_prefix}: {message}")


def log_debug(message=None):
    """
    Logs a debug message.

    :param message: The message to be logged.
    """
    if message:
        # logging.info(f"{logging_prefix}: {message}")
        ida_kernwin.msg(f"{logging_prefix}[DEBUG]: {message}\n")
