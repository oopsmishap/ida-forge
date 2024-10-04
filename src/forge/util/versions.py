import sys
import ida_kernwin


def is_python_version_supported() -> bool:
    """
    Check if the Python version is supported.

    :return: True if the version is supported, False otherwise.
    """
    # TODO: Find out the minimum version, have been using 3.9 for dev/testing
    minimum_major = 3
    minimum_minor = 6
    return sys.version_info >= (minimum_major, minimum_minor)


def is_ida_version_supported() -> bool:
    """
    Check if the IDA kernel version is supported.

    :return: True if the version is supported, False otherwise.
    """
    # TODO: Find out the minimum version, have been using 7.6 for dev/testing
    # Since the API overhaul was done in 7.4, we'll assume that's the minimum
    minimum_major = 7
    minimum_minor = 4

    ida_kernel_version = tuple(map(int, ida_kernwin.get_kernel_version().split(".")))
    return ida_kernel_version >= (minimum_major, minimum_minor)
