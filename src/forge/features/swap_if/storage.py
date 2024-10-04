import idaapi

from forge.api.storage import Storage
from forge.util.logging import log_debug

swap_if_storage = Storage("SwapIf")


def has_inverted(func_ea):
    func_rva = func_ea - idaapi.get_imagebase()
    return func_rva in swap_if_storage


def get_inverted(func_ea):
    func_rva = func_ea - idaapi.get_imagebase()
    log_debug(
        f"Getting inverted for {func_ea}, keys: {swap_if_storage.keys()}, key_keys: {list(swap_if_storage[func_rva].values())}"
    )
    return sorted(list(swap_if_storage[func_rva].values()))


def set_inverted(func_ea, if_ea):
    iv_rva = if_ea - idaapi.get_imagebase()
    func_rva = func_ea - idaapi.get_imagebase()

    if func_rva not in swap_if_storage:
        swap_if_storage[func_rva] = {0: iv_rva}
    else:
        iv_dict = swap_if_storage[func_rva]
        if iv_rva not in iv_dict.values():
            size = len(iv_dict.keys())
            iv_dict[size] = iv_rva
            swap_if_storage[func_rva] = iv_dict
