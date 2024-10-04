import idaapi

from forge.util.logging import log_debug

imported_ea = set()


def _init_imported_ea():

    def imp_cb(ea, name, ord):
        imported_ea.add(ea - idaapi.get_imagebase())
        return True

    log_debug("Collecting information about imports")
    imported_ea.clear()
    import_count = idaapi.get_import_module_qty()

    for i in range(0, import_count):
        name = idaapi.get_import_module_name(i)
        if not name:
            log_debug("Failed to get import module name for #%d" % i)
            continue

        # print "Walking-> %s" % name
        idaapi.enum_import_names(i, imp_cb)
    log_debug("Done...")


def initialize_cache(*args):
    _init_imported_ea()
