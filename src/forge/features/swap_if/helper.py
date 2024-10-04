import ida_hexrays


def inverse_if_condition(cif):
    cit_if_condition = cif.expr
    tmp_cexpr = ida_hexrays.cexpr_t()
    tmp_cexpr.assign(cit_if_condition)
    new_if_condition = ida_hexrays.lnot(tmp_cexpr)
    cif.expr.swap(new_if_condition)
    del cit_if_condition


def inverse_if(cif):
    inverse_if_condition(cif)
    ida_hexrays.qswap(cif.ithen, cif.ielse)
