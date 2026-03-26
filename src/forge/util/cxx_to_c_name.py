import re


def bad_c_name_pattern(name):
    """
    Removes or replaces characters from demangled symbol so that it was possible to create legal C structure from it
    """
    bad_c_name_pattern_re = re.compile(
        ":::+|(?=:(?=[^:]))(?=(?<=[^:]):):|^:[^:]|[^:]:$|^:$|[^a-zA-Z_0-9:]"
    )

    if not bad_c_name_pattern_re.findall(name):
        return name

    # filter `vtable and `typeinfo
    if name.startswith("`"):
        return name


# FIXME: This is very ugly way to find and replace illegal characters
def demangled_name_to_c_str(name):
    # Define a dictionary of C++ operator names and their C-compatible replacements
    operator_replacements = {
        "==": "eq_",
        "!=": "neq_",
        "=": "assign_",
        "+=": "plus_assign_",
        "-=": "minus_assign_",
        "*=": "mul_assign_",
        "/=": "div_assign_",
        "%=": "modulo_div_assign_",
        "|=": "or_assign_",
        "&=": "and_assign_",
        "^=": "xor_assign_",
        "<<=": "left_shift_assign_",
        ">>=": "right_shift_assign_",
        "++": "inc_",
        "--": "ptr_",
        "->": "ref_",
        "[]": "idx_",
        "*": "star_",
        "&&": "land_",
        "||": "lor_",
        "!": "lnot_",
        "&": "and_",
        "|": "or_",
        "^": "xor_",
        "<<": "left_shift_",
        ">>": "right_shift_",
        "<=": "less_equal_",
        ">=": "greater_equal_",
        "<": "less_",
        ">": "greater_",
        "+": "add_",
        "-": "sub_",
        "/": "div_",
        "%": "modulo_",
        "()": "call_",
        " new[]": "new_array_",
        " delete[]": "delete_array_",
        " new": "new_",
        " delete": "delete_",
        '"" ': "literal_",
        "~": "not_",
    }

    # Replace C++ operator names with their C-compatible replacements
    for op, replacement in operator_replacements.items():
        name = name.replace("operator" + op, "operator_" + replacement)

    # name = name.replace("public:", "")
    # name = name.replace("protected:", "")
    # name = name.replace("private:", "")
    # name = name.replace("~", "destructor_")
    # name = name.replace("*", "ptr_")
    # name = name.replace("<", "t_")
    # name = name.replace(">", "t_")

    # name = "_".join(filter(None, bad_c_name_pattern(name).split(name)))

    return name
