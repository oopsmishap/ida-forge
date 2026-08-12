import re


def _replace_cpp_operator_names(name):
    replacements = (
        # longest-first so compound operators win over their prefixes
        ("<<=", "left_shift_assign_"),
        (">>=", "right_shift_assign_"),
        ("<=>", "spaceship_"),
        ("co_await", "co_await_"),
        ("->*", "arrow_star_"),
        ("new[]", "new_array_"),
        ("delete[]", "delete_array_"),
        ("!=", "neq_"),
        ("+=", "plus_assign_"),
        ("-=", "minus_assign_"),
        ("*=", "mul_assign_"),
        ("/=", "div_assign_"),
        ("%=", "modulo_div_assign_"),
        ("|=", "or_assign_"),
        ("&=", "and_assign_"),
        ("^=", "xor_assign_"),
        ("++", "inc_"),
        ("--", "ptr_"),
        ("->", "ref_"),
        ("[]", "idx_"),
        ("&&", "land_"),
        ("||", "lor_"),
        ("<<", "left_shift_"),
        (">>", "right_shift_"),
        ("<=", "less_equal_"),
        (">=", "greater_equal_"),
        ("==", "eq_"),
        ("()", "call_"),
        ("new", "new_"),
        ("delete", "delete_"),
        ('""', "literal_"),
        ("=", "assign_"),
        ("*", "star_"),
        ("!", "lnot_"),
        ("&", "and_"),
        ("|", "or_"),
        ("^", "xor_"),
        ("<", "less_"),
        (">", "greater_"),
        ("+", "add_"),
        ("-", "sub_"),
        ("/", "div_"),
        ("%", "modulo_"),
        ("~", "not_"),
    )

    for operator, replacement in replacements:
        name = name.replace(f"operator{operator}", f"operator_{replacement}")
        name = name.replace(f"operator {operator}", f"operator_{replacement}")
    return name


def sanitize_c_identifier(name, fallback="symbol"):
    sanitized = name.replace("::", "_")
    sanitized = re.sub(r"[^0-9A-Za-z_]+", "_", sanitized)
    sanitized = re.sub(r"_+", "_", sanitized).strip("_")
    if not sanitized:
        sanitized = fallback
    if sanitized[0].isdigit():
        sanitized = f"_{sanitized}"
    return sanitized


def demangled_name_to_c_str(name):
    return sanitize_c_identifier(_replace_cpp_operator_names(name))
