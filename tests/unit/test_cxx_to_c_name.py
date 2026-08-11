"""Table tests for forge.util.cxx_to_c_name (operator demangling)."""

from __future__ import annotations

import pytest

from forge.util.cxx_to_c_name import (
    demangled_name_to_c_str,
    sanitize_c_identifier,
)


@pytest.mark.parametrize(
    "demangled, expected",
    [
        ("operator<<=", "operator_left_shift_assign"),
        ("operator>>=", "operator_right_shift_assign"),
        ("operator new[]", "operator_new_array"),
        ("operator delete[]", "operator_delete_array"),
        ("operator!=", "operator_neq"),
        ("operator+=", "operator_plus_assign"),
        ("operator-=", "operator_minus_assign"),
        ("operator*=", "operator_mul_assign"),
        ("operator/=", "operator_div_assign"),
        ("operator%=", "operator_modulo_div_assign"),
        ("operator|=", "operator_or_assign"),
        ("operator&=", "operator_and_assign"),
        ("operator^=", "operator_xor_assign"),
        ("operator++", "operator_inc"),
        ("operator--", "operator_ptr"),
        ("operator->", "operator_ref"),
        ("operator[]", "operator_idx"),
        ("operator&&", "operator_land"),
        ("operator||", "operator_lor"),
        ("operator<<", "operator_left_shift"),
        ("operator>>", "operator_right_shift"),
        ("operator<=", "operator_less_equal"),
        ("operator>=", "operator_greater_equal"),
        ("operator==", "operator_eq"),
        ("operator()", "operator_call"),
        ("operator new", "operator_new"),
        ("operator delete", "operator_delete"),
        ('operator""', "operator_literal"),
        ("operator=", "operator_assign"),
        ("operator*", "operator_star"),
        ("operator!", "operator_lnot"),
        ("operator&", "operator_and"),
        ("operator|", "operator_or"),
        ("operator^", "operator_xor"),
        ("operator<", "operator_less"),
        ("operator>", "operator_greater"),
        ("operator+", "operator_add"),
        ("operator-", "operator_sub"),
        ("operator/", "operator_div"),
        ("operator%", "operator_modulo"),
        ("operator~", "operator_not"),
    ],
)
def test_demangled_name_to_c_str_operator_table(demangled, expected):
    assert demangled_name_to_c_str(demangled) == expected


@pytest.mark.parametrize(
    "name, expected",
    [
        ("a::b::c", "a_b_c"),
        ("Foo<T>::bar", "Foo_T_bar"),
        ("int; *&", "int"),
        ("", "symbol"),
        ("...", "symbol"),
        ("123abc", "_123abc"),
        ("__cxx_global_var_init", "cxx_global_var_init"),
    ],
)
def test_sanitize_c_identifier_table(name, expected):
    assert sanitize_c_identifier(name) == expected


def test_sanitize_c_identifier_custom_fallback():
    assert sanitize_c_identifier("!!!", fallback="unnamed") == "unnamed"


def test_namespace_function_round_trip():
    assert demangled_name_to_c_str("ns::foo()") == "ns_foo"