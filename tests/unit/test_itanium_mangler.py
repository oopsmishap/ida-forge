"""Golden-corpus tests for forge.util.itanium_mangler.

The module is a port of Classy's Itanium concept mangler. This suite pins
its stable output for the supported surface and asserts the documented
``NotImplementedError`` boundaries (templates, function pointers,
r-value refs). The mangled strings follow the port's (ABI-compatible)
conventions; deviations from the ABI would show up here as corpus edits,
which is exactly the regression guard this file exists for.
"""

from __future__ import annotations

import pytest

from forge.util import itanium_mangler as mangler


@pytest.mark.parametrize(
    "signature, kwargs, expected",
    [
        # no-arg / void
        ("foo()", {}, "_Z3foov"),
        ("foo(void)", {}, "_Z3foov"),
        # scalars
        ("foo(int)", {}, "_Z3fooi"),
        ("foo(bool, short, double)", {}, "_Z3foobsd"),
        ("foo(long long, unsigned int)", {}, "_Z3fooxj"),
        ("foo(unsigned long long)", {}, "_Z3fooy"),
        # pointers and references
        ("foo(char*)", {}, "_Z3fooPc"),
        ("foo(wchar_t*)", {}, "_Z3fooPw"),
        ("foo(int&)", {}, "_Z3fooRi"),
        ("foo(const int)", {}, "_Z3fooi"),
        ("foo(char const*)", {}, "_Z3fooPKc"),
        ("foo(const char * const)", {}, "_Z3fooPKc"),
        ("foo(int, const char*)", {}, "_Z3fooiPKc"),
        # namespaces and classes
        ("ns::foo()", {}, "_ZN2ns3fooEv"),
        ("ns::Foo::Foo()", {"ctor_type": 1}, "_ZN2ns3FooC1Ev"),
        ("ns::Foo::~Foo()", {"dtor_type": 0}, "_ZN2ns3FooD0Ev"),
        ("ns::Foo::bar() const", {}, "_ZNK2ns3Foo3barEv"),
        # substitution reuse
        ("foo(SomeClass, SomeClass)", {}, "_Z3foo9SomeClassS_"),
    ],
)
def test_mangle_function_golden_corpus(signature, kwargs, expected):
    assert mangler.mangle_function(signature, **kwargs) == expected


@pytest.mark.parametrize(
    "signature",
    [
        "foo(T<int>)",  # templates
        "foo(int(*)(char))",  # function pointers
        "foo(int&&)",  # r-value references
    ],
)
def test_mangle_function_rejects_unsupported_constructs(signature):
    with pytest.raises(NotImplementedError):
        mangler.mangle_function(signature)


def test_mangle_function_requires_argument_braces():
    with pytest.raises(ValueError):
        mangler.mangle_function("not_a_signature")


def test_mangle_function_rejects_const_on_free_function():
    with pytest.raises(ValueError):
        mangler.mangle_function("foo() const")


@pytest.mark.parametrize(
    "txt, expected",
    [
        ("int", "i"),
        ("void", "v"),
        ("MyClass", "7MyClass"),
        ("a::b", "N1a1bE"),
        ("a::b::c", "N1a1b1cE"),
    ],
)
def test_mangle_type(txt, expected):
    assert mangler.mangle_type(txt) == expected


def test_mangle_type_without_prefix_suffix():
    assert mangler.mangle_type("a::b", pre_and_postfix=False) == "1a1b"


@pytest.mark.parametrize("seqid, expected", [(0, "S_"), (1, "S0_"), (2, "S1_")])
def test_encode_seqid(seqid, expected):
    assert mangler.encode_seqid(seqid) == expected


def test_fix_multi_seg_types_mutates_list_in_place():
    segments = ["unsigned", "long", "long"]
    assert mangler.fix_multi_seg_types(segments) is None
    assert segments == ["unsigned_long_long"]


def test_apply_typedefs_expands_in_place():
    segments = ["MyInt", "foo"]
    mangler.apply_typedefs(segments, {"MyInt": "unsigned int"})
    assert segments == ["unsigned", "int", "foo"]


def test_check_identifier_accepts_alphanumeric_underscores():
    assert mangler.check_identifier("foo_1")
    assert mangler.check_identifier("_Z12")


def test_brace_split_splits_on_whitespace():
    assert mangler.brace_split("a b  c") == ["a", "b", "c"]