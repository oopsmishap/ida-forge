from __future__ import annotations

import pytest

from forge.features.templated_types.templated_types import TemplatedTypes


def test_reload_types_and_render_decl_from_custom_toml(tmp_path):
    toml_file = tmp_path / "templated_types.toml"
    toml_file.write_text(
        """
[Vector]
types = ["T"]
base_name = "Vector_{1}"
struct = "struct Vector_{1} {{ {0} *data; }};"
""".strip(),
        encoding="utf-8",
    )

    templated_types = TemplatedTypes()
    templated_types.set_file_path(str(toml_file))

    assert templated_types.file_name == "templated_types.toml"
    assert templated_types.keys == ["Vector"]

    name, decl = templated_types.get_decl_str("Vector", ("int", "Int"))
    assert name == "Vector_Int"
    assert decl == "struct Vector_Int { int *data; };"


def test_get_decl_str_returns_none_for_wrong_argument_count(tmp_path):
    toml_file = tmp_path / "templated_types.toml"
    toml_file.write_text(
        """
[Pair]
types = ["L", "R"]
base_name = "Pair_{1}_{3}"
struct = "struct Pair_{1}_{3} {{ {0} left; {2} right; }};"
""".strip(),
        encoding="utf-8",
    )

    templated_types = TemplatedTypes()
    templated_types.set_file_path(str(toml_file))

    assert templated_types.get_decl_str("Pair", ("int", "LeftOnly")) is None



def test_get_decl_str_returns_none_for_unknown_key(tmp_path):
    toml_file = tmp_path / "templated_types.toml"
    toml_file.write_text(
        """
[Vector]
types = ["T"]
base_name = "Vector_{1}"
struct = "struct Vector_{1} {{ {0} *data; }};"
""".strip(),
        encoding="utf-8",
    )

    templated_types = TemplatedTypes()
    templated_types.set_file_path(str(toml_file))

    assert templated_types.get_decl_str("Missing", ("int", "Int")) is None



def test_reload_types_returns_false_for_empty_path():
    templated_types = TemplatedTypes()
    templated_types.file_path = ""

    assert templated_types.reload_types() is False



def test_reload_types_raises_for_invalid_toml(tmp_path):
    toml_file = tmp_path / "templated_types.toml"
    toml_file.write_text("[Broken\nvalue = 1\n", encoding="utf-8")

    templated_types = TemplatedTypes()
    templated_types.file_path = str(toml_file)

    with pytest.raises(Exception):
        templated_types.reload_types()
