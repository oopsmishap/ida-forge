from __future__ import annotations

from types import SimpleNamespace

import forge_api


def test_functions_uses_domain_get_all(monkeypatch):
    rows = [
        SimpleNamespace(name="b", start_ea=20, end_ea=30),
        SimpleNamespace(name="a", start_ea=10, end_ea=15),
    ]
    database = SimpleNamespace(functions=SimpleNamespace(get_all=lambda: rows))
    monkeypatch.setattr(forge_api, "_require_ida", lambda: None)
    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: database)

    assert forge_api.functions() == [
        {"name": "a", "start_ea": 10, "end_ea": 15},
        {"name": "b", "start_ea": 20, "end_ea": 30},
    ]


def test_functions_discards_domain_rows_without_integer_bounds(monkeypatch):
    rows = [
        SimpleNamespace(name="missing", start_ea=None, end_ea=20),
        SimpleNamespace(name="bool", start_ea=True, end_ea=30),
        SimpleNamespace(name="bad_end", start_ea=5, end_ea="10"),
        SimpleNamespace(name="valid", start_ea=10, end_ea=20),
    ]
    database = SimpleNamespace(functions=SimpleNamespace(get_all=lambda: rows))
    monkeypatch.setattr(forge_api, "_require_ida", lambda: None)
    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: database)

    assert forge_api.functions() == [{"name": "valid", "start_ea": 10, "end_ea": 20}]
def test_functions_discards_reversed_domain_bounds(monkeypatch):
    rows = [
        SimpleNamespace(name="reversed", start_ea=30, end_ea=20),
        SimpleNamespace(name="valid", start_ea=10, end_ea=20),
    ]
    database = SimpleNamespace(functions=SimpleNamespace(get_all=lambda: rows))
    monkeypatch.setattr(forge_api, "_require_ida", lambda: None)
    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: database)

    assert forge_api.functions() == [{"name": "valid", "start_ea": 10, "end_ea": 20}]


def test_functions_falls_back_when_domain_enumeration_missing(monkeypatch):
    calls = []
    database = SimpleNamespace(functions=SimpleNamespace())
    function = SimpleNamespace(start_ea=10, end_ea=15)
    sdk = SimpleNamespace(
        Functions=lambda: [10],
        get_func=lambda ea: function,
        get_func_name=lambda ea: "sdk_function",
    )
    monkeypatch.setattr(forge_api, "_require_ida", lambda: None)
    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: database)
    monkeypatch.setattr(forge_api, "_sdk_fallback", lambda *args: calls.append(args))
    import sys
    monkeypatch.setitem(sys.modules, "ida_funcs", sdk)

    assert forge_api.functions() == [{"name": "sdk_function", "start_ea": 10, "end_ea": 15}]
    assert calls == [("functions.enumeration", "ida-domain function enumeration unavailable")]
