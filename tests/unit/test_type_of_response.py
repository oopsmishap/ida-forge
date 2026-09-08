import forge_api


def test_type_of_domain_members_are_detached(monkeypatch):
    member = type("Member", (), {
        "offset": 4,
        "size": 8,
        "name": "field",
        "type": type("Type", (), {"dstr": lambda self: "u64"})(),
    })()
    tinfo = type(
        "TInfo",
        (),
        {
            "is_udt": lambda self: True,
            "is_ptr": lambda self: False,
            "is_func": lambda self: False,
            "dstr": lambda self: "struct S { u64 field; }",
        },
    )()
    details = type("Details", (), {"name": "S", "declaration": "struct S { u64 field; }", "size": 8})()
    db = type("DB", (), {})()

    def dispatch(_db, namespace, method, *args, **kwargs):
        if (namespace, method) == ("types", "get_by_name"):
            return True, tinfo
        if (namespace, method) == ("types", "get_details"):
            return True, details
        if (namespace, method) == ("types", "get_udt_members"):
            return True, [member]
        raise AssertionError((namespace, method))

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: db)
    monkeypatch.setattr(forge_api, "_try_domain_method", dispatch)
    result = forge_api.type_of("S")
    result["members"][0]["name"] = "mutated"
    result["members"].append({"name": "extra"})

    fresh = forge_api.type_of("S")
    assert fresh["members"] == [{"offset": 4, "size": 8, "name": "field", "type": "u64"}]


def test_type_of_domain_member_failure_uses_sdk_fallback(monkeypatch):
    tinfo = type("TInfo", (), {
        "is_udt": lambda self: True,
        "is_ptr": lambda self: False,
        "is_func": lambda self: False,
        "dstr": lambda self: "struct S {}",
    })()
    details = type("Details", (), {"name": "S", "declaration": "struct S {}", "size": 0})()
    db = object()
    calls = []

    def dispatch(_db, namespace, method, *args, **kwargs):
        calls.append((namespace, method))
        if method == "get_by_name":
            return True, tinfo
        if method == "get_details":
            return True, details
        if method == "get_udt_members":
            return False, None
        raise AssertionError((namespace, method))

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: db)
    monkeypatch.setattr(forge_api, "_try_domain_method", dispatch)
    monkeypatch.setattr(forge_api, "_sdk_fallback", lambda *args, **kwargs: None)

    class FakeTinfo:
        def get_named_type(self, _idati, name):
            return name == "S"
        def is_udt(self):
            return True
        def get_udt_details(self, _data):
            return True
        def dstr(self):
            return "struct S {}"
        def get_size(self):
            return 0

    import ida_typeinf
    monkeypatch.setattr(ida_typeinf, "tinfo_t", FakeTinfo)
    monkeypatch.setattr(ida_typeinf, "get_idati", lambda: object())
    monkeypatch.setattr(ida_typeinf, "udt_type_data_t", list)

    result = forge_api.type_of("S")
    assert result == {"name": "S", "type": "struct S {}", "size": 0, "kind": "struct", "members": []}
    assert calls[-1] == ("types", "get_udt_members")
