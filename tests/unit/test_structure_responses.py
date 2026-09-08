import forge_api


def test_structure_read_responses_are_detached_from_store(monkeypatch):
    member = type("Member", (), {
        "offset": 0x10, "name": "value", "enabled": True,
        "is_array": False, "comment": "", "origin": 0, "score": 1,
        "tinfo": type("TInfo", (), {
            "dstr": lambda self: "u32",
            "get_size": lambda self: 4,
        })(),
    })()
    relationship = type("Rel", (), {
        "parent_structure_name": "Detached",
        "child_structure_name": "Child",
        "parent_member_offset": 0x10,
        "parent_member_name": "value",
        "relation_kind": "pointer",
    })()
    structure = type("Structure", (), {
        "name": "Detached", "main_offset": 0, "created_type_name": None,
        "pack": 1, "members": [member], "collisions": [],
        "child_relationships": [relationship],
    })()
    monkeypatch.setattr(forge_api, "_resolve_structure", lambda *_args, **_kwargs: structure)

    response = forge_api.get_structure("Detached")
    response["members"][0]["name"] = "mutated"
    response["collisions"].append((0x20, 0x20))
    response["child_relationships"].append({"child_structure_name": "Fake"})
    assert forge_api.get_structure("Detached")["members"][0]["name"] == "value"
    assert forge_api.get_structure("Detached")["collisions"] == []
    assert len(forge_api.get_structure("Detached")["child_relationships"]) == 1
