import forge_api


def test_scan_sites_returns_detached_rows(monkeypatch):
    rows = [{"func_ea": 0x401000, "var": "arg0", "ea": 0x402000, "type": "u32", "member_offset": 4}]
    target = type("Target", (), {"scan_sites_rows": rows})()
    monkeypatch.setattr(forge_api, "_resolve_structure", lambda *_args, **_kwargs: target)

    result = forge_api.scan_sites("S")
    result[0]["var"] = "mutated"
    result.append({"func_ea": 0x403000})

    assert rows[0]["var"] == "arg0"
    assert forge_api.scan_sites("S") == [rows[0]]
