import forge_api


def test_refresh_types_response_has_documented_keys(monkeypatch):
    monkeypatch.setattr(forge_api, "_require_ida", lambda: None)
    monkeypatch.setattr(forge_api, "_mirror_store", lambda: type("Mirror", (), {"items": lambda self: []})())
    monkeypatch.setattr(forge_api, "_mark_dirty", lambda: None)

    result = forge_api.refresh_types()

    assert result == {"updated": [], "unchanged": [], "renamed": []}


def test_refresh_types_processes_baseline_names_in_sorted_order(monkeypatch):
    baseline = {"Zulu": {"hash": "z"}, "Alpha": {"hash": "a"}}
    seen = []
    monkeypatch.setattr(forge_api, "_require_ida", lambda: None)
    monkeypatch.setattr(forge_api, "_mirror_store", lambda: baseline)
    monkeypatch.setattr(
        forge_api,
        "_idb_udt_snapshot",
        lambda name: (seen.append(name) or (baseline[name]["hash"], [])),
    )
    monkeypatch.setattr(forge_api, "_mark_dirty", lambda: None)

    result = forge_api.refresh_types()
    assert seen == ["Alpha", "Zulu"]
    assert result == {"updated": [], "unchanged": ["Alpha", "Zulu"], "renamed": []}
