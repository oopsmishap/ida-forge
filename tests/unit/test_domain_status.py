import forge_api
from forge.api import domain


def test_domain_status_returns_stable_fallback_snapshot(monkeypatch):
    domain.clear_fallback_records()
    domain.sdk_fallback("test.status", "initial")

    status = forge_api.domain_status()
    assert set(status) == {
        "available",
        "python",
        "python_minimum",
        "ida_minimum",
        "ida_domain",
        "preferred",
        "fallbacks",
        "fallback_summary",
        "fallback_counts",
        "fallback_clear_requested",
        "fallbacks_cleared",
    }
    assert status["preferred"] == "ida-domain"
    assert isinstance(status["python"], str)
    assert status["ida_minimum"] == "9.1"
    assert isinstance(status["ida_domain"], dict)
    assert isinstance(status["ida_domain"]["available"], bool)
    assert status["fallbacks"] == [{"capability": "test.status", "reason": "initial"}]
    assert status["fallback_summary"] == {
        "test": [{"capability": "test.status", "reason": "initial"}]
    }
    assert status["fallback_counts"] == {"test": 1}
    assert status["fallback_clear_requested"] is False
    assert status["fallbacks_cleared"] == 0

    cleared = forge_api.domain_status(clear_fallbacks=True)
    assert cleared["fallback_clear_requested"] is True
    assert cleared["fallbacks_cleared"] == 1
    assert forge_api.domain_status()["fallbacks"] == []

def test_capability_snapshot_handles_missing_domain_metadata(monkeypatch):
    domain.clear_capability_cache()
    monkeypatch.setattr(domain, "available", lambda: False)
    monkeypatch.setattr(
        domain.metadata,
        "version",
        lambda _name: (_ for _ in ()).throw(domain.metadata.PackageNotFoundError()),
    )
    snapshot = domain.capability_snapshot()

    assert snapshot["ida_domain"]["available"] is False
    assert snapshot["ida_domain"]["compatible"] is False
    assert snapshot["ida_domain"]["health"] == "unavailable"
    assert snapshot["ida_domain"]["version"] is None
    assert snapshot["ida_domain"]["compatibility_error"] == "ida-domain version metadata unavailable"
    assert snapshot["ida_minimum"] == "9.1"

def test_capability_snapshot_reports_domain_import_failure(monkeypatch):
    domain.clear_capability_cache()
    error = ImportError("missing dependency")

    def fail_import(name):
        if name == "ida_domain":
            raise error
        raise AssertionError(name)

    monkeypatch.setattr(domain, "import_module", fail_import)
    monkeypatch.setattr(domain, "available", lambda: False)
    monkeypatch.setattr(domain.metadata, "version", lambda _name: "0.5.1")

    snapshot = domain.capability_snapshot()

    assert snapshot["ida_domain"]["available"] is False
    assert snapshot["ida_domain"]["compatible"] is True
    assert snapshot["ida_domain"]["availability_error"] == "ImportError: missing dependency"


def test_capability_snapshot_reports_supported_domain_version(monkeypatch):
    domain.clear_capability_cache()
    monkeypatch.setattr(domain, "available", lambda: True)
    monkeypatch.setattr(domain.metadata, "version", lambda _name: "0.5.1")
    snapshot = domain.capability_snapshot()
    assert snapshot["ida_domain"] == {
        "available": True,
        "version": "0.5.1",
        "compatible": True,
        "health": "available",
    }

def test_capability_snapshot_reports_invalid_domain_version(monkeypatch):
    domain.clear_capability_cache()
    monkeypatch.setattr(domain, "available", lambda: True)
    monkeypatch.setattr(domain.metadata, "version", lambda _name: "development")
    snapshot = domain.capability_snapshot()
    assert snapshot["ida_domain"]["compatible"] is False
    assert snapshot["ida_domain"]["compatibility_error"] == "ida-domain version metadata is invalid"


def test_capability_snapshot_reports_old_domain_version(monkeypatch):
    domain.clear_capability_cache()
    monkeypatch.setattr(domain, "available", lambda: True)
    monkeypatch.setattr(domain.metadata, "version", lambda _name: "0.4.9")
    snapshot = domain.capability_snapshot()
    assert snapshot["ida_domain"]["compatible"] is False
    assert snapshot["ida_domain"]["health"] == "incompatible"
    assert "below supported minimum" in snapshot["ida_domain"]["compatibility_error"]

def test_capability_snapshot_cache_requires_explicit_reset(monkeypatch):
    domain.clear_capability_cache()
    calls = []

    def version(_name):
        calls.append("version")
        return "0.5.1"

    monkeypatch.setattr(domain.metadata, "version", version)
    monkeypatch.setattr(domain, "available", lambda: True)
    first = domain.capability_snapshot()
    second = domain.capability_snapshot()
    assert first == second
    assert calls == ["version"]

    domain.clear_capability_cache()
    domain.capability_snapshot()
    assert calls == ["version", "version"]


def test_capability_snapshot_returns_detached_cached_data():
    domain.clear_capability_cache()
    first = domain.capability_snapshot()
    first["ida_domain"]["version"] = "mutated"
    assert domain.capability_snapshot()["ida_domain"]["version"] != "mutated"

def test_domain_status_does_not_open_database(monkeypatch):
    called = []
    monkeypatch.setattr(domain, "database", lambda **kwargs: called.append(kwargs))
    domain.clear_fallback_records()

    status = forge_api.domain_status()

    assert isinstance(status["available"], bool)
    assert called == []


def test_domain_availability_translates_import_type_error(monkeypatch):
    monkeypatch.setattr(
        domain,
        "import_module",
        lambda _name: (_ for _ in ()).throw(TypeError("bad init")),
    )

    assert domain.available() is False


def test_sdk_fallback_deduplicates_exact_records():
    domain.clear_fallback_records()
    first = domain.sdk_fallback("cap", "reason")
    second = domain.sdk_fallback("cap", "reason")
    domain.sdk_fallback("cap", "other")
    domain.sdk_fallback("other-cap", "reason")

    assert first == second
    assert domain.fallback_records() == (
        domain.SdkFallback("cap", "reason"),
        domain.SdkFallback("cap", "other"),
        domain.SdkFallback("other-cap", "reason"),
    )

def test_fallback_records_returns_isolated_lifecycle_snapshot():
    domain.clear_fallback_records()
    domain.sdk_fallback("first", "initial")
    snapshot = domain.fallback_records()

    domain.sdk_fallback("second", "later")
    assert snapshot == (domain.SdkFallback("first", "initial"),)

    domain.clear_fallback_records()
    domain.sdk_fallback("third", "after clear")
    assert snapshot == (domain.SdkFallback("first", "initial"),)
    assert domain.fallback_records() == (domain.SdkFallback("third", "after clear"),)


def test_domain_status_returns_detached_fallback_dicts():
    domain.clear_fallback_records()
    domain.sdk_fallback("meta", "reason")

    status = forge_api.domain_status()
    status["fallbacks"][0]["reason"] = "mutated"
    status["fallbacks"].append({"capability": "extra", "reason": "extra"})

    assert forge_api.domain_status()["fallbacks"] == [
        {"capability": "meta", "reason": "reason"}
    ]


def test_domain_status_fallback_summary_is_detached_and_clears_with_records():
    domain.clear_fallback_records()
    domain.sdk_fallback("types.named_types", "missing")
    status = forge_api.domain_status()
    status["fallback_summary"]["types"][0]["reason"] = "mutated"
    assert forge_api.domain_status()["fallback_summary"] == {
        "types": [{"capability": "types.named_types", "reason": "missing"}]
    }
    cleared = forge_api.domain_status(clear_fallbacks=True)
    assert cleared["fallback_summary"]["types"]
    assert forge_api.domain_status()["fallback_summary"] == {}

def test_domain_status_can_clear_fallbacks_after_snapshot():
    domain.clear_fallback_records()
    domain.sdk_fallback("lifecycle", "one")

    status = forge_api.domain_status(clear_fallbacks=True)

    assert status["fallbacks"] == [{"capability": "lifecycle", "reason": "one"}]
    assert forge_api.domain_status()["fallbacks"] == []


def test_domain_status_default_preserves_fallbacks():
    domain.clear_fallback_records()
    domain.sdk_fallback("lifecycle", "preserve")

    first = forge_api.domain_status()
    second = forge_api.domain_status()

    assert first["fallbacks"] == second["fallbacks"] == [
        {"capability": "lifecycle", "reason": "preserve"}
    ]

def test_domain_status_exposes_detached_fallback_counts():
    domain.clear_fallback_records()
    domain.sdk_fallback("types.named_types", "missing")
    domain.sdk_fallback("types.named_types", "unsupported")
    domain.sdk_fallback("storage.netnode", "missing")

    status = forge_api.domain_status()

    assert status["fallback_counts"] == {"types": 2, "storage": 1}
    status["fallback_counts"]["types"] = 99
    assert forge_api.domain_status()["fallback_counts"] == {"types": 2, "storage": 1}
