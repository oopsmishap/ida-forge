from types import SimpleNamespace

from forge.api import domain


def test_try_domain_method_preserves_valid_none_without_fallback():
    domain.clear_fallback_records()
    database = SimpleNamespace(bytes=SimpleNamespace(get_cstring_at=lambda _ea: None))

    handled, result = domain.try_domain_method(
        database,
        "bytes",
        "get_cstring_at",
        0x401000,
        capability="bytes.test",
        unavailable_reason="unavailable",
        failure_reason="failed",
    )

    assert handled is True
    assert result is None
    assert domain.fallback_records() == ()


def test_try_domain_method_records_unavailable_once():
    domain.clear_fallback_records()

    handled, result = domain.try_domain_method(
        None,
        "bytes",
        "get_cstring_at",
        0x401000,
        capability="bytes.test",
        unavailable_reason="unavailable",
        failure_reason="failed",
    )

    assert (handled, result) == (False, None)
    records = domain.fallback_records()
    assert len(records) == 1
    assert records[0].capability == "bytes.test"
    assert records[0].reason == "unavailable"


def test_try_domain_method_records_operation_failure_once():
    domain.clear_fallback_records()

    def fail(_ea):
        raise RuntimeError("unsupported")

    database = SimpleNamespace(bytes=SimpleNamespace(get_cstring_at=fail))
    handled, result = domain.try_domain_method(
        database,
        "bytes",
        "get_cstring_at",
        0x401000,
        capability="bytes.test",
        unavailable_reason="unavailable",
        failure_reason="failed",
        exceptions=(Exception,),
    )

    assert (handled, result) == (False, None)
    records = domain.fallback_records()
    assert len(records) == 1
    assert records[0].reason == "failed"


def test_try_domain_call_preserves_valid_none_without_fallback():
    domain.clear_fallback_records()

    handled, result = domain.try_domain_call(
        lambda: None,
        capability="bytes.test",
        failure_reason="failed",
    )

    assert handled is True
    assert result is None
    assert domain.fallback_records() == ()
