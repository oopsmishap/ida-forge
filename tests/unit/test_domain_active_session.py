from __future__ import annotations

import sys
import types

import pytest

from forge.api import domain


class _Boxed:
    """Minimal double of the ida-domain ``Database`` session lifecycle."""

    def __init__(self, tag):
        self.tag = tag

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def _install_fake_domain(monkeypatch, *, with_current=None):
    """Install a per-test ida_domain whose open() is observable.

    ``open(path=...)`` (library open) returns a *stable* path handle used by
    forge's ``open_database``.  ``open()`` with no args (path-less current-DB
    snapshot) returns a fresh wrapper each call, mirroring the SDK behaviour
    where ``Database.open()`` allocates a fresh hooked wrapper.
    """

    class FakeDatabase:
        count = 0
        # path-bearing opens reuse one stable handle so the cache can be
        # observed; path-less opens always allocate a fresh snapshot.
        repository = {}

        @classmethod
        def open(cls, *args, **kwargs):
            path = args[0] if args else kwargs.get("path")
            if path:
                handle = cls.repository.get(path)
                if handle is None:
                    handle = _Boxed(f"path:{path}")
                    cls.repository[path] = handle
                return handle
            cls.count += 1
            return _Boxed("snapshot")

    module = types.ModuleType("ida_domain")
    module.Database = FakeDatabase
    monkeypatch.setitem(sys.modules, "ida_domain", module)
    return FakeDatabase


@pytest.fixture(autouse=True)
def _isolate_active_cache():
    domain.clear_active_database()
    yield
    domain.clear_active_database()


def test_reuses_explicitly_opened_handle_instead_of_resnapshotting(monkeypatch):
    """After ``open_database``, current_database serves the same handle."""
    fake = _install_fake_domain(monkeypatch)

    domain.open_database("sample.exe", save_on_close=True)
    assert fake.count == 0  # only the library open happened, no fresh snapshot

    first = domain.current_database()
    assert first.tag == "path:sample.exe"
    second = domain.current_database()
    assert second is first  # reused, not re-snapshot
    assert fake.count == 0  # the cache prevented path-less re-open


def test_no_reuse_from_unrelated_path_less_open(monkeypatch):
    """Reuse applies only after an explicit forge open; path-less stays fresh."""
    _install_fake_domain(monkeypatch)

    # No explicit open_database: current_database must reflect a live snapshot
    # each call (GUI-mode style), not a cached stale object.
    a = domain.current_database()
    b = domain.current_database()
    assert isinstance(a, _Boxed)
    assert a.tag == "snapshot"
    assert b is not a


def test_cache_invalidated_when_domain_module_replaced(monkeypatch):
    """A replaced ida_domain module must not let a stale handle through."""
    _install_fake_domain(monkeypatch)
    domain.open_database("sample.exe")
    cached = domain.current_database()
    assert cached.tag == "path:sample.exe"

    # Simulate process teardown/reload: swap in a brand-new module object.
    other_module = types.ModuleType("ida_domain")
    monkeypatch.setitem(sys.modules, "ida_domain", other_module)

    # The previous module object no longer matches -> cache drops, and since
    # the new module's Database is missing entirely, required=False is None.
    assert domain.current_database(required=False) is None
    assert domain._active_session.handle is None
    assert domain._active_session.module is None


def test_database_session_clears_cache_on_normal_close(monkeypatch):
    """After a database_session body, no closed handle is served."""
    _install_fake_domain(monkeypatch)

    with domain.database_session("sample.exe", save_on_close=True) as session:
        assert domain.current_database() is session
    # Session closed; the cache must be gone even though the module persists.
    assert domain._active_session.handle is None
    assert domain.current_database().tag == "snapshot"


def test_database_session_clears_cache_on_body_exception(monkeypatch):
    _install_fake_domain(monkeypatch)

    with pytest.raises(RuntimeError, match="body boom"), domain.database_session("sample.exe"):
        raise RuntimeError("body boom")
    assert domain._active_session.handle is None


def test_open_database_failure_invalidates_prior_handle(monkeypatch):
    """A failed open never leaves an older handle cached."""
    _install_fake_domain(monkeypatch)
    domain.open_database("sample.exe")
    assert domain._active_session.handle is not None

    class Exploding:
        @staticmethod
        def open(*args, **kwargs):
            raise ValueError("cannot open")

    exploding_module = types.ModuleType("ida_domain")
    exploding_module.Database = Exploding
    monkeypatch.setitem(sys.modules, "ida_domain", exploding_module)

    with pytest.raises(domain.DomainUnavailable, match="could not open"):
        domain.open_database("other.exe")
    assert domain._active_session.handle is None
    assert domain._active_session.module is None


def test_clear_active_database_drops_cache(monkeypatch):
    _install_fake_domain(monkeypatch)
    domain.open_database("sample.exe")
    assert domain.current_database().tag == "path:sample.exe"

    domain.clear_active_database()
    assert domain.current_database().tag == "snapshot"
