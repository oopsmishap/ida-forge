"""Lazy IDA Domain API boundary for ida-forge.

The project prefers ``ida_domain`` for database operations.  This module keeps
that dependency lazy so ``import forge_api`` and the headless unit suite remain
usable without IDA or the optional ``ida-domain`` package.

SDK imports belong in callers only when a capability is not exposed by the
Domain API.  Such callers should document the missing domain capability and
use :func:`sdk_fallback` to make the exception explicit.
"""

from __future__ import annotations

import copy
import platform
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import import_module, metadata
from typing import Any

from packaging.version import InvalidVersion, Version

MIN_PYTHON = "3.9"
MIN_IDA = "9.1"
DOMAIN_DISTRIBUTION = "ida-domain"


class DomainUnavailable(RuntimeError):
    """Raised when an IDA Domain operation is requested outside an IDA session."""


@dataclass
class _CapabilityCache:
    snapshot: dict[str, Any] | None = None


_capability_cache = _CapabilityCache()


# Reuse cache for the Domain handle this process opened explicitly through
# :func:`open_database` / :func:`database_session` (library mode).  Hot
# internal callers ask for the current database on nearly every operation; the
# SDK's ``Database.open()`` hands back a *fresh* hooked wrapper each time, so
# without reuse every such lookup re-allocates and re-hooks a wrapper against
# the same loaded IDB.  The handle is served back only while it is still
# produced by the *same* ``ida_domain`` module object (identity guard), so a
# replaced/removed module (test isolation, reload) can never hand out a stale
# external handle.  The cache is never engaged for path-less GUI snapshots:
# it is populated exclusively by an explicit forge open.  Like the capability
# cache above, state lives in a mutable holder so updates never rebind module
# globals.
@dataclass
class _ActiveSession:
    handle: Any | None = None
    module: Any | None = None


_active_session = _ActiveSession()


def clear_active_database() -> None:
    """Drop the cached active-session handle, if any.

    Callers that observe an out-of-band database lifecycle change (a fresh
    :func:`open_database`, a :func:`database_session` close, a process reload)
    use this to guarantee no stale handle is ever served.
    """
    _active_session.handle = None
    _active_session.module = None


def capability_snapshot() -> dict[str, Any]:
    """Return detached runtime and optional Domain package diagnostics."""
    if _capability_cache.snapshot is None:
        availability_error = None
        available_flag = available()
        if not available_flag:
            try:
                import_module("ida_domain")
            except (ImportError, AttributeError, RuntimeError, TypeError, OSError) as exc:
                availability_error = f"{type(exc).__name__}: {exc}"
        try:
            domain_version = metadata.version(DOMAIN_DISTRIBUTION)
        except (metadata.PackageNotFoundError, TypeError, ValueError):
            domain_version = None
        compatible = False
        compatibility_error = None
        if domain_version is None:
            compatibility_error = "ida-domain version metadata unavailable"
        else:
            try:
                compatible = Version(domain_version) >= Version("0.5.0")
                if not compatible:
                    compatibility_error = "ida-domain version is below supported minimum 0.5.0"
            except InvalidVersion:
                compatibility_error = "ida-domain version metadata is invalid"
        health = "available" if available_flag and compatible else ("incompatible" if available_flag else "unavailable")
        ida_domain = {
            "available": available_flag,
            "version": domain_version,
            "compatible": compatible,
            "health": health,
        }
        if availability_error is not None:
            ida_domain["availability_error"] = availability_error
        if compatibility_error is not None:
            ida_domain["compatibility_error"] = compatibility_error
        _capability_cache.snapshot = {
            "python": platform.python_version(),
            "python_minimum": MIN_PYTHON,
            "ida_minimum": MIN_IDA,
            "ida_domain": ida_domain,
        }
    return copy.deepcopy(_capability_cache.snapshot)


def clear_capability_cache() -> None:
    """Clear cached immutable capability metadata for tests or reconfiguration."""
    _capability_cache.snapshot = None

@dataclass(frozen=True)
class SdkFallback:
    """Evidence record for an unavoidable IDA Python SDK fallback."""

    capability: str
    reason: str


_fallbacks: list[SdkFallback] = []


def sdk_fallback(capability: str, reason: str) -> SdkFallback:
    """Record and return a justified SDK fallback descriptor.

    Exact duplicate records are ignored while preserving first-seen order.
    Distinct reasons remain separate evidence for the same capability.
    """
    fallback = SdkFallback(capability, reason)
    if fallback not in _fallbacks:
        _fallbacks.append(fallback)
    return fallback


def fallback_records() -> tuple[SdkFallback, ...]:
    """Return the fallback records accumulated by this process."""

    return tuple(_fallbacks)


def clear_fallback_records() -> None:
    """Clear fallback diagnostics, primarily for isolated tests."""

    _fallbacks.clear()


def available() -> bool:
    """Return whether ``ida_domain`` can be imported and initialized."""

    try:
        import_module("ida_domain")
    except (ImportError, AttributeError, RuntimeError, TypeError, OSError):
        return False
    return True


def database(*, required: bool = True) -> Any | None:
    """Return the current Domain ``Database`` handle, lazily.

    ``Database.open()`` without a path is the documented IDA-mode operation.
    No SDK module is imported by this function.  ``required=False`` returns
    ``None`` when the optional package/session is unavailable.

    Inside an explicit library session opened by this process
    (:func:`open_database` / :func:`database_session`) the cached handle is
    reused so hot internal callers do not allocate and re-hook a fresh
    Domain wrapper on every lookup.  The cache is consulted only when the
    still-imported ``ida_domain`` module is the one that produced it; a
    replaced or removed module invalidates the cache automatically.  Outside
    such an explicit open (for example plain IDA GUI mode) every call re-opens
    the current database pathlessly, so an out-of-band database switch is
    never served a stale handle.
    """
    using_active = None
    if _active_session.handle is not None:
        try:
            if import_module("ida_domain") is _active_session.module:
                using_active = _active_session.handle
            else:
                # The module that produced the cached handle is gone/replaced:
                # drop it so a stale external handle is never served.
                clear_active_database()
        except (ImportError, AttributeError, RuntimeError, TypeError, ValueError, OSError):
            clear_active_database()
    if using_active is not None:
        return using_active
    try:
        domain = import_module("ida_domain")
        domain_cls = domain.Database
        return domain_cls.open()
    except (ImportError, AttributeError, RuntimeError, TypeError, ValueError, OSError) as exc:
        if not required:
            return None
        raise DomainUnavailable(
            "ida-forge requires an IDA Domain database session; "
            "install ida-domain and run inside IDA Pro 9.1+"
        ) from exc
def open_database(path, *, save_on_close: bool = False, options: Any = None) -> Any:
    """Open a binary/database through ida-domain library mode.

    This is the documented clean-binary entry point: ``Database.open(path,
    args=options, save_on_close=...)``. The adapter does not fall back to the
    SDK because opening a database is a Domain-owned lifecycle operation.
    """

    try:
        domain = import_module("ida_domain")
        database_cls = domain.Database
        kwargs = {"save_on_close": save_on_close}
        if options is not None:
            kwargs["args"] = options
        handle = database_cls.open(path, **kwargs)
    except (ImportError, AttributeError, RuntimeError, ValueError, OSError, TypeError) as exc:
        # A failed open invalidates any prior handle: whatever session was
        # cached, if any, is no longer the authoritative current one.
        clear_active_database()
        raise DomainUnavailable(
            f"ida-domain could not open database {path!s}; "
            "use an IDA Pro 9.1+ environment with activated idalib"
        ) from exc
    _active_session.handle = handle
    _active_session.module = domain
    return handle

@contextmanager
def database_session(path, *, save_on_close: bool = False, options: Any = None):
    """Open a Domain database and deterministically close its library session."""

    database_handle = open_database(
        path,
        save_on_close=save_on_close,
        options=options,
    )
    try:
        active_database = database_handle.__enter__()
    except (AttributeError, RuntimeError, TypeError, ValueError, OSError) as exc:
        raise DomainUnavailable(
            f"ida-domain database session setup failed for {path!s}"
        ) from exc
    try:
        yield active_database
    except BaseException:
        try:
            suppressed = database_handle.__exit__(*sys.exc_info())
        except (AttributeError, RuntimeError, TypeError, ValueError, OSError) as exc:
            raise DomainUnavailable(
                f"ida-domain database session cleanup failed for {path!s}"
            ) from exc
        if not suppressed:
            raise
    else:
        try:
            database_handle.__exit__(None, None, None)
        except (AttributeError, RuntimeError, TypeError, ValueError, OSError) as exc:
            raise DomainUnavailable(
                f"ida-domain database session cleanup failed for {path!s}"
            ) from exc
    finally:
        # The session deterministically closed the database; never hand the
        # closed session's handle back to later callers (stale-handle guard).
        clear_active_database()


def require_database() -> Any:
    """Return the current Domain database or raise :class:`DomainUnavailable`."""

    return database(required=True)


def current_database(*, required: bool = True) -> Any | None:
    """Return the current Domain database, optionally without raising."""

    return database(required=required)
def _strict_domain_method(
    database_handle: Any,
    namespace: str,
    method: str,
    *args,
    capability: str,
    reason: str,
    **kwargs,
):
    """Resolve a strict Domain method while recording capability gaps."""
    handler = getattr(database_handle, namespace, None)
    operation = getattr(handler, method, None)
    if not callable(operation):
        sdk_fallback(capability, reason)
        raise DomainUnavailable(
            f"ida-domain does not expose db.{namespace}.{method} on this build"
        )
    return operation(*args, **kwargs)


def domain_method(database_handle: Any, namespace: str, method: str, *args, **kwargs):
    """Call one documented Domain namespace method with a useful error.

    This small helper centralizes absent/old Domain API handling while keeping
    public forge contracts independent of Domain object implementation details.
    """

    return _strict_domain_method(
        database_handle,
        namespace,
        method,
        *args,
        capability=f"{namespace}.{method}",
        reason=f"ida-domain {namespace} handler lacks {method}",
        **kwargs,
    )


def try_domain_call(
    operation,
    *args,
    capability: str,
    failure_reason: str,
    exceptions: tuple[type[BaseException], ...] = (Exception,),
    **kwargs,
) -> tuple[bool, Any | None]:
    """Call an already-resolved Domain adapter operation with diagnostics."""
    try:
        return True, operation(*args, **kwargs)
    except exceptions:
        sdk_fallback(capability, failure_reason)
        return False, None


def try_domain_method(
    database_handle: Any | None,
    namespace: str,
    method: str,
    *args,
    capability: str,
    unavailable_reason: str,
    failure_reason: str,
    exceptions: tuple[type[BaseException], ...] = (
        AttributeError,
        RuntimeError,
        TypeError,
        ValueError,
    ),
    **kwargs,
) -> tuple[bool, Any | None]:
    """Call an optional Domain method and record one SDK fallback on failure."""
    if database_handle is None:
        sdk_fallback(capability, unavailable_reason)
        return False, None
    handler = getattr(database_handle, namespace, None)
    operation = getattr(handler, method, None)
    if not callable(operation):
        sdk_fallback(capability, unavailable_reason)
        return False, None
    return try_domain_call(
        operation,
        *args,
        capability=capability,
        failure_reason=failure_reason,
        exceptions=exceptions,
        **kwargs,
    )
def function_at(database_handle: Any, ea: int) -> Any | None:
    """Return the Domain function containing ``ea``."""

    return _strict_domain_method(
        database_handle,
        "functions",
        "get_at",
        ea,
        capability="functions.get_at",
        reason="ida-domain functions handler lacks get_at",
    )


def function_name(database_handle: Any, function: Any) -> str | None:
    """Return a Domain function name for a function object or address."""

    return _strict_domain_method(
        database_handle,
        "functions",
        "get_name",
        function,
        capability="functions.get_name",
        reason="ida-domain functions handler lacks get_name",
    )


def decompile(database_handle: Any, ea: int) -> Any:
    """Decompile through the documented Domain pseudocode handler."""

    return _strict_domain_method(
        database_handle,
        "pseudocode",
        "decompile",
        ea,
        capability="pseudocode.decompile",
        reason="ida-domain pseudocode handler lacks decompile",
    )


def type_by_name(database_handle: Any, name: str) -> Any | None:
    """Look up a named type through the Domain types handler."""

    return _strict_domain_method(
        database_handle,
        "types",
        "get_by_name",
        name,
        capability="types.get_by_name",
        reason="ida-domain types handler lacks get_by_name",
    )


def parse_declaration(database_handle: Any, declaration: str, *, name: str | None = None) -> Any:
    """Parse one declaration through the Domain types handler."""

    return _strict_domain_method(
        database_handle,
        "types",
        "parse_one_declaration",
        None,
        declaration,
        name,
        capability="types.parse_one_declaration",
        reason="ida-domain types handler lacks parse_one_declaration",
    )

def decompile_result(database_handle: Any, ea: int) -> dict | None:
    """Extract forge's stable decompile shape from an ida-domain function."""

    function = decompile(database_handle, ea)
    if function is None:
        return None
    text_lines = function.to_text(remove_tags=True)
    local_variables = function.local_variables
    lvar_rows = []
    for index, variable in enumerate(local_variables):
        type_info = getattr(variable, "type_info", None)
        type_str = None
        if type_info is not None:
            try:
                type_str = type_info.dstr()
            except Exception:  # noqa: BLE001 — incomplete type information
                type_str = None
        lvar_rows.append(
            {
                "index": index,
                "name": variable.name,
                "type": type_str,
                "is_arg": bool(variable.is_arg),
            }
        )
    calls = {
        expression.x.obj_ea
        for expression in function.find_calls()
        if getattr(expression, "x", None) is not None
        and getattr(expression.x, "is_object", False)
        and getattr(expression.x, "obj_ea", None) is not None
    }
    return {
        "ea": ea,
        "name": None,
        "pseudocode": "\n".join(text_lines),
        "lvars": lvar_rows,
        "calls": sorted(calls),
    }


def apply_declaration(database_handle: Any, ea: int, declaration: str, *, flags: Any = None) -> bool:
    """Apply a declaration through Domain, omitting optional flags by default."""

    args = (ea, declaration) if flags is None else (ea, declaration, flags)
    return bool(
        _strict_domain_method(
            database_handle,
            "types",
            "apply_declaration_at",
            *args,
            capability="types.apply_declaration_at",
            reason="ida-domain types handler lacks apply_declaration_at",
        )
    )
