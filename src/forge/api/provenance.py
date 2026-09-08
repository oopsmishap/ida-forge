"""Applied type provenance: durable dependency/reference catalog (gap #10).

The recovery evaluation (2026-08-30) showed that after a type is re-committed
or renamed, every place that consumed its previous ordinal — structure member
declarations, applied globals, retyped locals, function prototypes — goes
stale and must be re-applied, and nothing in the plugin knew what "everything"
was. This module is that record.

The catalog stores plain, detached rows (:class:`TypeReference`) — never live
tinfo handles (the T1.1 rule) — in a ``Storage("TypeReferences")`` netnode
namespace, with the same best-effort persistence policy as the structure
catalog: failures degrade to a warning and never break facade operations.

Reference kinds cover today's structure/member declarations and the future
application surfaces (EA, hex-rays lvar, prototype) so one freshness query —
:meth:`TypeReferenceCatalog.dependents_of` — answers "what must be refreshed
when this type changes" for every consumer, and
:meth:`TypeReferenceCatalog.resolve_commit_order` answers "in what order do
these structures commit" (referenced types first).

The catalog is reconstructible: structure/member declaration rows rebuild
from the structure catalog's persisted descriptions (:meth:`rebuild`), while
EA/lvar/prototype rows persist as recorded — so a save/reopen cycle loses
nothing.
"""

from __future__ import annotations

import copy

from forge.api.storage import Storage
from forge.util.logging import log_warning

_STORAGE_KEY = "TypeReferences"

# Reference kinds
STRUCTURE_MEMBER = "structure_member"  # a structure's member declaration names a type
GLOBAL_EA = "global_ea"  # a type was applied at a data address
LVAR = "lvar"  # a type was applied to a hex-rays local
PROTOTYPE = "prototype"  # a type appears in a function prototype

_KINDS = frozenset({STRUCTURE_MEMBER, GLOBAL_EA, LVAR, PROTOTYPE})


class TypeReference:
    """One detached (consumer, referenced type) row.

    ``type_name`` is the referenced type. The consumer side depends on the
    kind: ``owner``/``offset``/``member_name`` for structure member
    declarations, ``ea`` for globals, ``func_ea``/``var`` for locals, and
    ``func_ea`` for prototypes. ``detail`` carries the full declaration
    text or relation kind where it is useful for display.
    """

    __slots__ = (
        "detail",
        "ea",
        "func_ea",
        "kind",
        "member_name",
        "offset",
        "owner",
        "type_name",
        "var",
    )

    def __init__(
        self,
        kind: str,
        type_name: str,
        *,
        owner: str | None = None,
        offset: int | None = None,
        member_name: str | None = None,
        ea: int | None = None,
        func_ea: int | None = None,
        var: str | None = None,
        detail: str | None = None,
    ):
        if kind not in _KINDS:
            raise ValueError(f"unknown reference kind {kind!r}")
        if not type_name:
            raise ValueError("type_name must be a non-empty name")
        self.kind = kind
        self.type_name = type_name
        self.owner = owner
        self.offset = offset
        self.member_name = member_name
        self.ea = ea
        self.func_ea = func_ea
        self.var = var
        self.detail = detail

    def identity_key(self) -> tuple:
        return (
            self.kind,
            self.type_name,
            self.owner,
            self.offset,
            self.member_name,
            self.ea,
            self.func_ea,
            self.var,
            self.detail,
        )

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "type_name": self.type_name,
            "owner": self.owner,
            "offset": self.offset,
            "member_name": self.member_name,
            "ea": self.ea,
            "func_ea": self.func_ea,
            "var": self.var,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> TypeReference:
        if not isinstance(raw, dict):
            raise ValueError("reference row must be a mapping")
        return cls(
            raw.get("kind"),
            raw.get("type_name"),
            owner=raw.get("owner"),
            offset=raw.get("offset"),
            member_name=raw.get("member_name"),
            ea=raw.get("ea"),
            func_ea=raw.get("func_ea"),
            var=raw.get("var"),
            detail=raw.get("detail"),
        )

    def consumer_key(self) -> tuple:
        """The consumer side only — one consumer, many referenced types."""
        return (self.kind, self.owner, self.offset, self.member_name, self.ea, self.func_ea, self.var)

    def __eq__(self, other):
        return isinstance(other, TypeReference) and self.identity_key() == other.identity_key()

    def __hash__(self):
        return hash(self.identity_key())

    def __repr__(self):
        return f"TypeReference({self.kind}, {self.type_name!r}, {self.consumer_key()!r})"


class TypeReferenceCatalog:
    """Dict-over-rows store of :class:`TypeReference` with write-through persistence."""

    def __init__(self):
        self._references: dict[tuple, TypeReference] = {}
        self._loaded = False
        self._recovery = {
            "load_failures": 0,
            "corrupt_entries": 0,
            "write_failures": 0,
        }
        self._last_error: dict[str, str] | None = None

    def recovery_status(self) -> dict:
        """Return detached persistence health, counters, and last error."""
        status = dict(self._recovery)
        status["health"] = "healthy" if not any(self._recovery.values()) else "degraded"
        status["last_error"] = copy.deepcopy(self._last_error)
        return status

    # -- persistence ---------------------------------------------------------

    @staticmethod
    def _storage() -> Storage:
        return Storage(_STORAGE_KEY)

    def _ensure_loaded(self) -> None:
        """Lazy one-time load from the persisted payload."""
        if self._loaded:
            return
        self._loaded = True
        try:
            stored = self._storage().get("data", None)
        except Exception as exc:  # noqa: BLE001 — persistence is best-effort
            self._recovery["load_failures"] += 1
            self._last_error = {
                "operation": "load",
                "type": type(exc).__name__,
                "message": str(exc),
            }
            log_warning(f"could not read persisted type reference catalog: {exc}")
            return
        self.load_payload(stored if isinstance(stored, dict) else None)

    def _snapshot(self) -> None:
        """Write-through persistence; never raises."""
        try:
            self._storage()["data"] = copy.deepcopy(self.to_payload())
        except Exception as exc:  # noqa: BLE001 — persistence is best-effort
            self._recovery["write_failures"] += 1
            self._last_error = {
                "operation": "write",
                "type": type(exc).__name__,
                "message": str(exc),
            }
            log_warning(f"could not persist type reference catalog: {exc}")

    def _mark_dirty(self) -> None:
        self._ensure_loaded()
        self._snapshot()

    def to_payload(self) -> dict:
        """A portable, tinfo-free payload (T1.1 rule)."""
        return {
            "version": 1,
            "references": [
                reference.to_dict()
                for reference in sorted(
                    self._references.values(),
                    key=lambda reference: reference.identity_key(),
                )
            ],
        }

    def load_payload(self, payload: dict | None) -> int:
        """Replace in-memory state from ``payload``; returns loaded rows.

        Counts as the lazy load itself (a direct ``load_payload`` call is
        not clobbered by ``_ensure_loaded`` afterwards). Corrupt rows are
        counted and skipped (the structure catalog's corrupt-entry
        policy), never fatal.
        """
        self._loaded = True
        self._references.clear()
        if not payload:
            return 0
        loaded = 0
        for raw in payload.get("references", []) or []:
            if not isinstance(raw, dict):
                # A non-mapping row is not an entry at all; skip it with a
                # log line but do not count it as a corrupt entry.
                log_warning(f"skipping non-mapping reference row: {raw!r}")
                continue
            try:
                reference = TypeReference.from_dict(raw)
            except Exception:  # noqa: BLE001 — skip corrupt rows
                self._recovery["corrupt_entries"] += 1
                self._last_error = {
                    "operation": "corrupt_entry",
                    "type": "ValueError",
                    "message": f"invalid reference row {raw!r}",
                }
                log_warning(f"skipping corrupt reference row: {raw!r}")
                continue
            self._references[reference.identity_key()] = reference
            loaded += 1
        return loaded

    def add(self, reference: TypeReference, *, persist: bool = True) -> TypeReference:
        """Record ``reference`` (idempotent by identity).

        Persists unless ``persist=False`` (batched callers — :meth:`rebuild`
        — call :meth:`_mark_dirty` themselves once at the end).
        """
        self._ensure_loaded()
        self._references.setdefault(reference.identity_key(), reference)
        if persist:
            self._mark_dirty()
        return self._references[reference.identity_key()]

    def record_structure_member(
        self,
        structure_name: str,
        offset: int,
        member_name: str | None,
        type_name: str,
        *,
        detail: str | None = None,
        persist: bool = True,
    ) -> TypeReference:
        return self.add(
            TypeReference(
                STRUCTURE_MEMBER,
                type_name,
                owner=structure_name,
                offset=offset,
                member_name=member_name,
                detail=detail,
            ),
            persist=persist,
        )

    def record_declaration(
        self,
        structure_name: str,
        offset: int,
        member_name: str | None,
        declaration: str | None,
        *,
        persist: bool = True,
    ) -> list[TypeReference]:
        """Record one row per named type a member declaration references.

        The dependency-aware companion of
        :func:`forge.api.members.declaration_type_references`: a member
        declared ``fixture_Quest *`` produces one
        :data:`STRUCTURE_MEMBER` row for ``fixture_Quest``. Returns the
        recorded rows (empty when the declaration references no named
        type).
        """
        from forge.api.members import declaration_type_references

        return [
            self.record_structure_member(
                structure_name,
                offset,
                member_name,
                name,
                detail=declaration,
                persist=persist,
            )
            for name in declaration_type_references(declaration)
        ]

    def record_global_ea(self, ea: int, type_name: str, *, detail: str | None = None) -> TypeReference:
        return self.add(
            TypeReference(GLOBAL_EA, type_name, ea=ea, detail=detail)
        )

    def record_lvar(self, func_ea: int, var: str, type_name: str, *, detail: str | None = None) -> TypeReference:
        return self.add(
            TypeReference(LVAR, type_name, func_ea=func_ea, var=var, detail=detail)
        )

    def record_prototype(self, func_ea: int, type_name: str, *, detail: str | None = None) -> TypeReference:
        return self.add(
            TypeReference(PROTOTYPE, type_name, func_ea=func_ea, detail=detail)
        )

    # -- queries -------------------------------------------------------------

    def all(self) -> list[TypeReference]:
        self._ensure_loaded()
        return sorted(
            self._references.values(), key=lambda reference: reference.identity_key()
        )

    def __len__(self) -> int:
        self._ensure_loaded()
        return len(self._references)

    def dependents_of(self, type_name: str) -> list[TypeReference]:
        """Every recorded consumer of ``type_name`` (the freshness query).

        When ``type_name`` is re-committed, renamed, or re-filed, each
        returned row is a place that must be re-applied/re-parsed: member
        declarations re-pack, EA/lvar/prototype sites re-apply.
        """
        self._ensure_loaded()
        return [
            reference
            for reference in self.all()
            if reference.type_name == type_name
        ]

    def owners_of(self, type_name: str) -> set[str]:
        """Structure names whose member declarations reference ``type_name``."""
        return {
            reference.owner
            for reference in self.dependents_of(type_name)
            if reference.kind == STRUCTURE_MEMBER and reference.owner
        }

    def references_from_structure(self, structure_name: str) -> list[TypeReference]:
        """Every structure-member row recorded for ``structure_name``."""
        self._ensure_loaded()
        return [
            reference
            for reference in self.all()
            if reference.kind == STRUCTURE_MEMBER and reference.owner == structure_name
        ]

    def clear_owner(self, structure_name: str, *, persist: bool = True) -> int:
        """Drop every structure-member row of ``structure_name``; returns the count."""
        self._ensure_loaded()
        stale = [
            key
            for key, reference in self._references.items()
            if reference.kind == STRUCTURE_MEMBER and reference.owner == structure_name
        ]
        for key in stale:
            del self._references[key]
        if stale and persist:
            self._mark_dirty()
        return len(stale)

    def clear(self) -> None:
        """Drop every row."""
        self._ensure_loaded()
        self._references.clear()
        self._mark_dirty()

    # -- reconstruction ------------------------------------------------------

    def rebuild(self, structures, *, keep_applied: bool = True) -> dict:
        """Refresh structure-member rows from duck-typed structure objects.

        Accepts any iterable of objects exposing ``name`` and ``members``
        (the structure catalog's :class:`Structure` shape). For each
        structure its previous :data:`STRUCTURE_MEMBER` rows are dropped
        and re-recorded from the members' authored declarations
        (``decl_src``, falling back to their rendered type) and
        linked-child relations; structures not passed are left untouched.
        Recorded EA/lvar/prototype rows are kept unless
        ``keep_applied=False``. Persistence is batched to one write.
        Returns a summary dict.
        """
        self._ensure_loaded()
        kept = 0 if not keep_applied else sum(
            1 for reference in self._references.values()
            if reference.kind != STRUCTURE_MEMBER
        )
        if not keep_applied:
            # Drop the applied runtime rows (EA/lvar/prototype); the
            # structure-member declaration rows are rebuilt below.
            self._references = {
                key: reference
                for key, reference in self._references.items()
                if reference.kind == STRUCTURE_MEMBER
            }
        recorded = 0
        skipped_members = 0
        for structure in structures or []:
            name = getattr(structure, "name", None)
            if not name:
                continue
            self.clear_owner(name, persist=False)
            for member in getattr(structure, "members", None) or []:
                offset = getattr(member, "offset", 0)
                member_name = getattr(member, "name", None)
                try:
                    declaration = getattr(member, "decl_src", None) or getattr(
                        member, "type_name", None
                    )
                    rows = self.record_declaration(
                        name, offset, member_name, declaration, persist=False
                    )
                    recorded += len(rows)
                except Exception as exc:  # noqa: BLE001 — one degenerate
                    # member degrades alone (the catalog's corrupt-entry
                    # policy): the rebuild continues with the healthy ones.
                    skipped_members += 1
                    self._last_error = {
                        "operation": "rebuild_member",
                        "type": type(exc).__name__,
                        "message": str(exc),
                    }
                    log_warning(
                        f"rebuild skipped degenerate member "
                        f"{name}.{member_name}: {exc}"
                    )
                    continue
                child = getattr(member, "linked_child_structure_name", None)
                if child:
                    self.record_structure_member(
                        name,
                        offset,
                        member_name,
                        child,
                        detail=getattr(member, "child_relation_kind", None) or "pointer",
                        persist=False,
                    )
                    recorded += 1
        self._mark_dirty()
        return {
            "recorded": recorded,
            "kept_applied": kept,
            "skipped_members": skipped_members,
            "total": len(self),
        }

    # -- dependency ordering -------------------------------------------------

    def dependencies_of(self, structure_name: str, *, scope: set[str] | None = None) -> set[str]:
        """Named types ``structure_name``'s declarations reference.

        With ``scope``, only names inside it count (commit planning).
        """
        self._ensure_loaded()
        return {
            reference.type_name
            for reference in self.references_from_structure(structure_name)
            if reference.type_name != structure_name and (scope is None or reference.type_name in scope)
        }

    def resolve_commit_order(self, names) -> tuple[list[str], list[str]]:
        """Order ``names`` so referenced types come first (topological).

        Returns ``(ordered, deferred)``: ``ordered`` respects every
        dependency inside the requested set; ``deferred`` lists the names
        left over from dependency cycles (appended in input order) so the
        caller can still commit them and report the cycle. Self-references
        (a structure whose member declares itself) never defer.
        """
        self._ensure_loaded()
        scope = list(dict.fromkeys(names))
        scope_set = set(scope)
        remaining = {
            name: self.dependencies_of(name, scope=scope_set)
            for name in scope
        }
        ordered: list[str] = []
        resolved: set[str] = set()
        while remaining:
            ready = [
                name for name in scope if name in remaining and remaining[name] <= resolved
            ]
            if not ready:
                break
            for name in ready:
                ordered.append(name)
                resolved.add(name)
                del remaining[name]
        deferred = [name for name in scope if name not in resolved]
        ordered.extend(deferred)
        return ordered, deferred


references = TypeReferenceCatalog()
