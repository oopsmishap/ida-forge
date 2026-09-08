"""Shared structure catalog with optional netnode persistence (I.28).

The catalog is the single source of truth for the structure store. It is
dict-like over structure names so every existing caller keeps working,
adds ``unique_name``/``current`` helpers, and persists a portable
description (never live tinfo handles — the T1.1 rule) to
``Storage("Structures")`` after every mutation, reloading lazily on first
access. Persistence failures only degrade to a warning — they never break
facade operations.
"""

from __future__ import annotations

import bisect
import copy
import dataclasses

from contextlib import contextmanager
from forge.api.storage import Storage
from forge.util.logging import log_warning

_STORAGE_KEY = "Structures"


def _live_scan_site_rows(structure) -> list:
    """Site rows derived from the members' live scan objects (R3.6).

    Plain JSON rows only (the T1.1 rule: never live tinfo handles) —
    ``{"func_ea", "var", "ea", "type", "member_offset"}`` per recorded
    scan-object site, deduplicated like the apply step does.
    """
    from forge.api.structure import Structure

    rows: list = []
    seen: set = set()
    for member in structure.members:
        for scan_object in getattr(member, "scanned_variables", None) or ():
            identity_key = getattr(scan_object, "identity_key", None)
            key = (
                identity_key()
                if callable(identity_key)
                else (
                    getattr(scan_object, "func_ea", None),
                    getattr(scan_object, "ea", None),
                    getattr(scan_object, "id", None),
                    getattr(scan_object, "name", None),
                )
            )
            if key in seen or key == (None, None):
                continue
            seen.add(key)
            try:
                row = Structure._scan_site_row(scan_object)
            except Exception as exc:  # noqa: BLE001 — one degenerate object degrades
                from forge.util.logging import log_debug

                log_debug(f"scan-site row failed for {scan_object!r}: {exc}")
                continue
            row["member_offset"] = getattr(member, "offset", 0)
            rows.append(row)
    return rows


def _scan_sites_payload(structure) -> list:
    """The persisted scan-site rows for a structure.

    Live member scan objects win (a fresh scan updates the model); with
    no live objects — e.g. right after a catalog reload — the previously
    persisted rows are kept so a re-snapshot never erases them.
    """
    rows = _live_scan_site_rows(structure)
    if rows:
        return [dict(row) for row in rows]
    return [dict(row) for row in (getattr(structure, "scan_sites_rows", None) or [])]


class StructureCatalog:
    """Dict-like store of :class:`Structure` with write-through persistence."""
    def __init__(self):
        self._structures: dict = {}
        self._current: str | None = None
        self._loaded = False
        # F4: True after a failed/corrupt initial load; persistence is
        # suspended so the (possibly empty) in-memory guess is never
        # written over the saved catalog.
        self._load_failed = False
        # In-transaction write suppression: inner mutations skip the
        # per-item snapshot+notify; the outermost commit/rollback fires one.
        self._suppress = False
        self._transaction_depth = 0
        self.events: list = []
        self._recovery = {
            "load_failures": 0,
            "corrupt_entries": 0,
            "write_failures": 0,
        }
        self._last_error: dict[str, str] | None = None

    def recovery_status(self) -> dict:
        """Return detached persistence health, counters, and last recovery error."""
        status = dict(self._recovery)
        status["health"] = (
            "healthy"
            if not any(self._recovery.values())
            else "degraded"
        )
        status["last_error"] = copy.deepcopy(self._last_error)
        return status
    # -- persistence -------------------------------------------------------

    @staticmethod
    def _storage() -> Storage:
        return Storage(_STORAGE_KEY)

    def _ensure_loaded(self) -> None:
        """Lazy one-time load from the persisted catalog description.

        A failed/corrupt read is distinguished from an ABSENT payload (F4):
        absence is a normal empty start, while a failed load flags the
        catalog (``_load_failed``) so :meth:`_snapshot` suspends
        persistence — writing the empty in-memory guess through would
        destroy the saved catalog. A failed load is retried on the next
        access so a transient failure can still heal.
        """
        if self._loaded:
            return
        try:
            # Strict read: ``Storage.get`` swallows corrupt-payload errors
            # (NetnodeCorruptError, json/zlib failures) into ``None``,
            # conflating them with absence. Indexing raises instead, so a
            # corrupt catalog is counted, never silently emptied.
            stored = self._storage()["data"]
            if stored is not None and not isinstance(stored, dict):
                raise ValueError(
                    f"catalog payload is {type(stored).__name__}, not a dict"
                )
        except KeyError:
            self._loaded = True  # absent payload: normal empty start
            return
        except Exception as exc:  # noqa: BLE001 — persistence is best-effort
            if not self._load_failed:
                self._recovery["load_failures"] += 1
            self._load_failed = True
            self._last_error = {
                "operation": "load",
                "type": type(exc).__name__,
                "message": str(exc),
            }
            log_warning(f"could not read persisted structure catalog: {exc}")
            return
        self._loaded = True
        self._load_failed = False
        if not stored:
            return
        for raw in stored.get("structures", []) or []:
            try:
                structure = self._deserialize(raw)
            except Exception as exc:  # noqa: BLE001 — skip corrupt entries
                self._recovery["corrupt_entries"] += 1
                self._last_error = {
                    "operation": "corrupt_entry",
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
                log_warning(
                    f"skipping corrupt catalog entry {raw.get('name', '?')!r}: {exc}"
                )
                continue
            self._structures[structure.name] = structure
        if stored.get("current") in self._structures:
            self._current = stored["current"]

    def _snapshot(self) -> None:
        """Write-through persistence; never raises.

        After a failed/corrupt load the in-memory catalog is a possibly
        empty guess; persisting it would overwrite the saved catalog with
        ``{'structures': [], ...}``. Persistence is suspended until a load
        succeeds (F4, 2026-09 review) — never wipe silently.
        """
        if self._load_failed:
            log_warning(
                "structure catalog persistence suspended: the initial "
                "load failed; in-memory changes stay in memory and the "
                "persisted catalog is left untouched"
            )
            return
        try:
            payload = self._snapshot_payload()
            self._storage()["data"] = copy.deepcopy(payload)
        except Exception as exc:  # noqa: BLE001 — persistence is best-effort
            self._recovery["write_failures"] += 1
            self._last_error = {
                "operation": "write",
                "type": type(exc).__name__,
                "message": str(exc),
            }
            log_warning(f"could not persist structure catalog: {exc}")


    def _serialize(self, structure) -> dict:
        from forge.api.members import LinkedStructureMember, VirtualTable
        provenance = getattr(structure, "provenance", {})
        if not isinstance(provenance, dict):
            provenance = dataclasses.asdict(provenance) or {}
        provenance = copy.deepcopy(provenance)
        members = []
        for member in structure.members:
            # C2 (2026-09 review): enabled/comment/is_array ride every row —
            # they used to be dropped by the serializer, so a disabled
            # member resurrected as enabled and a comment erased on reload.
            # Defaults are omitted to keep payloads lean, but every load
            # honors them.
            flags = {}
            if not getattr(member, "enabled", True):
                flags["enabled"] = False
            comment = getattr(member, "comment", "") or ""
            if comment:
                flags["comment"] = comment
            if getattr(member, "is_array", False):
                flags["is_array"] = True
            if isinstance(member, LinkedStructureMember):
                # T1.1: plain portable rows only — never live tinfo handles.
                members.append(
                    {
                        "kind": "linked",
                        "offset": member.offset,
                        "name": getattr(member, "name", ""),
                        "child_structure_name": member.child_structure_name,
                        "conservative_extent": member.conservative_extent,
                        "child_relation_kind": member.child_relation_kind,
                        "origin": getattr(member, "origin", 0),
                        **flags,
                    }
                )
                continue
            tinfo = getattr(member, "tinfo", None)
            type_str = ""
            dstr = getattr(tinfo, "dstr", None)
            if callable(dstr):
                try:
                    type_str = dstr()
                except Exception:  # noqa: BLE001 — stub tinfos may break
                    type_str = ""
            entry = {
                "offset": member.offset,
                "name": getattr(member, "name", ""),
                "type": type_str,
                # The authored declaration string (E4): re-parsed fresh at
                # pack time so stale tinfo ordinals can never serialize as
                # ``#NN *``. Persisted so members keep it across reloads.
                "decl_src": getattr(member, "decl_src", None),
                "origin": getattr(member, "origin", 0),
                "array_count": getattr(member, "array_count", None),
                "kind": "vtable" if isinstance(member, VirtualTable) else "member",
            }
            if entry["kind"] == "vtable":
                entry["vtable_address"] = getattr(member, "address", 0)
            entry.update(flags)
            members.append(entry)
        return {
            "name": structure.name,
            "main_offset": structure.main_offset,
            "created_type_name": structure.created_type_name,
            "is_auto_named": structure.is_auto_named,
            "pack": structure.pack,
            # R3.6: scan-evidence sites ride the catalog's netnode payload —
            # plain rows only (the T1.1 rule: never live tinfo handles), so
            # scan_sites() answers from the DB after any reopen/rebuild.
            "scan_sites": _scan_sites_payload(structure),
            "last_applied": copy.deepcopy(list(getattr(structure, "last_apply_sites", []))),
            "provenance": provenance,
            "members": members,
            "child_relationships": [
                {
                    "parent_structure_name": rel.parent_structure_name,
                    "child_structure_name": rel.child_structure_name,
                    "parent_member_offset": rel.parent_member_offset,
                    "parent_member_name": rel.parent_member_name,
                    "relation_kind": rel.relation_kind,
                }
                for rel in structure.child_relationships
            ],
            "abi_metadata": copy.deepcopy(getattr(structure, "abi_metadata", {})),
        }

    def _deserialize(self, raw: dict):
        from forge.api.members import Member, VirtualTable, parse_user_tinfo
        from forge.api.structure import Structure, StructureProvenance

        structure = Structure(raw["name"])
        structure.main_offset = raw.get("main_offset", 0)
        structure.created_type_name = raw.get("created_type_name")
        structure.is_auto_named = raw.get("is_auto_named", False)
        structure.abi_metadata = copy.deepcopy(raw.get("abi_metadata") or {})
        # R3.2: existing persisted catalogs default to packed (no migration).
        structure.pack = raw.get("pack", 1)
        structure.scan_sites_rows = copy.deepcopy(raw.get("scan_sites") or [])
        structure.last_apply_sites = copy.deepcopy(raw.get("last_applied") or [])
        prov = copy.deepcopy(raw.get("provenance") or {})
        known = set(StructureProvenance.__dataclass_fields__)
        structure.provenance = StructureProvenance(
            **{key: value for key, value in prov.items() if key in known}
        )
        for member_raw in raw.get("members", []) or []:
            try:
                if member_raw.get("kind") == "vtable":
                    member = VirtualTable(
                        member_raw.get("offset", 0),
                        member_raw.get("vtable_address", 0),
                        None,
                        member_raw.get("origin", 0),
                    )
                elif member_raw.get("kind") == "linked":
                    from forge.api.members import LinkedStructureMember

                    # T1.1: the row is the portable placeholder — tinfo
                    # stays None until the child commits and the link
                    # refreshes. No live handles are ever reconstructed.
                    offset = member_raw.get("offset", 0)
                    member = LinkedStructureMember(
                        offset,
                        member_raw.get("child_structure_name") or "",
                        member_raw.get("conservative_extent", 1),
                        member_raw.get("name")
                        or f"field_{offset:x}",
                        relation_kind=member_raw.get(
                            "child_relation_kind", "embedded"
                        ),
                        scanned_variables=(),
                    )
                    member.origin = member_raw.get("origin", 0)
                else:
                    authored_type = member_raw.get("decl_src")
                    serialized_type = member_raw.get("type")
                    type_declaration = authored_type or serialized_type or "u64"
                    tinfo = parse_user_tinfo(type_declaration)
                    if tinfo is None:
                        # Gap #9 (recovery eval 2026-08-30): when the authored
                        # declaration does not parse (typically it references a
                        # store structure not committed to the IDB yet), the
                        # u64 storage fallback stays (legacy catalogs depend on
                        # it) but the warning now names the missing types so
                        # the degradation is never silent. Packing stays safe:
                        # ``decl_src`` persists and the pre-pack readiness
                        # check (:meth:`pack_readiness`) reports these names.
                        from forge.api.members import declaration_type_references

                        unresolved = (
                            declaration_type_references(authored_type)
                            if authored_type
                            else []
                        )
                        detail = (
                            f" (unresolved references: {', '.join(unresolved)})"
                            if unresolved
                            else ""
                        )
                        log_warning(
                            f"catalog member type {type_declaration!r} did not "
                            f"parse; using u64{detail}"
                        )
                        tinfo = parse_user_tinfo("u64")
                    if tinfo is None:
                        raise ValueError(
                            f"catalog member type {type_declaration!r} and fallback u64 did not parse"
                        )
                    member = Member(
                        member_raw.get("offset", 0),
                        tinfo,
                        None,
                        member_raw.get("origin", 0),
                    )
                    member.name = member_raw.get("name") or member.name
                    member.decl_src = authored_type
            except Exception as exc:  # noqa: BLE001 — skip corrupt catalog members
                log_warning(f"skipping corrupt catalog member: {exc}")
                continue
            member.enabled = member_raw.get("enabled", True)
            member.comment = member_raw.get("comment", "")
            member.is_array = member_raw.get("is_array", False)
            if member_raw.get("array_count") is not None:
                member.array_count = member_raw.get("array_count")
            structure.members.append(member)
        for rel in raw.get("child_relationships", []) or []:
            structure.add_child_relationship(
                child_structure_name=rel.get("child_structure_name", ""),
                parent_member_offset=rel.get("parent_member_offset", 0),
                parent_member_name=rel.get("parent_member_name", ""),
                relation_kind=rel.get("relation_kind", "pointer"),
            )
        structure.refresh_collisions()
        return structure

    @contextmanager
    def transaction(self, label: str = "catalog transaction"):
        """Atomically group catalog mutations with in-memory rollback.

        The snapshot uses the existing detached serializer, so rollback does not
        retain live IDA tinfo handles. Persistence is written once on commit;
        exceptions restore the prior structures and current selection and
        re-snapshot the netnode (C3) so a mid-transaction write-through
        cannot leave an aborted mutation persisted.

        While a transaction is open, per-item ``_mark_dirty`` side effects
        (snapshot + change notification) are suppressed; the outermost
        commit/rollback fires exactly one snapshot+notify pair.
        """
        self._ensure_loaded()
        before = copy.deepcopy(self._snapshot_payload())
        self._transaction_depth += 1
        self._suppress = True
        committed = False
        try:
            yield self
        except Exception as error:
            # F5: the restore itself may fail (corrupt prior payload); that
            # must never mask the original exception, and it must never
            # silently drop members through a half-parsed rollback.
            try:
                restored = self._deserialize_payload(before)
            except Exception as restore_error:
                log_warning(
                    f"catalog rollback for {label!r} could not restore the "
                    f"pre-transaction snapshot: {restore_error}"
                )
                raise error from restore_error
            self._structures = restored[0]
            self._current = restored[1]
            self._snapshot()
            self.notify_changed()
            raise
        else:
            committed = True
        finally:
            self._transaction_depth = max(0, self._transaction_depth - 1)
            if self._transaction_depth == 0:
                self._suppress = False
                if committed:
                    self._snapshot()
                    self.notify_changed()

    def _snapshot_payload(self) -> dict:
        return {
            "structures": [self._serialize(s) for s in self._structures.values()],
            "current": self._current,
        }

    def _deserialize_payload(self, payload: dict) -> tuple[dict, str | None]:
        structures = {}
        for raw in payload.get("structures", []) or []:
            structure = self._deserialize(raw)
            structures[structure.name] = structure
        current = payload.get("current") if payload.get("current") in structures else None
        return structures, current

    # -- change notification ------------------------------------------------

    def notify_changed(self) -> None:
        for handler in list(self.events):
            try:
                handler()
            except Exception as exc:  # noqa: BLE001 — UI callbacks must not break the store
                log_warning(f"catalog change handler failed: {exc}")

    def _mark_dirty(self) -> None:
        self._ensure_loaded()
        if self._suppress:
            # In-transaction mutations are batched: one snapshot+notify on
            # the outermost commit/rollback.
            return
        self._snapshot()
        self.notify_changed()


    # -- dict-like API -------------------------------------------------------

    def __getitem__(self, name: str):
        self._ensure_loaded()
        return self._structures[name]

    def get(self, name: str, default=None):
        self._ensure_loaded()
        return self._structures.get(name, default)

    def __contains__(self, name: str) -> bool:
        self._ensure_loaded()
        return name in self._structures

    def __iter__(self):
        self._ensure_loaded()
        return iter(self._structures)

    def __len__(self) -> int:
        self._ensure_loaded()
        return len(self._structures)

    def __setitem__(self, name: str, structure) -> None:
        self._ensure_loaded()
        self._structures[name] = structure
        self._mark_dirty()

    def __delitem__(self, name: str) -> None:
        self._ensure_loaded()
        del self._structures[name]
        self._mark_dirty()

    def keys(self):
        self._ensure_loaded()
        return self._structures.keys()

    def values(self):
        self._ensure_loaded()
        return self._structures.values()

    def items(self):
        self._ensure_loaded()
        return self._structures.items()

    def clear(self) -> None:
        """Drop every structure and reset the current selection."""
        self._ensure_loaded()
        self._structures.clear()
        self._current = None
        self._mark_dirty()

    # -- helpers --------------------------------------------------------------

    def pack_readiness(self, name: str):
        """Dependency-aware pre-pack resolution report (gap #9, 2026-08-30).

        Re-resolves every enabled member's authored declaration against the
        current type table. The returned :class:`PackReadiness` is ok only
        when no member would pack as a placeholder; ``readiness.error`` is
        the structured, member-level reason (unresolved type references or
        a malformed declaration). The facade packing path calls this before
        ``_pack_commit`` and returns the error instead of committing.
        """
        self._ensure_loaded()
        structure = self._structures[name]
        from forge.api.members import resolve_pack_readiness

        return resolve_pack_readiness(structure.members, structure.name)

    def merge_member(self, structure_name: str, incoming) -> dict:
        """Merge a scan-built member into a catalog structure at the same offset.

        Provenance-safe (gap #8): delegates to
        :func:`forge.api.members.merge_member_evidence`, then drops the
        non-surviving member from ``structure.members`` and persists — the
        drop-the-loser step of the facade contract lives here so callers
        cannot forget it. The survivor keeps its authored name/``decl_src``/
        type/comment; the loser contributes its scan evidence. When no
        member exists at the incoming offset, the incoming member is added.
        Returns ``{"ok": True, "merged": <survivor>, "dropped": <loser or
        None>}`` or ``{"ok": False, "error": ...}``.
        """
        self._ensure_loaded()
        structure = self._structures.get(structure_name)
        if structure is None:
            return {"ok": False, "error": f"unknown structure {structure_name!r}"}
        from forge.api.members import merge_member_evidence

        offset = getattr(incoming, "offset", None)
        existing = (
            structure.get_member_by_offset(offset) if offset is not None else None
        )
        merged = merge_member_evidence(existing, incoming)
        if merged is None:
            return {"ok": False, "error": "members cannot merge (different offsets)"}
        loser = incoming if merged is existing else existing
        if loser is not None:
            # C1 (2026-09 review): AbstractMember.__eq__ is VALUE equality
            # ((offset, type_name), with a scanned-variables side effect),
            # so ``list.remove``/``in`` could delete the SURVIVOR when
            # another member shares (offset, type). Identity ops only.
            structure.members[:] = [
                member for member in structure.members if member is not loser
            ]
        if not any(member is merged for member in structure.members):
            # Keep the sorted (offset, type) order that refresh_collisions /
            # build_cdecl walk; a plain append breaks the invariant.
            bisect.insort(structure.members, merged)
        structure.refresh_collisions()
        self._mark_dirty()
        return {"ok": True, "merged": merged, "dropped": loser}


    @property

    def current(self) -> str | None:
        self._ensure_loaded()
        return self._current

    @current.setter
    def current(self, value: str | None) -> None:
        self._ensure_loaded()
        if self._current != value:
            self._current = value
            self._mark_dirty()

    def unique_name(self, base: str) -> str:
        """A name not yet taken: ``base``, or ``base Copy``, ``base Copy 2``..."""
        self._ensure_loaded()
        if base not in self._structures:
            return base
        copy_index = 2
        candidate = f"{base} Copy"
        while candidate in self._structures:
            candidate = f"{base} Copy {copy_index}"
            copy_index += 1
        return candidate


catalog = StructureCatalog()