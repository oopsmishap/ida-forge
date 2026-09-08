"""Live member-commit regression: non-array UDT assembly must not be size-1.

Recovery-eval gap #2 (2026-08-30): ``Member.get_udt_member()`` historically
never assigned ``udt_member.type`` for *non-array* members (only the array
branch populated it), so every ``create_type`` committed a size-1 UDT while
reporting ``ok``.  Unit tests cannot load a real ``ida_typeinf`` (all ``ida_*``
modules are stubbed), so this is a dedicated live smoke: run it inside an
idalib/ida-domain session against the cold fixture and it FAILS (nonzero) if a
non-array member commits as a size-1 UDT.

Contract under test
-------------------
For a non-array member with a real scalar/named type, ``get_udt_member(array_size=0)``
must populate ``udt_member.type`` and the resulting ``tinfo_t.create_udt(BTF_STRUCT)``
must report a size larger than the 1-byte empty-UDT sentinel.

Run it
------
Activated idalib (ida-codemode worker) with the plugin importable, then:

    python scripts/domain_member_udt_commit_smoke.py [fixture.exe]

Exit codes: 0 = all members committed as >1-byte UDTs; 1 = an assertion failed
(a size-1 UDT was produced); 2 = the domain session/import was unavailable.
"""
from __future__ import annotations

import json
import sys
from typing import Any

from forge.api.domain import DomainUnavailable, current_database, database_session

DEFAULT_PATH = ".scratch_probe_cold/pure_c_struct_fixture.exe"

# (member type decl, expected non-trivial width) — all non-array.  Uses the
# project's signed-8 normalization so the smoke does not depend on a tili seed.
_UDT_COMMIT_CASES: tuple[tuple[str, int], ...] = (
    ("unsigned __int32", 4),   # integral scalar member
    ("unsigned __int16", 2),
    ("unsigned __int64", 8),
    ("unsigned __int8", 1),    # legal but individually 1 byte; the point is
    # the COMMITTED STRUCT accumulates these members, never collapses to 1.
)

_SENTINEL_SIZE = 1  # a real create_udt over real members is always > 1 byte


def _run_live(database: Any) -> dict[str, Any]:
    """Assemble a multi-member struct from non-array Members and assert size."""
    import ida_typeinf  # noqa: PLC0415 - only importable inside a live IDA
    from forge.api.members import Member, parse_user_tinfo  # noqa: PLC0415

    members: list[Member] = []
    offset = 0
    for decl, width in _UDT_COMMIT_CASES:
        tinfo = parse_user_tinfo(decl)
        if tinfo is None:
            return {
                "ok": False,
                "error": f"could not parse member type {decl!r} against live tili",
            }
        member = Member(offset, tinfo, None, origin=0)
        member.name = f"probe_{offset:x}"
        members.append(member)
        offset += max(width, 1)

    udt = ida_typeinf.udt_type_data_t()
    for member in members:
        # The exact non-array path the pack/commit core uses.
        udt.push_back(member.get_udt_member(array_size=0, offset=0))

    final = ida_typeinf.tinfo_t()
    if not final.create_udt(udt, ida_typeinf.BTF_STRUCT):
        return {
            "ok": False,
            "error": "create_udt(BTF_STRUCT) returned False for non-array members",
        }
    committed_size = final.get_size()
    return {
        "ok": committed_size > _SENTINEL_SIZE,
        "committed_size": committed_size,
        "member_count": len(members),
        "non_array": True,
        "size_is_one": committed_size == _SENTINEL_SIZE,
    }


def main(argv: list[str] | None = None) -> int:
    """Run the live regression; return a process exit code."""
    arguments = sys.argv[1:] if argv is None else argv
    path = arguments[0] if arguments else DEFAULT_PATH
    try:
        # Under an ida-codemode worker the database is already open as the
        # exec target; opening a second one fails.  Prefer the active handle.
        active = current_database(required=False)
        if active is not None:
            result = _run_live(active)
        else:
            with database_session(path, save_on_close=False) as database:
                result = _run_live(database)
    except DomainUnavailable as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
