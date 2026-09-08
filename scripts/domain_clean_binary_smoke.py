from __future__ import annotations

import sys

from forge.api.domain import DomainUnavailable, database_session

DEFAULT_PATH = ".scratch_probe_cold/pure_c_struct_fixture.exe"


def main(argv: list[str] | None = None) -> int:
    """Open a clean binary through Domain and print its session identity.

    The first positional argument selects the binary; with no arguments,
    ``DEFAULT_PATH`` is used. Additional arguments are intentionally ignored.
    """
    arguments = sys.argv[1:] if argv is None else argv
    path = arguments[0] if arguments else DEFAULT_PATH
    try:
        with database_session(path, save_on_close=False) as database:
            print(type(database).__name__)
            print(getattr(database, "path", None) or path)
    except DomainUnavailable as exc:
        print(f"{type(exc).__name__}: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
