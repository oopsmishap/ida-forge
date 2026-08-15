# R3.2 gap-fix probe (F1-F7) — scripts/r3_gap_probe.py
#
# Standalone codemode probe: executed via ida_open_database (cold .exe) +
# ida_execute_python(code=<this source>); the harness calls run(db).
# Prints one PASS/FAIL line per assertion and a final
# "PROBE RESULT: <n>/<m> PASS" line. No fixture imports; forge_api and
# ida_* are imported inside run() so module state is fresh per execute.

import sys


def _reimport_forge():
    for mod in [
        m for m in list(sys.modules)
        if m == "forge_api" or m.startswith("forge")
    ]:
        del sys.modules[mod]


def run(db=None):  # codemode convention: harness passes db
    _reimport_forge()
    import ida_bytes

    import forge_api

    passed = 0
    total = 7

    def check(name, ok, detail=""):
        nonlocal passed
        if ok:
            passed += 1
            print(f"PASS {name}")
        else:
            print(f"FAIL {name}: {detail}")

    # 1. pack default: a u8@0 + u64@1 layout commits 9 bytes packed
    #    (natural alignment would be 16).
    forge_api.create_structure(
        "R3Probe",
        members=[
            {"offset": 0, "type": "unsigned __int8", "name": "first"},
            {"offset": 1, "type": "unsigned __int64", "name": "wide"},
        ],
    )
    commit = forge_api.create_type("R3Probe", overwrite=True)
    size = forge_api.type_of("R3Probe")["size"]
    check(
        "pack default",
        commit.get("ok") is True and size == 9,
        f"create_type={commit} size={size} (expected 9)",
    )

    # 2. pack opt-out: natural alignment re-commits to 16 bytes.
    forge_api.set_pack("R3Probe", None)
    forge_api.create_type("R3Probe", overwrite=True)
    size_natural = forge_api.type_of("R3Probe")["size"]
    check(
        "pack opt-out",
        size_natural == 16,
        f"size={size_natural} (expected 16)",
    )

    # 3. aliases: uint32 shorthand parses all the way to a native token.
    forge_api.create_structure("R3Alias")
    member = forge_api.add_member("R3Alias", 0, "uint32", name="x")
    check(
        "aliases",
        "error" not in member and member.get("name") == "x",
        f"member={member}",
    )

    # 4. rename_member on a committed type (pack back to 1, re-commit,
    #    then rename the member at byte offset 1).
    forge_api.set_pack("R3Probe", 1)
    forge_api.create_type("R3Probe", overwrite=True)
    size_packed = forge_api.type_of("R3Probe")["size"]
    renamed = forge_api.rename_member("R3Probe", 1, "renamed_wide")
    members = forge_api.type_of("R3Probe")["members"]
    offset1 = next((m for m in members if m["offset"] == 1), None)
    check(
        "rename_member",
        size_packed == 9
        and renamed.get("ok") is True
        and offset1 is not None
        and offset1["name"] == "renamed_wide",
        f"size={size_packed} renamed={renamed} offset1={offset1}",
    )

    # 5. typedef: function-pointer typedef commits through the
    #    declarator-name rung and reads back as a function-pointer type.
    tdef = forge_api.create_typedef(
        "DispatchFn", "int (__cdecl *)(void *, unsigned int)"
    )
    to = forge_api.type_of("DispatchFn")
    is_fnptr = to is not None and to.get("kind") in ("pointer", "function")
    check(
        "typedef",
        tdef.get("ok") is True and is_fnptr,
        f"create_typedef={tdef} type_of={to}",
    )

    # 6. teleport: helper-mediated allocation on the caller; the callee
    #    body (chain_node_new) is scanned too. >= 2 distinct offsets.
    r = forge_api.scan_from_allocation(
        0x140001F10, var_name="v0", name="R3Chain", commit=False
    )
    print(f"      allocation row: {r.get('allocation')}")
    if r.get("ok"):
        offsets = {m["offset"] for m in r["members"]}
        ok6 = len(offsets) >= 2
        detail6 = f"offsets={sorted(offsets)} callee={r.get('allocation', {}).get('callee')}"
    else:
        ok6 = False
        detail6 = f"scan_from_allocation error={r.get('error')}"
    check("teleport", ok6, detail6)

    # 7. F6 double-apply: a second apply_type over the same span must not
    #    erode the item (size stays stable across both applies).
    first = forge_api.apply_type(0x140006000, "unsigned __int32", redefine_range=True)
    size1 = ida_bytes.get_item_size(0x140006000)
    second = forge_api.apply_type(0x140006000, "unsigned __int32", redefine_range=True)
    size2 = ida_bytes.get_item_size(0x140006000)
    check(
        "F6 double-apply",
        first.get("ok") is True
        and second.get("ok") is True
        and size1 == size2
        and size1 >= 4,
        f"first={first} second={second} size1={size1} size2={size2}",
    )

    print(f"PROBE RESULT: {passed}/{total} PASS")
    return {"passed": passed, "total": total}