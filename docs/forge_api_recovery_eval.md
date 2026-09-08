# Forge API C++ recovery evaluation — recover and apply the complete ABI type surface

## Mission

Recover the C++ fixture's type surface through the `forge_api` facade and apply it to a cold IDA
analysis:

- namespace-scoped records;
- classes with virtual methods and vtables;
- single and multiple inheritance;
- recursive pointers and fixed arrays;
- nested aggregates;
- template instantiations;
- globals and section-runner pointer flow.

The final score measures only the final IDB against the authorized C++ ground truth. C++ ABI
artifacts—vptrs, secondary base subobjects, thunks, RTTI/vtable references, compiler padding, and
mangled names—are evidence to recover, not reasons to substitute a C-style layout.

## Why forge_api

`forge_api` is the headless facade for structure building, C++-aware type recovery, scanning,
committing, naming, global application, local retyping, and persistence verification. Use the
facade for every type operation it exposes. Use ida-domain first for general binary evidence:

- `db.functions` and `db.pseudocode` for function discovery/decompilation;
- `db.types` for ABI type inspection and type application;
- `db.bytes` for data, vtables, strings, and object spans;
- `db.names` for symbol/name evidence;
- `db.xrefs` for vtable, RTTI, global, and string references;
- `db.imports` and `db.segments` for import/segment classification.

IDA Python is an explicit fallback only where the current ida-domain release has no documented
equivalent. Every fallback must be isolated and recorded in the report with its capability and
reason.

## Target and ground truth

Target binary, opened cold through `ida_open_database`:

```text
tests/fixtures/build/Release/complex_fixture.exe
```

Repository-relative ground truth, opened only during Phase 4 Score:

```text
tests/fixtures/cpp_complex/include/fixture.hpp
tests/fixtures/cpp_complex/src/fixture.cpp
tests/fixtures/cpp_complex/src/main.cpp
```

Build provenance:

```text
C++20
-O0
-g0
-fno-omit-frame-pointer
```

The committed Release binary is stripped. Do not rely on source-level symbol names surviving in
the IDB. Resolve anonymous globals and methods from binary evidence: function enumeration,
mangled names when present, vtable/RTTI references, strings, calls, xrefs, object sizes, and
constructor/destructor patterns.

## Ground-truth gate

Ground truth is **off-limits through Recon, Recover, and Apply**. Do not open `fixture.hpp`,
`fixture.cpp`, or `main.cpp` for member lists, offsets, sizes, class relationships, or missed
scanner evidence until Phase 4 Score, after the final recovery and apply passes have been
committed.

Opening ground truth before Phase 4 invalidates scanner attribution. Header-derived completion
performed after Phase 4 is allowed only as an explicit manual fallback and must be listed in the
report as:

```text
resolved from C++ ground truth, not binary evidence
```

The final report must include the exact attestation:

```text
ground truth opened at Phase 4 only
```

## Ground-truth inventory to build in Phase 4

Build the exact table from `fixture.hpp` only after Apply. Include ABI size, alignment, every
member/base-subobject offset, member name, member type, vptr/vtable evidence, and inheritance
relationships.

### Namespace records

- `fixture::Vec3`
- `fixture::Transform`
- `fixture::StatusEffect`
- `fixture::InventoryItem`
- `fixture::InventorySlot`
- `fixture::Inventory`
- `fixture::QuestStep`
- `fixture::Quest`
- `fixture::SceneNode`
- `fixture::Waypoint`
- `fixture::PatrolRoute`
- `fixture::LeaderboardEntry`
- `fixture::DialogLine`
- `fixture::DialogNode`
- `fixture::ArrayRef<T>` and the instantiated forms exercised by the binary, including
  `ArrayRef<QuestStep>` and `ArrayRef<int>`.

### Class hierarchy

- `fixture::Entity`
- `fixture::ActorMixin`
- `fixture::LivingEntity : Entity, ActorMixin`
- `fixture::Player final : LivingEntity`
- `fixture::Merchant final : LivingEntity`
- `fixture::Enemy final : LivingEntity`
- `fixture::Renderable`
- `fixture::Collectible : Entity, Renderable`
- `fixture::System`
- `fixture::PhysicsSystem final : System`
- `fixture::AISystem final : System`
- `fixture::RenderSystem final : System`
- `fixture::AudioSystem final : System`
- `fixture::Guild`
- `fixture::World`

For each polymorphic class, score:

- primary vptr position and vtable identity;
- virtual method slots and overriding relationships;
- base-subobject offsets, including the secondary `ActorMixin`/`Renderable` subobject where
  applicable;
- non-static data members and compiler padding;
- pointer targets and recursive references;
- constructor/destructor and thunk evidence where available.

### Globals

The authorized source declares:

- `fixture::World g_world`
- `fixture::const char *g_scene_name`
- `fixture::Player *g_main_player`

Do not guess their addresses. Resolve each address from binary data, xrefs, and decompilation;
apply exact types with `forge_api.apply_type(..., redefine_range=True)` only to verified spans.

### Entry points and pointer-flow functions

Score the exported/additional entry points and the relevant helper methods:

- `fixture::run_demo`
- `fixture::run_systems_demo`
- `fixture::run_patrol_demo`
- `fixture::run_dialog_demo`
- `fixture::run_guild_demo`
- `fixture::run_render_demo`
- `fixture::run_templated_demo`
- `World::add_player`, `World::add_enemy`, `World::add_merchant`
- `World::tick_all`, `World::tick_systems`
- `World::add_leaderboard_entry`, `World::top_entry`
- `Guild::add_member`, `Guild::lead`
- `Collectible::render`, `Collectible::label`
- the system `update` methods and the helper paths that pass `World&`, `Entity*`,
  `Player*`, `System*`, `Renderable*`, `Quest*`, `DialogNode*`, `PatrolRoute*`, and
  `ArrayRef<T>` values.

If stripping or inlining merges source functions, record the binary function(s) covering the
source entry point and score the merged pseudocode rather than inventing a missing function.

## Scoring

Build the Phase 4 ground-truth table from the C++ header/source. Read the final IDB using
`db.types`, `forge_api.get_structure()`, `forge_api.decompile()`, `forge_api.scan_sites()`, and
Domain type inspection. Do not score from visual pseudocode inspection alone.

### Classes and records — 55%

Per type:

- 30% ABI layout: total size, alignment, every member/base-subobject offset;
- 20% member/base names;
- 20% member and base types, including pointer targets and template arguments;
- 15% vptr/vtable/RTTI identity for polymorphic types;
- 15% inheritance and override relationships.

A type with no scanner attempt before manual construction is capped at 50% of its type bucket.
A type whose layout is manually completed after Phase 4 must be marked as such even if its final
ABI layout is exact.

### Globals — 20%

Each global receives one quarter of the bucket. Full credit requires:

- exact global type at the verified EA;
- correct array/template extent where applicable;
- no stray qword/blob fallback in the relevant decompile/data view;
- persisted type after save and reopen.

### Pointer flow and C++ dispatch — 25%

Score the sampled entry points and helpers for:

- exact local/argument class or record pointer/reference types;
- correct `this` type and base-subobject adjustment;
- rendered member access (`world->...`, `node->...`, `item->...`);
- virtual dispatch/vtable use attributed to the correct class;
- template aggregate flow (`ArrayRef<T>` data/length) where exercised.

Report exact, partial, and missing per function. If Hex-Rays keeps a literal address as
`MEMORY[...]` despite a verified applied type, count it conservatively and document the IDA
limitation.

## Required recovery workflow

### Phase 1 — Recon

1. Open the Release `.exe` cold through `ida_open_database`.
2. Confirm ida-domain availability/version and record fallbacks.
3. Enumerate functions and identify constructors, destructors, thunks, vtable references, RTTI,
   string references, global data, and source-like runner clusters without opening ground truth.
4. Record C++ evidence: mangled names, vtable-shaped arrays, `this` adjustments, allocation sizes,
   `lea`/`mov` member offsets, virtual calls, and format strings.

### Phase 2 — Recover

For each recoverable type, scanner-first:

1. Run `deep_scan`, `shallow_scan`, `scan_global`, or `scan_from_allocation` from a verified
   binary root.
2. Record the call and complete output, including failure output.
3. Inspect `scan_sites(name)` and scan additional roots into the same store structure.
4. Resolve collisions and junk with `auto_resolve`, `set_member(enabled=False)`, and explicit
   C++ member names from binary evidence.
5. Rebind child/template/base types after dependent structures change.
6. Use manual construction only where binary evidence proves scanner blindness; identify each
   header-derived completion in the report.
7. Commit with `create_type(..., overwrite=True)` and require non-empty `applied_sites` whenever
   scanner evidence exists.

For polymorphic classes, scanner evidence must be supplemented by explicit vtable/RTTI evidence.
Do not collapse a multiple-inheritance class into a flat unrelated struct.

### Phase 3 — Apply

1. Commit children, bases, records, templates, and derived classes in dependency order.
2. Apply all verified globals with `apply_type(..., redefine_range=True)`.
3. Retype locals/arguments and `this` pointers with `set_lvar_types(..., scope="all")`.
4. Verify member access, virtual dispatch, vtable references, and base adjustments in
   decompilation.
5. Save the IDB and reopen it before opening ground truth.

### Phase 4 — Score

1. Open `fixture.hpp`, `fixture.cpp`, and `main.cpp` for the first time.
2. Build the exact size/offset/name/type/inheritance/vtable/global/function table.
3. Score the reopened final IDB through MCP/Domain scripts.
4. Fix recoverable mismatches through Forge, re-commit, re-apply, save, reopen, and rescore.
5. Never replace scanner evidence with unreported header-derived claims.

### Phase 5 — Report

Create:

```text
docs/forge_api_recovery_eval_output.md
```

The report must include:

- per-record and per-class exact/partial/missing table;
- vptr/vtable, inheritance, and template results;
- all three globals and their verified EAs/types;
- every sampled function and pointer-flow result;
- scanner calls and outputs, including failures;
- manual/header-derived completions and why scanner evidence was insufficient;
- save/reopen persistence evidence;
- weighted total percentage;
- ranked Forge gaps as the final section;
- exact attestation: `ground truth opened at Phase 4 only`.

## Constraints and known C++ risks

- Do not use the C fixture's evaluation types or score assumptions for this binary.
- Do not infer class layout solely from source declaration order; account for the active Windows C++
  ABI, vptrs, alignment, secondary bases, thunks, and compiler-generated padding.
- Do not treat a vtable address as a data member; record it as polymorphic type evidence.
- Do not merge template instantiations whose element types differ.
- Do not overlap `apply_type(..., redefine_range=True)` spans.
- Recommit dependent parents after changing a child, base, union, or template instantiation.
- Save before dropping the IDA worker; reopen and verify persistence.
- If the binary is stripped, report unresolved source names with verified addresses and evidence;
  never fabricate symbol names.

## Acceptance

The evaluation is complete only when:

- every listed record/class/template instantiation is committed or explicitly reported missing;
- class ABI layouts, bases, and polymorphic metadata are scored;
- all three globals are applied and persisted where verified;
- pointer-flow and virtual-dispatch samples are scored;
- the final weighted score is at least 90%;
- `docs/forge_api_recovery_eval_output.md` exists and ends with the ranked Forge-gap list;
- unit tests and the live IDA evaluation both pass their documented verification commands.
