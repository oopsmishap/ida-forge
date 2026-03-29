#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${ROOT}/build"
BIN="${OUT_DIR}/complex_fixture_debug"
CXX="${CXX:-clang++}"
TMP_DIR="$(mktemp -d)"
TMP_SRC="${TMP_DIR}/fixture.cpp"

cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

python3 - <<'PY' "${ROOT}/src/fixture.cpp" "${TMP_SRC}"
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
out = []
skipping = False
seen_run_demo = 0
for line in source:
    stripped = line.strip()
    if not skipping and stripped == "int run_demo() {":
        seen_run_demo += 1
        if seen_run_demo == 2:
            skipping = True
            continue
    if skipping:
        if stripped == "}":
            skipping = False
            continue
        continue
    out.append(line)


Path(sys.argv[2]).write_text("\n".join(out) + "\n", encoding="utf-8")
PY

mkdir -p "${OUT_DIR}"

"${CXX}" \
  -std=c++20 \
  -O0 \
  -g0 \
  -fno-omit-frame-pointer \
  -I"${ROOT}/include" \
  "${TMP_SRC}" \
  "${ROOT}/src/main.cpp" \
  -o "${BIN}"

echo "${BIN}"
