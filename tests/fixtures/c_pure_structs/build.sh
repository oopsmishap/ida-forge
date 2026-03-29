#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${ROOT}/build"
BIN="${OUT_DIR}/pure_c_struct_fixture"
CC="${CC:-clang}"

mkdir -p "${OUT_DIR}"

"${CC}" \
  -std=c11 \
  -O0 \
  -g0 \
  -fno-omit-frame-pointer \
  -I"${ROOT}/include" \
  "${ROOT}/src/fixture.c" \
  "${ROOT}/src/main.c" \
  -o "${BIN}"

case "$(uname -s)" in
  Darwin)
    strip -S -x "${BIN}"
    ;;
  *)
    strip --strip-all "${BIN}"
    ;;
esac

echo "${BIN}"
