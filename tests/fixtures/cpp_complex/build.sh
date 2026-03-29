#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${ROOT}/build"
BIN="${OUT_DIR}/complex_fixture"
CXX="${CXX:-clang++}"

mkdir -p "${OUT_DIR}"

"${CXX}" \
  -std=c++20 \
  -O0 \
  -g0 \
  -fno-omit-frame-pointer \
  -I"${ROOT}/include" \
  "${ROOT}/src/fixture.cpp" \
  "${ROOT}/src/main.cpp" \
  -o "${BIN}"

case "$(uname -s)" in
  Darwin)
    # Keep only the symbols required for dynamic linking; remove our own exported names.
    strip -u -r "${BIN}"
    ;;
  *)
    strip --strip-all "${BIN}"
    ;;
esac

echo "${BIN}"
