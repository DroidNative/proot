#!/usr/bin/env bash
# Builds this tree for the PC (glibc, system talloc and sqlite3) in a copy
# under $1, for the tests in this directory.
#
# Usage: tests/droidnative/build-host.sh <build dir>
set -euo pipefail
SRC="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:?build dir}"
mkdir -p "$OUT"
rsync -a --exclude .git "$SRC/" "$OUT/proot/"
make -s -C "$OUT/proot/src" -j"$(nproc)" proot
echo "$OUT/proot/src/proot"
