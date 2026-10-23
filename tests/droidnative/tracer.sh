#!/usr/bin/env bash
# Test of the hidden tracer (syscall/enter.c, maybe_hide_tracer): guests
# must see "TracerPid: 0" and their own status, not PRoot's.
#
# Usage: tests/droidnative/tracer.sh <build dir>
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
B="$(mkdir -p "${1:?build dir}" && cd "$1" && pwd)"

"$HERE/build-host.sh" "$B" >/dev/null 2>&1 || { echo "build failed"; exit 1; }
PROOT="$B/proot/src/proot"
export PROOT_TMP_DIR="$B/tmp"
mkdir -p "$PROOT_TMP_DIR"

fails=0
check() {   # $1 = name, $2 = output, $3 = expected substring
    if printf '%s' "$2" | grep -qF -- "$3"; then
        echo "ok   $1"
    else
        echo "FAIL $1"; printf '%s\n' "$2" | head -20 | sed 's/^/     /'
        fails=$((fails + 1))
    fi
}
guest() { timeout 60 "$PROOT" -r / sh -c "$1" 2>&1; }

check "self" "$(guest 'grep TracerPid /proc/self/status')" "TracerPid:	0"
check "own name" "$(guest 'grep ^Name /proc/self/status')" "grep"
check "by pid" "$(guest 'grep TracerPid /proc/$$/status')" "TracerPid:	0"
check "thread" "$(guest 'grep TracerPid /proc/thread-self/status')" "TracerPid:	0"
check "task" "$(guest 'grep TracerPid /proc/$$/task/$$/status')" "TracerPid:	0"
check "other files untouched" "$(guest 'grep -c . /proc/self/stat')" "1"
left="$(ls "$PROOT_TMP_DIR" | grep -c proot-status || true)"
check "copies removed" "left=$left" "left=0"

echo "$fails failed"
[ "$fails" -eq 0 ]
