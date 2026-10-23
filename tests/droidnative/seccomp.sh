#!/usr/bin/env bash
# Test of SIGSYS from a filter the guest installed itself
# (tracee/event.c): it must reach the guest's handler instead of being
# taken for Android's app filter (which traps with data 0), and the
# handler must survive a data-0 trap inside it (tracee/seccomp.c,
# restore_sigsys_action).
#
# Usage: tests/droidnative/seccomp.sh <build dir>
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
B="$(mkdir -p "${1:?build dir}" && cd "$1" && pwd)"

"$HERE/build-host.sh" "$B" >/dev/null 2>&1 || { echo "build failed"; exit 1; }
PROOT="$B/proot/src/proot"
export PROOT_TMP_DIR="$B/tmp"
mkdir -p "$PROOT_TMP_DIR"
cc -O1 -o "$B/seccomp-trap" "$HERE/seccomp-trap.c" || { echo "test build failed"; exit 1; }

fails=0
check() {   # $1 = name, $2 = output, $3 = expected substring
    if printf '%s' "$2" | grep -qF -- "$3"; then
        echo "ok   $1"
    else
        echo "FAIL $1"; printf '%s\n' "$2" | head -20 | sed 's/^/     /'
        fails=$((fails + 1))
    fi
}

check "native" "$("$B/seccomp-trap" 2>&1)" "result 4242 data 7"
check "under proot" "$(timeout 60 "$PROOT" -r / "$B/seccomp-trap" 2>&1)" "result 4242 data 7"
# A data-0 trap inside the handler: PRoot reinstalls the reset handler
check "nested trap" "$(timeout 60 "$PROOT" -r / "$B/seccomp-trap" nested 2>&1)" "result 4242 data 7"

echo "$fails failed"
[ "$fails" -eq 0 ]
