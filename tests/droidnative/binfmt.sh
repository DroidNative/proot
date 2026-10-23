#!/usr/bin/env bash
# Tests of the binfmt_misc emulation on the PC (execve/binfmt.c). The guest
# rootfs is a directory with the PC's /usr bound in and its own /etc, so the
# PC's real binfmt.d rules stay out.
#
# Usage: tests/droidnative/binfmt.sh <build dir>
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
B="$(mkdir -p "${1:?build dir}" && cd "$1" && pwd)"

"$HERE/build-host.sh" "$B" >/dev/null 2>&1 || { echo "build failed"; exit 1; }
PROOT="$B/proot/src/proot"
export PROOT_TMP_DIR="$B/tmp"
mkdir -p "$PROOT_TMP_DIR"

R="$(mktemp -d "$B/root.XXXXXX")"
mkdir -p "$R/etc/binfmt.d" "$R/w" "$R/tmp"
for d in bin lib lib64 sbin; do
    [ -L "/$d" ] && ln -s "$(readlink "/$d")" "$R/$d"
done
printf '\177DNT payload\n' > "$R/w/prog"
printf 'not matched\n' > "$R/w/doc.dnx"
printf '#!/w/prog -s\n' > "$R/w/script"
chmod +x "$R/w/prog" "$R/w/doc.dnx" "$R/w/script"

fails=0
check() {   # $1 = name, $2 = output, $3 = expected substring
    if printf '%s' "$2" | grep -qF -- "$3"; then
        echo "ok   $1"
    else
        echo "FAIL $1"; printf '%s\n' "$2" | head -20 | sed 's/^/     /'
        fails=$((fails + 1))
    fi
}
guest() {
    timeout 60 "$PROOT" -0 -r "$R" -b /usr -b /dev -b /proc -w /w sh -c "$1" 2>&1
}

check "no rule: plain exec fails" "$(guest './prog >/dev/null 2>&1; echo rc=$?')" "rc=12"

echo ':dntest:M::\x7fDNT::/usr/bin/echo:' > "$R/etc/binfmt.d/dntest.conf"
check "magic rule runs the interpreter" "$(guest './prog a b')" "./prog a b"
check "absolute path" "$(guest '/w/prog x')" "/w/prog x"
check "shebang to a matched program" "$(guest './script arg')" "/w/prog -s ./script arg"

echo ':dnext:E::dnx::/usr/bin/echo:' > "$R/etc/binfmt.d/dnext.conf"
check "extension rule" "$(guest './doc.dnx q')" "./doc.dnx q"

check "rule added while running" \
    "$(guest 'rm -f /etc/binfmt.d/dnext.conf; ./doc.dnx; echo rc=$?;
              echo ":dnext:E::dnx::/usr/bin/echo:" > /etc/binfmt.d/dnext.conf; ./doc.dnx z')" \
    "./doc.dnx z"

# Sorts before dntest.conf; printf prints only its first argument
echo ':dnmask:M::\x7fDNX:\xff\xff\xff\x00:/usr/bin/printf:' > "$R/etc/binfmt.d/a-mask.conf"
check "mask and name order" "$(guest './prog m 2>/dev/null; echo "|"')" "./prog|"
rm "$R/etc/binfmt.d/a-mask.conf"

echo ':dnmiss:M::\x7fDNT::/usr/bin/missing-interp:' > "$R/etc/binfmt.d/0-missing.conf"
check "missing interpreter" "$(guest './prog; echo rc=$?')" "rc=127"
rm "$R/etc/binfmt.d/0-missing.conf"

check "PROOT_NO_BINFMT" "$(PROOT_NO_BINFMT=1 guest './prog >/dev/null 2>&1; echo rc=$?')" "rc=12"

check "child sees argv" "$(guest 'exec ./prog "with space" end')" "./prog with space end"

[ "${KEEP:-}" ] || rm -rf "${R:?}"
echo "$fails failed"
[ "$fails" -eq 0 ]
