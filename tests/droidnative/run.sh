#!/usr/bin/env bash
# Tests of the DroidNative storage extension on the PC (extension/dn_storage):
# exec from a noexec mount, FAT-like volumes, FUSE emulation, disk images.
# The guest is the PC itself (-r /); nothing is mounted for real.
#
# Usage: tests/droidnative/run.sh <build dir>
# Needs: a noexec tmpfs writable by the user (/run/lock on most systems,
#        or $NOEXEC_DIR), libfuse3 headers, git.  The test image on it is
#        kept and reused (each run works in a directory of its own).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
B="$(mkdir -p "${1:?build dir}" && cd "$1" && pwd)"
NOEXEC="${NOEXEC_DIR:-/run/lock}/dn-proot-test"

"$HERE/build-host.sh" "$B" >/dev/null 2>&1 || { echo "build failed"; exit 1; }
cc -O2 "$HERE/fuse-ro.c" $(pkg-config --cflags --libs fuse3) -o "$B/fuse-ro" || exit 1

export PROOT_TMP_DIR="$B/tmp"
mkdir -p "$PROOT_TMP_DIR" "$NOEXEC"
WORK="$(mktemp -d "$B/work.XXXXXX")"
trap 'rm -f "${NOEXEC:?}/true" "${NOEXEC:?}/$(basename "${lib:-none}")"' EXIT
PROOT="$B/proot/src/proot"

fails=0
check() {   # $1 = name, $2 = output, $3 = expected substring
    if printf '%s' "$2" | grep -qF -- "$3"; then
        echo "ok   $1"
    else
        echo "FAIL $1"; printf '%s\n' "$2" | head -20 | sed 's/^/     /'
        fails=$((fails + 1))
    fi
}
guest() {   # $@ = proot options, then the shell command
    local cmd="${!#}"
    timeout 120 "$PROOT" -0 --link2symlink -r / -w "$WORK" "${@:1:$#-1}" sh -c "$cmd" 2>&1
}

# Exec on noexec
cp /usr/bin/true "$NOEXEC/true"
lib="$(ldd /usr/bin/ls | awk '/libselinux/ {print $3}')"
[ -n "$lib" ] && cp "$lib" "$NOEXEC/"
check "native exec from noexec fails" "$("$NOEXEC/true" 2>&1; echo rc=$?)" "rc=126"
check "exec from noexec" "$(guest -b "$NOEXEC:/mnt/x" '/mnt/x/true && echo ran')" "ran"
if [ -n "$lib" ]; then
    check "library from noexec" "$(guest -b "$NOEXEC:/mnt/x" 'LD_LIBRARY_PATH=/mnt/x ls /mnt/x >/dev/null && echo ran')" "ran"
fi

# FAT-like volume
chmod 600 "$NOEXEC/true"
check "fat mode" "$(guest --fat-bind="$NOEXEC:/mnt/x" 'stat -c %a /mnt/x/true')" "755"
check "fat exec without x bit" "$(guest --fat-bind="$NOEXEC:/mnt/x" '[ -x /mnt/x/true ] && /mnt/x/true && echo ran')" "ran"
check "fat chmod succeeds" "$(guest --fat-bind="$NOEXEC:/mnt/x" 'chmod 600 /mnt/x/true && echo done')" "done"

# FUSE
mkdir -p "$WORK/src/sub" "$WORK/mnt"
cp /usr/bin/true "$WORK/src/sub/true"
echo hello > "$WORK/src/hello.txt"
ln -sf sub/true "$WORK/src/link"
seq 1 200000 > "$WORK/src/big.txt"
out="$(guest --fuse "$B/fuse-ro src mnt -f & sleep 1
cat mnt/hello.txt; cmp mnt/big.txt src/big.txt && echo same; mnt/link && echo link-ran
touch mnt/new; umount mnt; wait; echo done")"
check "fuse read" "$out" "hello"
check "fuse big file" "$out" "same"
check "fuse exec through symlink" "$out" "link-ran"
check "fuse read-only" "$out" "Read-only file system"
check "fuse unmount" "$out" "done"

# Disk image (on the noexec mount)
IMG="$NOEXEC/img"
R="run-$$"
out="$(guest --image="$IMG:/mnt/img" 'cd /mnt/img && mkdir '$R' && cd '$R' && mkdir a && echo hi > a/File && echo lo > a/file
cat a/File a/file; ln a/File a/hard; ln -s File a/sym; cat a/sym
chmod 700 a/File; chown 1234:5678 a/file; stat -c "%n %a %h %u" a/File a/file
cp /usr/bin/true a/t && chmod 755 a/t && a/t && echo image-exec
mv a/file a/moved; rm a/hard; mkfifo a/fifo; stat -c "%n %h %F" a/File a/fifo')"
check "image case" "$out" "lo"
check "image symlink" "$out" "hi"
check "image chmod and hard link" "$out" "a/File 700 2"
check "image chown" "$out" "a/file 664 1 1234"
check "image exec" "$out" "image-exec"
check "image unlink" "$out" "a/File 1 regular file"
check "image fifo" "$out" "fifo"
out="$(guest --image="$IMG:/mnt/img" 'stat -c "%a %u" /mnt/img/'$R'/a/moved')"
check "image persists" "$out" "664 1234"
for g in "$PROOT_TMP_DIR"/dnimage-*/generation; do echo 0 > "$g"; done
check "image shadow rebuild" "$(guest --image="$IMG:/mnt/img" 'cat /mnt/img/'$R'/a/sym')" "hi"
out="$(guest --image="$IMG:/mnt/img" 'cd /mnt/img/'$R' && mkdir repo && cd repo && git init -q && echo a > f && git add f &&
git -c user.name=demouser -c user.email=demouser@example.com commit -qm one && git fsck && echo git-ok')"
check "image git" "$out" "git-ok"

echo "$fails failed"
[ "$fails" -eq 0 ]
