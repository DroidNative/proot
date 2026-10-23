#!/usr/bin/env bash
# Tests of the generated /proc/net/tcp (extension/dn_net), forced on the PC
# with PROOT_DN_NET=force: a loopback server and client in the guest must
# appear there, and lsof must name the client's process.
#
# Usage: tests/droidnative/net.sh <build dir>      Needs: python3, lsof
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

# Server and client in one guest; the client prints its port, then the
# tables and lsof's view are taken while both sockets are open
script='
import socket, subprocess, sys
fam = socket.AF_INET6 if sys.argv[1] == "6" else socket.AF_INET
host = "::1" if fam == socket.AF_INET6 else "127.0.0.1"
srv = socket.socket(fam); srv.bind((host, 0)); srv.listen(1)
port = srv.getsockname()[1]
cli = socket.socket(fam); cli.connect((host, port))
conn, _ = srv.accept()
cport = cli.getsockname()[1]
print("ports %X %X" % (port, cport))
print(open("/proc/net/tcp6" if fam == socket.AF_INET6 else "/proc/net/tcp").read())
print(subprocess.run(["lsof", "-P", "-F", "upnR", "-i", "TCP@%s:%d" % (host if fam == socket.AF_INET else "[::1]", cport)],
      capture_output=True, text=True).stdout)
print("pid", __import__("os").getpid())
'
out="$(PROOT_DN_NET=force timeout 60 "$PROOT" -r / python3 -c "$script" 4 2>&1)"
sport="$(sed -n 's/^ports \([0-9A-F]*\) .*/\1/p' <<<"$out")"
cport="$(sed -n 's/^ports [0-9A-F]* \([0-9A-F]*\)$/\1/p' <<<"$out")"
pid="$(sed -n 's/^pid //p' <<<"$out")"
sport4="$(printf '%04X' "0x${sport:-0}")"; cport4="$(printf '%04X' "0x${cport:-0}")"
check "listening socket" "$out" "0100007F:$sport4 00000000:0000 0A"
check "client socket" "$out" "0100007F:$cport4 0100007F:$sport4 01"
check "accepted socket" "$out" "0100007F:$sport4 0100007F:$cport4 01"
check "lsof names the process" "$out" "p$pid"
# Without -n lsof names the address (as Steam calls it)
check "lsof addresses" "$out" "nlocalhost:$((16#$cport))->localhost:$((16#$sport))"

out="$(PROOT_DN_NET=force timeout 60 "$PROOT" -r / python3 -c "$script" 6 2>&1)"
sport="$(sed -n 's/^ports \([0-9A-F]*\) .*/\1/p' <<<"$out")"
sport4="$(printf '%04X' "0x${sport:-0}")"
check "tcp6 listening socket" "$out" "00000000000000000000000001000000:$sport4 00000000000000000000000000000000:0000 0A"

out="$(PROOT_DN_NET=force timeout 60 "$PROOT" -r / sh -c 'cat /proc/net/tcp | wc -l')"
check "closed sockets left out" "$out" "1"
out="$(PROOT_DN_NET=0 timeout 60 "$PROOT" -r / sh -c 'head -1 /proc/net/tcp')"
check "PROOT_DN_NET=0 keeps the real file" "$out" "local_address"

echo "$fails failed"
[ "$fails" -eq 0 ]
