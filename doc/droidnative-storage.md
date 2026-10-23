# DroidNative storage extension

PRoot fork for DroidNative (Android, no root). The extension in
`src/extension/dn_storage/` makes Android storage usable by a Linux guest.
It is always loaded (last, so it sees syscalls before link2symlink and
fake_id0); the options below switch on its parts.

## Options

| Option | Effect |
|---|---|
| `--fat-bind=HOST[:GUEST]` | like `-b`, for a volume without POSIX permissions: owned by the user, mode 0755, chmod succeeds without effect |
| `--fuse` | emulates `/dev/fuse` and FUSE mounts, read-only |
| `--image=DIR:GUEST` | mounts the disk image `DIR` (created when empty) at `GUEST`; also `mount -t dnimage DIR GUEST` in the guest |

## Exec on noexec mounts (`exec.c`)

Android mounts all shared storage and SD cards noexec. The kernel checks
noexec in `do_open_execat()` before any binfmt handler is looked up and
refuses `mmap(PROT_EXEC)` of such files, so binfmt_misc or a wrapper around
PRoot can't help. PRoot already starts every program through its loader;
what remained were the mappings:

- seccomp traces `mmap`/`mmap2` only with `PROT_EXEC` and without
  `MAP_ANONYMOUS` (`FILTER_PROT_EXEC`, `syscall/seccomp.c`).
- Such a mapping of a file on a noexec mount becomes an anonymous RW
  mapping, then chained `pread64` + `mprotect` give it the content and the
  protection asked for (as qemu-user and box64 copy code they translate).
- `execve` (`execve/enter.c`) and `access(X_OK)` use the mode PRoot
  presents: always executable on `--fat-bind` volumes, the image's mode in
  disk images, the host mode elsewhere.

Copies are per process and not shared between processes.

### Exec of written file pages (`execmod`)

Android's SELinux policy denies apps `execmod`: `mprotect(PROT_EXEC)` of
pages of a private file mapping that were written. Wine maps PE files this
way and relocates them in place, so without help every Wine process fails
in `map_image_into_view` ("noexec filesystem?"). The same error comes from
noexec mounts when a file was mapped without `PROT_EXEC` first.

- seccomp traces `mprotect` only with `PROT_EXEC` (`FILTER_MPROTECT_EXEC`,
  `syscall/seccomp.c`); `handle_mprotect_enter()` asks for the exit stage.
- On `-EACCES`, `handle_mprotect_exit()` checks in `/proc/<pid>/maps` that
  the range is private memory (at most 64 MiB), saves it through
  `/proc/<pid>/mem` and chains `mmap(MAP_ANONYMOUS | MAP_FIXED)` (RW) and
  the original `mprotect`. `dn_exec_chained_exit()` writes the saved
  content back after the `mmap`; the tracee gets the result of the
  `mprotect`.
- Other threads see zeroes in the range between the `mmap` and the write;
  programs change the protection of code they are still setting up.

## FUSE (`fuse.c`)

`open("/dev/fuse")` (a placeholder bound there) becomes `socket(AF_UNIX,
SOCK_SEQPACKET)` connected to PRoot (chained `connect`): one packet per
FUSE message, as with the real device. `mount(2)` of type `fuse*` with
`fd=N` binds a directory of PRoot's temporary directory at the target and
sends INIT. PRoot then plays the kernel: entering a directory lists it
(OPENDIR, READDIR, LOOKUP, READLINK) into placeholders, opening or
executing a file fetches it whole (OPEN, READ, RELEASE). Programs run from
these copies. Writes give EROFS. When the daemon quits, the mount goes
away (`fusermount -u` can't work: emulated mounts are not in
`/proc/mounts`).

The daemon is a tracee, so a syscall can't wait for it in place: the
tracee "parks" (`tracee->dn.parked`), stays stopped at its untouched
sysenter stage, and `resume_parked_tracee()` (`tracee/event.c`) handles the
same stop again once the daemon answered. While FUSE mounts exist the event
loop polls the daemons' sockets between `waitpid(WNOHANG)` calls
(`dn_storage_waitpid()`, SIGCHLD wakes it).

## Disk images (`image.c`)

```
DIR/dnimage.db          SQLite: meta, inodes (mode, uid, gid, rdev,
                        data = symlink target or content UUID), dentries
DIR/data/ab/ab12...     content of each regular file
```

Names, case, permissions, owners, symlinks, hard links, FIFOs and device
numbers live only in the database. The guest sees a shadow tree in PRoot's
temporary directory (`dnimage-<uuid>/tree`, bound at the mount point):
directories, symlinks and FIFOs as they are, regular files as 36 byte
placeholders holding the content's UUID. Path translation leads to the
content file instead (`TRANSLATED_PATH`), stat results get mode, owner,
link count and device number from the database, and every change of the
tree (mkdir, unlink, rename, link, symlink, mknod, creating open, chmod,
chown) is done by PRoot on the database and the shadow in one transaction.
The shadow is rebuilt when its generation differs from the database's
(e.g. image used on another device). `/proc/PID/fd` names content files
by their path in the image.

Default owner is the host uid, which fake_id0 shows as the guest's user.

## Other changes

- Extensions keep their order in child tracees (they were reversed per
  generation).
- `mount(2)` emulation returns errors from these file systems.
- Patches 0001 to 0005 of DroidNative (bubblewrap/Flatpak support, V4L2,
  memfd SysV shm, exit status, pivot_root) are part of this tree.
- Seccomp filters of the program itself (`tracee/event.c`,
  `tracee/seccomp.c`). PRoot used to take every seccomp SIGSYS for one
  of Android's app filter and answer it (ENOSYS by default). A SIGSYS
  whose `si_errno` (the filter's SECCOMP_RET_DATA) is not 0 now reaches
  the program: Android's filter traps with 0, Chromium style sandboxes
  (Firefox's content processes) use the handler index. Also, a trap that
  hits while SIGSYS is blocked (new threads start with all signals
  blocked and call `set_robust_list`, which Android traps) makes the
  kernel reset the program's SIGSYS handler; PRoot records the handler
  at `rt_sigaction` exit (per thread group as a fallback for threads it
  has not linked to their parent yet) and reinstalls it with an
  injected `rt_sigaction` before answering such a trap
  (`restore_sigsys_action`). Without both, LibreWolf's content processes
  crashed (SIGSEGV, later SIGSYS).

## Tests

`tests/droidnative/run.sh <build dir>` builds PRoot for the PC and runs 23
checks with the PC as guest (`-r /`). Needs a noexec tmpfs writable by the
user (`/run/lock`), libfuse3 headers and git. Further suites with the same
argument: `binfmt.sh` (binfmt_misc emulation), `tracer.sh` (hidden
TracerPid), `net.sh` (`/proc/net/tcp` from dn_net) and `seccomp.sh` (the
program's own seccomp filter, `seccomp-trap.c`).
