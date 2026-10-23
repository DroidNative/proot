/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * DroidNative storage: exec on noexec mounts, FAT-like volumes,
 * emulated FUSE file-systems and disk images.  See
 * doc/droidnative-storage.md.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 */

#ifndef DN_STORAGE_H
#define DN_STORAGE_H

#include <stdbool.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/statx.h"

/* Command line, see cli/proot.h.  */
extern int dn_storage_add_fat(const char *host_path);
extern int dn_storage_enable_fuse(void);
extern int dn_storage_add_image(const char *value, char binding[PATH_MAX]);
extern int dn_storage_initialize(Tracee *tracee);

/* Event loop, see tracee/event.c.  */
extern pid_t dn_storage_waitpid(int *status);
extern void resume_parked_tracee(Tracee *tracee);

/* execve(2), see execve/enter.c.  */
extern bool dn_exec_allowed(const char *host_path);

/* mount(2) and umount(2), see syscall/enter.c.  */
extern int dn_storage_mount(Tracee *tracee, const char *source_user, const char *fstype,
			    const char *data, char host_path[PATH_MAX]);
extern void dn_storage_unmounted(const char *host_path);

/* Helpers shared by the parts of this extension (dn_storage.c).  */
extern bool dn_path_in(const char *path, const char *root);
extern bool dn_noexec(const char *host_path);
extern int dn_fd_path(const Tracee *tracee, int fd, char path[PATH_MAX]);
extern int dn_read_host_arg(const Tracee *tracee, char path[PATH_MAX], Reg reg);
extern int dn_stat_target(Tracee *tracee, char path[PATH_MAX]);
extern mode_t dn_umask(const Tracee *tracee);

/* exec.c */
extern bool dn_fat_path(const char *host_path);
extern int dn_exec_enter_end(Tracee *tracee);
extern void dn_exec_exit_end(Tracee *tracee);
extern void dn_exec_chained_exit(Tracee *tracee);
extern void dn_exec_statx(struct statx_syscall_state *state);

/* fuse.c */
extern bool dn_fuse_active(void);
extern int dn_fuse_host_path(Tracee *tracee, const char *host_path, bool final);
extern int dn_fuse_translated(Tracee *tracee, const char *host_path);
extern int dn_fuse_mount(Tracee *tracee, const char *data, char host_path[PATH_MAX]);
extern void dn_fuse_unmounted(const char *host_path);
extern int dn_fuse_enter_end(Tracee *tracee);
extern void dn_fuse_exit_end(Tracee *tracee);
extern void dn_fuse_chained_exit(Tracee *tracee);
extern int dn_fuse_poll(void);
extern const char *dn_fuse_device(void);

/* image.c */
extern int dn_image_initialize(Tracee *tracee);
extern bool dn_image_active(void);
extern int dn_image_enter_start(Tracee *tracee);
extern int dn_image_translated(Tracee *tracee, char host_path[PATH_MAX]);
extern void dn_image_exit_end(Tracee *tracee);
extern void dn_image_statx(struct statx_syscall_state *state);
extern int dn_image_presented_mode(const char *host_path, mode_t *mode);
extern int dn_image_mount(Tracee *tracee, const char *source_user, const char *data, char host_path[PATH_MAX]);
extern void dn_image_unmounted(const char *host_path);
struct readlink_proc_fd_state;
extern void dn_image_proc_fd(struct readlink_proc_fd_state *state);

#endif /* DN_STORAGE_H */
