/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * DroidNative storage, see dn_storage.h and doc/droidnative-storage.md.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statfs.h>
#include <sys/statvfs.h> /* ST_NOEXEC, */
#include <sys/wait.h>
#include <unistd.h>
#include <talloc.h>

#include "extension/dn_storage/dn_storage.h"
#include "extension/extension.h"
#include "syscall/sysnum.h"
#include "syscall/seccomp.h"
#include "syscall/syscall.h"
#include "tracee/mem.h"
#include "path/path.h"
#include "cli/note.h"

#include "attribute.h"

/* Configuration: shared by all tracees.  */
static char **fat_roots;
static size_t nb_fat_roots;

/* Host paths given to --fat-bind, resolved once the extension starts.  */
int dn_storage_add_fat(const char *host_path)
{
	char **roots;

	roots = realloc(fat_roots, (nb_fat_roots + 1) * sizeof(char *));
	if (roots == NULL)
		return -1;
	fat_roots = roots;
	fat_roots[nb_fat_roots] = strdup(host_path);
	if (fat_roots[nb_fat_roots] == NULL)
		return -1;
	nb_fat_roots++;
	return 0;
}

/* Helpers */

/**
 * Whether @path is @root or below it (both canonical host paths).
 */
bool dn_path_in(const char *path, const char *root)
{
	size_t len = strlen(root);

	if (len == 1 && root[0] == '/')
		return true;
	return strncmp(path, root, len) == 0 && (path[len] == '\0' || path[len] == '/');
}

/**
 * Whether @host_path lives on a file-system mounted noexec.
 */
bool dn_noexec(const char *host_path)
{
	struct statfs info;

	if (statfs(host_path, &info) < 0)
		return false;
	return (info.f_flags & ST_NOEXEC) != 0;
}

/**
 * Copy into @path the host path of the @tracee's file descriptor @fd.
 */
int dn_fd_path(const Tracee *tracee, int fd, char path[PATH_MAX])
{
	return readlink_proc_pid_fd(tracee->pid, fd, path);
}

/**
 * Copy into @path the string the @reg argument of the current syscall
 * points to, as it was when the sysenter stage ended: the translated
 * host path for the path arguments.
 */
int dn_read_host_arg(const Tracee *tracee, char path[PATH_MAX], Reg reg)
{
	word_t address = peek_reg(tracee, MODIFIED, reg);
	int status;

	if (address == 0)
		return -EFAULT;
	status = read_path(tracee, path, address);
	return status < 0 ? status : 0;
}

/**
 * Copy into @path the host path of what the stat(2)-like syscall the
 * @tracee is leaving looked at.  This function returns -errno if it
 * can't tell, otherwise 0.
 */
int dn_stat_target(Tracee *tracee, char path[PATH_MAX])
{
	int status;

	switch (get_sysnum(tracee, ORIGINAL)) {
	case PR_stat:
	case PR_stat64:
	case PR_lstat:
	case PR_lstat64:
	case PR_oldstat:
	case PR_oldlstat:
		return dn_read_host_arg(tracee, path, SYSARG_1);

	case PR_fstat:
	case PR_fstat64:
		return dn_fd_path(tracee, (int) peek_reg(tracee, ORIGINAL, SYSARG_1), path);

	case PR_newfstatat:
	case PR_fstatat64:
		status = dn_read_host_arg(tracee, path, SYSARG_2);
		if (status < 0)
			return status;
		if (path[0] != '\0')
			return 0;
		return dn_fd_path(tracee, (int) peek_reg(tracee, ORIGINAL, SYSARG_1), path);

	default:
		return -EINVAL;
	}
}

/**
 * Return the file mode creation mask of @tracee.
 */
mode_t dn_umask(const Tracee *tracee)
{
	char path[64];
	char line[128];
	mode_t mask = 022;
	FILE *file;

	snprintf(path, sizeof(path), "/proc/%d/status", tracee->pid);
	file = fopen(path, "r");
	if (file == NULL)
		return mask;
	while (fgets(line, sizeof(line), file) != NULL) {
		if (strncmp(line, "Umask:", 6) == 0) {
			mask = (mode_t) strtoul(line + 6, NULL, 8) & 0777;
			break;
		}
	}
	fclose(file);
	return mask;
}

/* FAT-like volumes */

/**
 * Whether @host_path is on a volume bound with --fat-bind.
 */
bool dn_fat_path(const char *host_path)
{
	size_t i;

	for (i = 0; i < nb_fat_roots; i++) {
		if (dn_path_in(host_path, fat_roots[i]))
			return true;
	}
	return false;
}

/* mount(2) */

/**
 * mount(2) of a file-system this extension emulates: copies into
 * @host_path what to bind at the mount point.  Returns 0 if @fstype
 * is none of these, -errno on error, otherwise 1.
 */
int dn_storage_mount(Tracee *tracee, const char *source_user, const char *fstype,
		     const char *data, char host_path[PATH_MAX])
{
	if (strncmp(fstype, "fuse", 4) == 0 && dn_fuse_device() != NULL)
		return dn_fuse_mount(tracee, data, host_path);
	if (strcmp(fstype, "dnimage") == 0)
		return dn_image_mount(tracee, source_user, data, host_path);
	return 0;
}

/**
 * The binding of @host_path was removed by umount(2).
 */
void dn_storage_unmounted(const char *host_path)
{
	dn_fuse_unmounted(host_path);
	dn_image_unmounted(host_path);
}

/* Event loop */

/**
 * waitpid(-1, @status, __WALL), which also answers the emulated FUSE
 * file-systems while it waits (see dn_fuse_poll()).
 */
pid_t dn_storage_waitpid(int *status)
{
	pid_t pid;

	if (!dn_fuse_active())
		return waitpid(-1, status, __WALL);

	for (;;) {
		pid = waitpid(-1, status, __WALL | WNOHANG);
		if (pid != 0)
			return pid;
		if (dn_fuse_poll() == -EINTR) {
			errno = EINTR;
			return -1;
		}
	}
}

/* Extension */

static FilteredSysnum filtered_sysnums[] = {
	{ PR_mmap,		FILTER_PROT_EXEC },
	{ PR_mmap2,		FILTER_PROT_EXEC },
	{ PR_mprotect,		FILTER_MPROTECT_EXEC },
	{ PR_fchmod,		0 },
	{ PR_fchown,		0 },
	{ PR_fchown32,		0 },
	{ PR_fstat,		FILTER_SYSEXIT },
	{ PR_fstat64,		FILTER_SYSEXIT },
	{ PR_fstatat64,		FILTER_SYSEXIT },
	{ PR_newfstatat,	FILTER_SYSEXIT },
	{ PR_stat,		FILTER_SYSEXIT },
	{ PR_stat64,		FILTER_SYSEXIT },
	{ PR_lstat,		FILTER_SYSEXIT },
	{ PR_lstat64,		FILTER_SYSEXIT },
	{ PR_connect,		0 },
	{ PR_socket,		FILTER_SYSEXIT },
	FILTERED_SYSNUM_END,
};

static int dn_storage_callback(Extension *extension, ExtensionEvent event,
			       intptr_t data1, intptr_t data2)
{
	Tracee *tracee;
	int status;

	switch (event) {
	case INITIALIZATION:
		extension->filtered_sysnums = filtered_sysnums;
		return 0;

	case INHERIT_PARENT:
		return 0;	/* Shared configuration.  */

	case SYSCALL_ENTER_START:
		tracee = TRACEE(extension);
		if (dn_image_active())
			return dn_image_enter_start(tracee);
		return 0;

	case HOST_PATH:
		if (!dn_fuse_active())
			return 0;
		tracee = TRACEE(extension);
		return dn_fuse_host_path(tracee, (const char *) data1, (bool) data2);

	case TRANSLATED_PATH:
		tracee = TRACEE(extension);
		if (dn_image_active()) {
			status = dn_image_translated(tracee, (char *) data1);
			if (status != 0)
				return status;
		}
		if (dn_fuse_active())
			return dn_fuse_translated(tracee, (const char *) data1);
		return 0;

	case SYSCALL_ENTER_END:
		if ((int) data1 < 0)
			return 0;
		tracee = TRACEE(extension);
		status = dn_exec_enter_end(tracee);
		if (status != 0)
			return status;
		if (dn_fuse_device() != NULL)
			return dn_fuse_enter_end(tracee);
		return 0;

	case SYSCALL_EXIT_END:
		tracee = TRACEE(extension);
		if (tracee->dn.fuse_open != 0)
			dn_fuse_exit_end(tracee);
		if (dn_image_active())
			dn_image_exit_end(tracee);
		dn_exec_exit_end(tracee);
		return 0;

	case SYSCALL_CHAINED_EXIT:
		tracee = TRACEE(extension);
		if (tracee->dn.fuse_open != 0)
			dn_fuse_chained_exit(tracee);
		if (tracee->dn.mprotect_copy != 0)
			dn_exec_chained_exit(tracee);
		return 0;

	case STATX_SYSCALL:
		if (dn_image_active())
			dn_image_statx((struct statx_syscall_state *) data1);
		dn_exec_statx((struct statx_syscall_state *) data1);
		return 0;

	case READLINK_PROC_FD:
		if (dn_image_active())
			dn_image_proc_fd((struct readlink_proc_fd_state *) data1);
		return 0;

	default:
		(void) data2;
		return 0;
	}
}

/**
 * Start the extension for @tracee, once the command line is done: it
 * comes last, hence first in the list of extensions, so it sees the
 * syscalls before link2symlink and fake_id0 do.
 */
int dn_storage_initialize(Tracee *tracee)
{
	char resolved[PATH_MAX];
	size_t i;
	int status;

	for (i = 0; i < nb_fat_roots; i++) {
		if (realpath(fat_roots[i], resolved) == NULL)
			continue;
		free(fat_roots[i]);
		fat_roots[i] = strdup(resolved);
		if (fat_roots[i] == NULL)
			return -1;
	}

	status = initialize_extension(tracee, dn_storage_callback, NULL);
	if (status < 0)
		return status;

	return dn_image_initialize(tracee);
}
