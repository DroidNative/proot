/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * DroidNative storage: programs and libraries on noexec mounts, and
 * the permissions of FAT-like volumes.
 *
 * The kernel refuses to map a file of a noexec mount with PROT_EXEC,
 * and binfmt handlers never get to see such a file.  PRoot already
 * starts every program through its loader, so only the mappings are
 * left: an executable mapping of such a file becomes an anonymous
 * mapping that the tracee fills with pread(2) before it gets its
 * final protection (chained syscalls), as qemu-user and box64 do
 * with code they translate.  Whether a file counts as executable then
 * depends on its presented mode: always for FAT-like volumes, the
 * image's own mode for disk images, the host mode otherwise.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/mman.h>

#include "extension/dn_storage/dn_storage.h"
#include "syscall/sysnum.h"
#include "syscall/chain.h"
#include "syscall/syscall.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "cli/note.h"

/* Mode FAT-like volumes present, as vfat with the usual umask 022.  */
#define FAT_MODE 0755

/**
 * Whether the regular file @host_path counts as executable although
 * the kernel says it isn't (@host is its host stat): files of disk
 * images by their own mode, files on noexec mounts by the mode PRoot
 * presents.
 */
static bool presented_exec(const char *host_path, const struct stat *host)
{
	mode_t mode;

	if (dn_image_active() && dn_image_presented_mode(host_path, &mode) == 0)
		return (mode & 0111) != 0;
	if (!dn_noexec(host_path))
		return false;
	if (dn_fat_path(host_path))
		return true;
	return (host->st_mode & 0111) != 0;
}

/**
 * Whether execve(2) may run @host_path although access(X_OK) failed:
 * the loader's mappings are copied when the mount is noexec (see
 * handle_mmap_enter()), and the mode bits of the host don't matter to
 * the loader.
 */
bool dn_exec_allowed(const char *host_path)
{
	struct stat host;

	if (stat(host_path, &host) < 0 || !S_ISREG(host.st_mode))
		return false;
	return presented_exec(host_path, &host);
}

/* mmap(2) */

static bool is_old_mmap(const Tracee *tracee)
{
	/* mmap(2) of i386 takes a pointer to its arguments.  */
#if defined(ARCH_X86)
	(void) tracee;
	return true;
#elif defined(ARCH_X86_64)
	return get_abi(tracee) == ABI_2;
#else
	(void) tracee;
	return false;
#endif
}

/**
 * Replace an executable mapping of a file on a noexec mount with an
 * anonymous one, see handle_mmap_exit().
 */
static int handle_mmap_enter(Tracee *tracee, Sysnum sysnum)
{
	word_t prot = peek_reg(tracee, CURRENT, SYSARG_3);
	word_t flags = peek_reg(tracee, CURRENT, SYSARG_4);
	int fd = (int) peek_reg(tracee, CURRENT, SYSARG_5);
	char path[64];

	if (sysnum == PR_mmap && is_old_mmap(tracee))
		return 0;
	if ((prot & PROT_EXEC) == 0 || (flags & MAP_ANONYMOUS) != 0 || fd < 0)
		return 0;
	// A shared writable mapping can't be a copy
	if ((flags & MAP_TYPE) != MAP_PRIVATE && (prot & PROT_WRITE) != 0)
		return 0;

	snprintf(path, sizeof(path), "/proc/%d/fd/%d", tracee->pid, fd);
	if (!dn_noexec(path))
		return 0;

	poke_reg(tracee, SYSARG_3, PROT_READ | PROT_WRITE);
	poke_reg(tracee, SYSARG_4, (flags & ~(word_t) MAP_TYPE) | MAP_PRIVATE | MAP_ANONYMOUS);
	poke_reg(tracee, SYSARG_5, (word_t) -1);
	poke_reg(tracee, SYSARG_6, 0);

	tracee->dn.mmap_copy = true;
	tracee->sysexit_pending = true;
	tracee->restart_how = PTRACE_SYSCALL;
	return 0;
}

/**
 * Fill the anonymous mapping made by handle_mmap_enter() from the file,
 * then give it the protection the tracee asked for:
 *
 *     pread64(fd, address, length, offset)
 *     mprotect(address, length, prot)
 *
 * The tracee gets the address as the result of its mmap(2).
 */
static void handle_mmap_exit(Tracee *tracee)
{
	word_t address = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	word_t length = peek_reg(tracee, ORIGINAL, SYSARG_2);
	word_t prot = peek_reg(tracee, ORIGINAL, SYSARG_3);
	word_t fd = peek_reg(tracee, ORIGINAL, SYSARG_5);
	uint64_t offset = peek_reg(tracee, ORIGINAL, SYSARG_6);
	uint32_t low, high;

	tracee->dn.mmap_copy = false;

	if ((long) address < 0 && (long) address > -4096)
		return;

	if (get_sysnum(tracee, ORIGINAL) == PR_mmap2)
		offset *= 4096;

	low = (uint32_t) offset;
	high = (uint32_t) (offset >> 32);

#if defined(ARCH_X86_64) || defined(ARCH_ARM64)
	if (!is_32on64_mode(tracee))
		register_chained_syscall(tracee, PR_pread64, fd, address, length, offset, 0, 0);
	else
#endif
	{
#if defined(ARCH_ARM_EABI) || defined(ARCH_ARM64)
		// EABI aligns 64-bit arguments on a register pair
		register_chained_syscall(tracee, PR_pread64, fd, address, length, 0, low, high);
#else
		register_chained_syscall(tracee, PR_pread64, fd, address, length, low, high, 0);
#endif
	}
	register_chained_syscall(tracee, PR_mprotect, address, length, prot, 0, 0, 0);
	force_chain_final_result(tracee, address);
}

/* access(2) */

/**
 * Drop X_OK from an access(2)-like check of a regular file on a noexec
 * mount that counts as executable: the kernel would deny it for the
 * mount alone.
 */
static void handle_access_enter(Tracee *tracee, Reg path_reg, Reg mode_reg)
{
	word_t mode = peek_reg(tracee, CURRENT, mode_reg);
	char path[PATH_MAX];
	struct stat host;

	if ((mode & X_OK) == 0)
		return;
	if (read_path(tracee, path, peek_reg(tracee, CURRENT, path_reg)) < 0)
		return;
	if (stat(path, &host) < 0 || !S_ISREG(host.st_mode))
		return;
	if (presented_exec(path, &host))
		poke_reg(tracee, mode_reg, mode & ~(word_t) X_OK);
}

/* chmod(2) on FAT-like volumes */

/**
 * chmod(2) can't change anything on a FAT-like volume; like vfat, say
 * it worked.  Returns 1 when the syscall was answered.
 */
static int handle_chmod_enter(Tracee *tracee, Reg path_reg)
{
	char path[PATH_MAX];

	if (read_path(tracee, path, peek_reg(tracee, CURRENT, path_reg)) < 0)
		return 0;
	if (!dn_fat_path(path))
		return 0;
	if (dn_image_active() && dn_image_presented_mode(path, &(mode_t) {0}) == 0)
		return 0;

	poke_reg(tracee, SYSARG_RESULT, 0);
	set_sysnum(tracee, PR_void);
	return 1;
}

int dn_exec_enter_end(Tracee *tracee)
{
	Sysnum sysnum = get_sysnum(tracee, ORIGINAL);

	switch (sysnum) {
	case PR_mmap:
	case PR_mmap2:
		return handle_mmap_enter(tracee, sysnum);

	case PR_access:
		handle_access_enter(tracee, SYSARG_1, SYSARG_2);
		return 0;

	case PR_faccessat:
	case PR_faccessat2:
		handle_access_enter(tracee, SYSARG_2, SYSARG_3);
		return 0;

	case PR_chmod:
		(void) handle_chmod_enter(tracee, SYSARG_1);
		return 0;

	case PR_fchmodat:
		(void) handle_chmod_enter(tracee, SYSARG_2);
		return 0;

	default:
		return 0;
	}
}

/* stat(2) on FAT-like volumes */

/**
 * Present files of FAT-like volumes as vfat does: owned by the user,
 * mode 0755.  fake_id0 comes after this extension and turns the
 * host's uid and gid into the guest's.
 */
static void handle_stat_exit(Tracee *tracee, Reg buf_reg)
{
	word_t address = peek_reg(tracee, ORIGINAL, buf_reg);
	char path[PATH_MAX];
	uint32_t mode;

	if (peek_reg(tracee, CURRENT, SYSARG_RESULT) != 0)
		return;
	if (dn_stat_target(tracee, path) < 0 || !dn_fat_path(path))
		return;
	if (dn_image_active() && dn_image_presented_mode(path, &(mode_t) {0}) == 0)
		return;

	errno = 0;
	mode = peek_uint32(tracee, address + offsetof_stat_mode(tracee));
	if (errno != 0)
		return;
	poke_uint32(tracee, address + offsetof_stat_mode(tracee), (mode & S_IFMT) | FAT_MODE);
	poke_uint32(tracee, address + offsetof_stat_uid(tracee), getuid());
	poke_uint32(tracee, address + offsetof_stat_gid(tracee), getgid());
}

void dn_exec_exit_end(Tracee *tracee)
{
	switch (get_sysnum(tracee, ORIGINAL)) {
	case PR_mmap:
	case PR_mmap2:
		if (tracee->dn.mmap_copy)
			handle_mmap_exit(tracee);
		return;

	case PR_stat:
	case PR_stat64:
	case PR_lstat:
	case PR_lstat64:
	case PR_fstat:
	case PR_fstat64:
		handle_stat_exit(tracee, SYSARG_2);
		return;

	case PR_newfstatat:
	case PR_fstatat64:
		handle_stat_exit(tracee, SYSARG_3);
		return;

	default:
		return;
	}
}

void dn_exec_statx(struct statx_syscall_state *state)
{
	if (!dn_fat_path(state->host_path))
		return;
	if (dn_image_active() && dn_image_presented_mode(state->host_path, &(mode_t) {0}) == 0)
		return;

	state->statx_buf.stx_mode = (state->statx_buf.stx_mode & S_IFMT) | FAT_MODE;
	state->statx_buf.stx_uid = getuid();
	state->statx_buf.stx_gid = getgid();
	state->updated_stats = true;
}
