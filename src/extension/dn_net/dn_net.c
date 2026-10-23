/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 */

/* dn_net: the guest's TCP sockets in /proc/net/tcp and tcp6 (DroidNative).
 *
 * Android denies apps /proc/net/tcp{,6} and the sock_diag netlink socket,
 * so lsof, netstat and ss cannot tell which process owns a connection.
 * Steam's client asks lsof exactly that for every connection of its web
 * UI and rejects all of them without an answer.
 *
 * This extension records TCP sockets of the tracees itself: after a
 * successful bind, listen, connect or accept it chains getsockname,
 * getpeername and getsockopt(SO_TYPE) on the descriptor, with the results
 * in a scratch area below the tracee's stack pointer, and keeps the
 * addresses by socket inode. An open of /proc/net/tcp or tcp6 (also
 * through /proc/<pid>/net) then gets a generated file in the kernel's
 * format, when the real one is unreadable. Sockets no tracee holds any
 * more (scan of /proc/<pid>/fd) are left out. lsof maps the inodes to
 * processes through /proc/<pid>/fd as usual.
 *
 * Enabled when /proc/net/tcp is unreadable at start; PROOT_DN_NET=0 turns
 * it off, PROOT_DN_NET=force also replaces a readable file (tests). */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>

#include "extension/extension.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/chain.h"
#include "syscall/seccomp.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"
#include "tracee/reg.h"
#include "path/temp.h"

/* State */

#define MAX_SOCKS    1024
#define MAX_PENDING  128
#define SCRATCH_GAP  2048  // below the stack pointer, past any red zone

#define TCP_ESTABLISHED 0x01
#define TCP_CLOSE       0x07
#define TCP_LISTEN      0x0A

typedef struct {
	bool used;
	ino_t ino;
	int state;
	struct sockaddr_storage local;
	struct sockaddr_storage remote;
} Sock;

// Results of the chained queries, as they lie in the tracee's memory
typedef struct {
	struct sockaddr_storage local;
	struct sockaddr_storage remote;
	uint32_t local_len;
	uint32_t remote_len;
	int32_t type;
	uint32_t type_len;
} Scratch;

typedef struct {
	bool used;
	pid_t pid;
	int fd;
	bool listening;
	word_t scratch;
	bool ok[3];       // getsockname, getpeername, getsockopt
} Pending;

static Sock socks[MAX_SOCKS];
static size_t next_evict;
static Pending pending[MAX_PENDING];
static bool force_synthesis;

/* Recording */

static Pending *pending_of(pid_t pid)
{
	size_t i;

	for (i = 0; i < MAX_PENDING; i++)
		if (pending[i].used && pending[i].pid == pid)
			return &pending[i];
	return NULL;
}

static Sock *sock_slot(ino_t ino)
{
	size_t i;
	Sock *free_slot = NULL;

	for (i = 0; i < MAX_SOCKS; i++) {
		if (socks[i].used && socks[i].ino == ino)
			return &socks[i];
		if (!socks[i].used && free_slot == NULL)
			free_slot = &socks[i];
	}
	if (free_slot != NULL)
		return free_slot;
	// Full: replace round-robin (stale entries are the likely victims)
	free_slot = &socks[next_evict];
	next_evict = (next_evict + 1) % MAX_SOCKS;
	return free_slot;
}

// After bind/listen/connect/accept: query the socket in the tracee
static void query_socket(Tracee *tracee, int fd, bool listening, word_t result)
{
	Scratch init;
	Pending *p = NULL;
	word_t scratch;
	size_t i;

	// A chain the tracee never finished (killed meanwhile) is reused
	p = pending_of(tracee->pid);
	for (i = 0; i < MAX_PENDING && p == NULL; i++)
		if (!pending[i].used)
			p = &pending[i];
	if (p == NULL)
		return;

	scratch = (peek_reg(tracee, CURRENT, STACK_POINTER) - SCRATCH_GAP - sizeof(Scratch)) & ~(word_t) 15;
	memset(&init, 0, sizeof(init));
	init.local_len = sizeof(init.local);
	init.remote_len = sizeof(init.remote);
	init.type_len = sizeof(init.type);
	if (write_data(tracee, scratch, &init, sizeof(init)) < 0)
		return;

	if (register_chained_syscall(tracee, PR_getsockname, fd,
			scratch + offsetof(Scratch, local), scratch + offsetof(Scratch, local_len), 0, 0, 0) < 0
	    || register_chained_syscall(tracee, PR_getpeername, fd,
			scratch + offsetof(Scratch, remote), scratch + offsetof(Scratch, remote_len), 0, 0, 0) < 0
	    || register_chained_syscall(tracee, PR_getsockopt, fd, SOL_SOCKET, SO_TYPE,
			scratch + offsetof(Scratch, type), scratch + offsetof(Scratch, type_len), 0) < 0)
		return;
	force_chain_final_result(tracee, result);

	memset(p, 0, sizeof(*p));
	p->used = true;
	p->pid = tracee->pid;
	p->fd = fd;
	p->listening = listening;
	p->scratch = scratch;
}

static void record(Tracee *tracee, Pending *p)
{
	char path[64];
	struct stat st;
	Scratch s;
	Sock *sock;
	int family;

	if (!p->ok[0] || !p->ok[2])
		return;
	if (read_data(tracee, &s, p->scratch, sizeof(s)) < 0)
		return;
	family = s.local.ss_family;
	if (s.type != SOCK_STREAM || (family != AF_INET && family != AF_INET6))
		return;
	snprintf(path, sizeof(path), "/proc/%d/fd/%d", p->pid, p->fd);
	if (stat(path, &st) < 0)
		return;

	sock = sock_slot(st.st_ino);
	memset(sock, 0, sizeof(*sock));
	sock->used = true;
	sock->ino = st.st_ino;
	sock->local = s.local;
	if (p->ok[1]) {
		sock->remote = s.remote;
		sock->state = TCP_ESTABLISHED;
	}
	else {
		sock->remote.ss_family = family;
		sock->state = p->listening ? TCP_LISTEN : TCP_CLOSE;
	}
}

/* /proc/net/tcp */

// Socket inodes some process of ours still holds
static bool is_live(ino_t ino, ino_t *live, size_t nb_live)
{
	size_t i;

	for (i = 0; i < nb_live; i++)
		if (live[i] == ino)
			return true;
	return false;
}

static size_t collect_live(ino_t *live, size_t max)
{
	struct dirent *pid_entry;
	size_t n = 0;
	DIR *proc;

	proc = opendir("/proc");
	if (proc == NULL)
		return 0;
	while ((pid_entry = readdir(proc)) != NULL && n < max) {
		struct dirent *fd_entry;
		char dir[64];
		DIR *fds;

		if (pid_entry->d_name[0] < '0' || pid_entry->d_name[0] > '9')
			continue;
		snprintf(dir, sizeof(dir), "/proc/%s/fd", pid_entry->d_name);
		fds = opendir(dir);
		if (fds == NULL)
			continue;
		while ((fd_entry = readdir(fds)) != NULL && n < max) {
			char link[PATH_MAX];
			char target[64];
			unsigned long ino;
			ssize_t len;

			if (fd_entry->d_name[0] == '.')
				continue;
			snprintf(link, sizeof(link), "%s/%s", dir, fd_entry->d_name);
			len = readlink(link, target, sizeof(target) - 1);
			if (len <= 0)
				continue;
			target[len] = '\0';
			if (sscanf(target, "socket:[%lu]", &ino) == 1)
				live[n++] = (ino_t) ino;
		}
		closedir(fds);
	}
	closedir(proc);
	return n;
}

static void print_addr4(FILE *out, const struct sockaddr_storage *ss)
{
	const struct sockaddr_in *in = (const struct sockaddr_in *) ss;

	// The kernel prints the raw 32-bit words, in host byte order
	fprintf(out, "%08X:%04X", (unsigned) in->sin_addr.s_addr, (unsigned) ntohs(in->sin_port));
}

static void print_addr6(FILE *out, const struct sockaddr_storage *ss)
{
	const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *) ss;
	uint32_t w[4];

	memcpy(w, &in6->sin6_addr, sizeof(w));
	fprintf(out, "%08X%08X%08X%08X:%04X", (unsigned) w[0], (unsigned) w[1],
		(unsigned) w[2], (unsigned) w[3], (unsigned) ntohs(in6->sin6_port));
}

static void write_table(FILE *out, int family)
{
	static ino_t live[8192];
	size_t nb_live = collect_live(live, sizeof(live) / sizeof(live[0]));
	unsigned uid = (unsigned) getuid();
	size_t i;
	int sl = 0;

	if (family == AF_INET)
		fputs("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
		      "   uid  timeout inode\n", out);
	else
		fputs("  sl  local_address                         remote_address"
		      "                        st tx_queue rx_queue tr tm->when retrnsmt"
		      "   uid  timeout inode\n", out);

	for (i = 0; i < MAX_SOCKS; i++) {
		Sock *sock = &socks[i];

		if (!sock->used)
			continue;
		if (!is_live(sock->ino, live, nb_live)) {
			sock->used = false;
			continue;
		}
		if (sock->local.ss_family != family)
			continue;
		fprintf(out, "%4d: ", sl++);
		if (family == AF_INET) {
			print_addr4(out, &sock->local);
			fputc(' ', out);
			print_addr4(out, &sock->remote);
		}
		else {
			print_addr6(out, &sock->local);
			fputc(' ', out);
			print_addr6(out, &sock->remote);
		}
		fprintf(out, " %02X 00000000:00000000 00:00000000 00000000 %5u %8d %lu 1"
			" 0000000000000000 100 0 0 10 0\n",
			sock->state, uid, 0, (unsigned long) sock->ino);
	}
}

// AF_INET for /proc/net/tcp, AF_INET6 for tcp6, else 0
static int table_of(const char *path)
{
	const char *rest;

	if (strncmp(path, "/proc/", 6) != 0)
		return 0;
	rest = path + 6;
	if (strncmp(rest, "self/", 5) == 0)
		rest += 5;
	else if (strncmp(rest, "thread-self/", 12) == 0)
		rest += 12;
	else if (rest[0] >= '0' && rest[0] <= '9') {
		rest += strspn(rest, "0123456789");
		if (*rest++ != '/')
			return 0;
	}
	if (strcmp(rest, "net/tcp") == 0)
		return AF_INET;
	if (strcmp(rest, "net/tcp6") == 0)
		return AF_INET6;
	return 0;
}

static void maybe_synthesize(Tracee *tracee, Reg reg)
{
	char path[PATH_MAX];
	const char *copy;
	FILE *out;
	int family;

	if (get_sysarg_path(tracee, path, reg) < 0)
		return;
	family = table_of(path);
	if (family == 0)
		return;
	if (!force_synthesis && access(path, R_OK) == 0)
		return;

	copy = create_temp_file(tracee->ctx, "proot-net");
	out = (copy != NULL ? fopen(copy, "w") : NULL);
	if (out == NULL)
		return;
	write_table(out, family);
	if (fclose(out) == 0)
		(void) set_sysarg_path(tracee, copy, reg);
}

/* Extension */

static FilteredSysnum filtered_sysnums[] = {
	{ PR_bind,	FILTER_SYSEXIT },
	{ PR_listen,	FILTER_SYSEXIT },
	{ PR_connect,	FILTER_SYSEXIT },
	{ PR_accept,	FILTER_SYSEXIT },
	{ PR_accept4,	FILTER_SYSEXIT },
	{ PR_open,	0 },
	{ PR_openat,	0 },
	FILTERED_SYSNUM_END,
};

int dn_net_callback(Extension *extension, ExtensionEvent event, intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
	Tracee *tracee;

	switch (event) {
	case INITIALIZATION: {
		const char *mode = getenv("PROOT_DN_NET");

		if (mode != NULL && strcmp(mode, "0") == 0)
			return -1;
		force_synthesis = (mode != NULL && strcmp(mode, "force") == 0);
		if (!force_synthesis && access("/proc/net/tcp", R_OK) == 0)
			return -1;
		extension->filtered_sysnums = filtered_sysnums;
		return 0;
	}

	case INHERIT_PARENT:
		return 0;       // shared: the socket table is global

	case SYSCALL_ENTER_END:
		tracee = TRACEE(extension);
		if (tracee->status < 0)
			return 0;
		switch (get_sysnum(tracee, CURRENT)) {
		case PR_open:
			maybe_synthesize(tracee, SYSARG_1);
			break;
		case PR_openat:
			maybe_synthesize(tracee, SYSARG_2);
			break;
		default:
			break;
		}
		return 0;

	case SYSCALL_EXIT_END: {
		word_t result;
		Sysnum sysnum;

		tracee = TRACEE(extension);
		sysnum = get_sysnum(tracee, ORIGINAL);
		result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		switch (sysnum) {
		case PR_bind:
		case PR_listen:
			if ((int) result == 0)
				query_socket(tracee, (int) peek_reg(tracee, ORIGINAL, SYSARG_1),
					     sysnum == PR_listen, result);
			break;
		case PR_connect:
			if ((int) result == 0 || (int) result == -EINPROGRESS)
				query_socket(tracee, (int) peek_reg(tracee, ORIGINAL, SYSARG_1), false, result);
			break;
		case PR_accept:
		case PR_accept4:
			if ((int) result >= 0)
				query_socket(tracee, (int) result, false, result);
			break;
		default:
			break;
		}
		return 0;
	}

	case SYSCALL_CHAINED_EXIT: {
		Pending *p;
		bool ok;

		tracee = TRACEE(extension);
		p = pending_of(tracee->pid);
		if (p == NULL)
			return 0;
		ok = ((int) peek_reg(tracee, CURRENT, SYSARG_RESULT) == 0);
		switch (get_sysnum(tracee, CURRENT)) {
		case PR_getsockname: p->ok[0] = ok; break;
		case PR_getpeername: p->ok[1] = ok; break;
		case PR_getsockopt:
			// The last query of the chain
			p->ok[2] = ok;
			record(tracee, p);
			p->used = false;
			break;
		default:
			break;
		}
		return 0;
	}

	default:
		return 0;
	}
}
