/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

/* binfmt_misc emulation (DroidNative).
 *
 * The kernel's binfmt_misc needs root, so PRoot matches executables
 * against the guest's systemd-style rules itself: every *.conf in
 * /etc/binfmt.d and /usr/lib/binfmt.d of the guest rootfs (a file in /etc
 * hides the one of the same name in /usr/lib), one rule per line:
 *
 *     :name:type:offset:magic:mask:interpreter:flags
 *
 * type M compares magic (with mask) at offset, type E the file name
 * extension. Files are read in name order, the first matching rule wins.
 * A match runs "interpreter path args..." like the kernel without the P
 * flag; the other flags are ignored. Rules are re-read when a file or
 * directory changes. PROOT_NO_BINFMT=1 switches this off.
 *
 * Like the kernel's F flag the rules belong to the rootfs, not to a
 * namespace: inside an emulated mount namespace (bubblewrap) the
 * interpreter is looked up there first and else taken from the rootfs. */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <linux/limits.h>

#include "execve/binfmt.h"
#include "execve/execve.h"
#include "path/binding.h"
#include "tracee/tracee.h"

/* Limits */

#define BINFMT_BUF   256  // bytes the kernel reads too (BINPRM_BUF_SIZE)
#define MAX_MAGIC    128
#define MAX_RULES    64
#define MAX_FILES    64

typedef struct {
	bool by_ext;
	size_t offset;
	size_t len;
	unsigned char magic[MAX_MAGIC];
	unsigned char mask[MAX_MAGIC];
	char interp[PATH_MAX];
} Rule;

typedef struct {
	char path[PATH_MAX];
	struct timespec mtime;
} Stamp;

static const char *const rule_dirs[] = { "/etc/binfmt.d", "/usr/lib/binfmt.d" };
#define NB_DIRS (sizeof(rule_dirs) / sizeof(rule_dirs[0]))

static struct {
	bool initialized;
	bool disabled;
	char root[PATH_MAX];       // host path of the guest rootfs
	struct timespec dir_mtime[NB_DIRS];
	Stamp files[MAX_FILES];
	size_t nb_files;
	Rule rules[MAX_RULES];
	size_t nb_rules;
} binfmt;

/* Change detection */

static struct timespec mtime_of(const char *path)
{
	struct stat st;
	struct timespec none = { 0, 0 };

	if (stat(path, &st) < 0)
		return none;
	return st.st_mtim;
}

static bool same_time(struct timespec a, struct timespec b)
{
	return a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec;
}

static bool rules_stale(void)
{
	char path[PATH_MAX];
	size_t i;

	for (i = 0; i < NB_DIRS; i++) {
		snprintf(path, sizeof(path), "%s%s", binfmt.root, rule_dirs[i]);
		if (!same_time(mtime_of(path), binfmt.dir_mtime[i]))
			return true;
	}
	for (i = 0; i < binfmt.nb_files; i++)
		if (!same_time(mtime_of(binfmt.files[i].path), binfmt.files[i].mtime))
			return true;
	return false;
}

/* Parsing */

static int hex_digit(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

// Decodes \xHH and \\ escapes; returns the length or -1
static int unescape(const char *in, unsigned char *out, size_t max)
{
	size_t n = 0;

	while (*in != '\0') {
		int c = (unsigned char) *in++;

		if (c == '\\' && in[0] == 'x' && hex_digit(in[1]) >= 0 && hex_digit(in[2]) >= 0) {
			c = hex_digit(in[1]) * 16 + hex_digit(in[2]);
			in += 3;
		}
		else if (c == '\\' && in[0] == '\\')
			in++;
		if (n == max)
			return -1;
		out[n++] = (unsigned char) c;
	}
	return (int) n;
}

// Splits ":name:type:offset:magic:mask:interpreter:flags" into a rule
static bool parse_rule(char *line, Rule *rule)
{
	char *field[7];
	char delim = line[0];
	char *p = line + 1;
	size_t i;
	int len;

	if (delim == '\0')
		return false;
	for (i = 0; i < 7; i++) {
		field[i] = p;
		p = strchr(p, delim);
		if (p == NULL) {
			// The flags field may end the line without a delimiter
			if (i < 5)
				return false;
			for (i++; i < 7; i++)
				field[i] = (char *) "";
			break;
		}
		*p++ = '\0';
	}

	memset(rule, 0, sizeof(*rule));
	if (strcmp(field[1], "M") == 0)
		rule->by_ext = false;
	else if (strcmp(field[1], "E") == 0)
		rule->by_ext = true;
	else
		return false;

	rule->offset = (size_t) strtoul(field[2], NULL, 0);
	len = unescape(field[3], rule->magic, MAX_MAGIC);
	if (len <= 0)
		return false;
	rule->len = (size_t) len;

	if (rule->by_ext) {
		rule->magic[rule->len] = '\0';
	}
	else {
		if (rule->offset + rule->len > BINFMT_BUF)
			return false;
		if (field[4][0] == '\0')
			memset(rule->mask, 0xff, rule->len);
		else if (unescape(field[4], rule->mask, MAX_MAGIC) != len)
			return false;
	}

	if (field[5][0] != '/' || strlen(field[5]) >= PATH_MAX)
		return false;
	strcpy(rule->interp, field[5]);
	return true;
}

static void load_file(const char *path)
{
	char line[1024];
	FILE *file;

	if (binfmt.nb_files == MAX_FILES)
		return;
	file = fopen(path, "r");
	if (file == NULL)
		return;

	strcpy(binfmt.files[binfmt.nb_files].path, path);
	binfmt.files[binfmt.nb_files].mtime = mtime_of(path);
	binfmt.nb_files++;

	while (fgets(line, sizeof(line), file) != NULL && binfmt.nb_rules < MAX_RULES) {
		line[strcspn(line, "\r\n")] = '\0';
		if (line[0] == '\0' || line[0] == '#' || line[0] == ';')
			continue;
		if (parse_rule(line, &binfmt.rules[binfmt.nb_rules]))
			binfmt.nb_rules++;
	}
	fclose(file);
}

static void load_rules(void)
{
	char *names[MAX_FILES];
	size_t nb_names = 0;
	char path[PATH_MAX];
	size_t i, j;

	binfmt.nb_rules = 0;
	binfmt.nb_files = 0;

	// Collect the file names, a name in an earlier directory wins
	for (i = 0; i < NB_DIRS; i++) {
		struct dirent *entry;
		DIR *dir;

		snprintf(path, sizeof(path), "%s%s", binfmt.root, rule_dirs[i]);
		binfmt.dir_mtime[i] = mtime_of(path);
		dir = opendir(path);
		if (dir == NULL)
			continue;
		while ((entry = readdir(dir)) != NULL && nb_names < MAX_FILES) {
			size_t len = strlen(entry->d_name);
			bool known = false;

			if (len < 6 || strcmp(entry->d_name + len - 5, ".conf") != 0)
				continue;
			for (j = 0; j < nb_names; j++)
				known |= strcmp(names[j] + strlen(names[j]) + 1, entry->d_name) == 0;
			if (known)
				continue;
			// Stored as "<dir>\0<name>" so that the name sorts and compares
			names[nb_names] = malloc(strlen(path) + len + 2);
			if (names[nb_names] == NULL)
				break;
			strcpy(names[nb_names], path);
			strcpy(names[nb_names] + strlen(path) + 1, entry->d_name);
			nb_names++;
		}
		closedir(dir);
	}

	// Sort by file name (the part after the directory)
	for (i = 0; i < nb_names; i++) {
		for (j = i + 1; j < nb_names; j++) {
			char *a = names[i] + strlen(names[i]) + 1;
			char *b = names[j] + strlen(names[j]) + 1;
			if (strcmp(a, b) > 0) {
				char *t = names[i];
				names[i] = names[j];
				names[j] = t;
			}
		}
	}

	for (i = 0; i < nb_names; i++) {
		snprintf(path, sizeof(path), "%s/%s", names[i], names[i] + strlen(names[i]) + 1);
		load_file(path);
		free(names[i]);
	}
}

/* Matching */

static bool rule_matches(const Rule *rule, const unsigned char *buf, size_t size,
			const char *user_path)
{
	size_t i;

	if (rule->by_ext) {
		const char *base = strrchr(user_path, '/');
		const char *dot;

		base = (base != NULL ? base + 1 : user_path);
		dot = strrchr(base, '.');
		return dot != NULL && strcmp(dot + 1, (const char *) rule->magic) == 0;
	}

	if (rule->offset + rule->len > size)
		return false;
	for (i = 0; i < rule->len; i++)
		if ((buf[rule->offset + i] & rule->mask[i]) != (rule->magic[i] & rule->mask[i]))
			return false;
	return true;
}

// Interpreter: the tracee's view first, then the rootfs (F flag)
static int resolve_interp(Tracee *tracee, const char *interp, char host_path[PATH_MAX])
{
	struct stat st;

	if (translate_and_check_exec(tracee, host_path, interp) == 0)
		return 0;

	if (strlen(binfmt.root) + strlen(interp) >= PATH_MAX)
		return -ENAMETOOLONG;
	snprintf(host_path, PATH_MAX, "%s%s", binfmt.root, interp);
	if (lstat(host_path, &st) < 0 || !S_ISREG(st.st_mode))
		return -ENOENT;
	if (access(host_path, X_OK) < 0)
		return -EACCES;
	return 0;
}

/**
 * Look up a binfmt rule for the program at @host_path (@user_path from
 * the guest's view).  Returns 1 and fills @interp_user/@interp_host
 * when a rule matches, 0 when none does, -errno on error.
 */
int binfmt_lookup(Tracee *tracee, const char *host_path, const char *user_path,
		char interp_user[PATH_MAX], char interp_host[PATH_MAX])
{
	unsigned char buf[BINFMT_BUF];
	ssize_t size;
	size_t i;
	int fd;

	if (!binfmt.initialized) {
		const char *root = get_root(tracee);
		const char *off = getenv("PROOT_NO_BINFMT");

		binfmt.initialized = true;
		binfmt.disabled = (off != NULL && off[0] != '\0' && strcmp(off, "0") != 0)
				|| root == NULL || strlen(root) >= PATH_MAX;
		if (!binfmt.disabled) {
			// The rootfs "/" is the empty prefix
			strcpy(binfmt.root, strcmp(root, "/") == 0 ? "" : root);
			load_rules();
		}
	}
	if (binfmt.disabled || tracee->qemu != NULL)
		return 0;

	if (rules_stale())
		load_rules();
	if (binfmt.nb_rules == 0)
		return 0;

	fd = open(host_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;  // the normal path reports the error
	size = read(fd, buf, sizeof(buf));
	close(fd);
	if (size <= 0)
		return 0;

	for (i = 0; i < binfmt.nb_rules; i++) {
		const Rule *rule = &binfmt.rules[i];
		int status;

		if (!rule_matches(rule, buf, (size_t) size, user_path))
			continue;
		status = resolve_interp(tracee, rule->interp, interp_host);
		if (status < 0)
			return status;
		strcpy(interp_user, rule->interp);
		return 1;
	}
	return 0;
}
