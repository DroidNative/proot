/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * DroidNative storage: disk images.
 *
 * A disk image is a directory on any storage, FAT and Android's
 * shared storage included:
 *
 *     dnimage.db        SQLite: the inodes (type, mode, owner, symlink
 *                       target, content file) and the directory entries
 *     data/ab/ab12...   content of each regular file, named by a UUID
 *
 * Names, case, permissions, owners, symlinks, hard links, FIFOs and
 * device numbers only live in the database, so the storage below
 * needs none of them.  The guest sees the image through a "shadow"
 * tree in PRoot's temporary directory, bound at the mount point:
 * directories, symlinks and FIFOs as they are, a regular file as a
 * small placeholder holding the UUID of its content.  Path
 * translation leads to the content file instead of the placeholder
 * (dn_image_translated()), stat(2) gets the mode and owner of the
 * database (dn_image_exit_end()), and every change of the tree is
 * done by PRoot, on the database and on the shadow alike
 * (dn_image_enter_start()).  The shadow is rebuilt from the database
 * whenever their generation numbers differ, e.g. after the image was
 * used on another device.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <sqlite3.h>
#include <talloc.h>

#include "extension/dn_storage/dn_storage.h"
#include "syscall/sysnum.h"
#include "syscall/syscall.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "path/path.h"
#include "path/temp.h"
#include "cli/note.h"

#define DB_NAME "dnimage.db"
#define IMAGE_FORMAT "1"
#define UUID_SIZE 36

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

enum {
	ST_LOOKUP,	// parent, name -> ino
	ST_INODE,	// ino -> mode, uid, gid, rdev, data, nlink
	ST_BY_DATA,	// uuid -> ino
	ST_ENTRY_OF,	// ino -> parent, name
	ST_CHILDREN,	// parent -> name, ino, mode, data
	ST_NEW_INODE,
	ST_NEW_ENTRY,
	ST_DROP_ENTRY,
	ST_MOVE_ENTRY,
	ST_SET_ENTRY_INO,
	ST_DROP_INODE,
	ST_SET_MODE,
	ST_SET_OWNER,
	ST_BUMP,
	ST_GENERATION,
	NB_STATEMENTS
};

static const char *statements[NB_STATEMENTS] = {
	[ST_LOOKUP] = "SELECT ino FROM dentries WHERE parent = ?1 AND name = ?2",
	[ST_INODE] = "SELECT mode, uid, gid, rdev, data, (SELECT COUNT(*) FROM dentries WHERE ino = ?1)"
		     " FROM inodes WHERE ino = ?1",
	[ST_BY_DATA] = "SELECT ino FROM inodes WHERE data = ?1 AND (mode & 61440) = 32768",
	[ST_ENTRY_OF] = "SELECT parent, name FROM dentries WHERE ino = ?1 LIMIT 1",
	[ST_CHILDREN] = "SELECT d.name, d.ino, i.mode, i.data FROM dentries d JOIN inodes i ON i.ino = d.ino"
			" WHERE d.parent = ?1",
	[ST_NEW_INODE] = "INSERT INTO inodes (mode, uid, gid, rdev, data) VALUES (?1, ?2, ?3, ?4, ?5)",
	[ST_NEW_ENTRY] = "INSERT INTO dentries (parent, name, ino) VALUES (?1, ?2, ?3)",
	[ST_DROP_ENTRY] = "DELETE FROM dentries WHERE parent = ?1 AND name = ?2",
	[ST_MOVE_ENTRY] = "UPDATE dentries SET parent = ?3, name = ?4 WHERE parent = ?1 AND name = ?2",
	[ST_SET_ENTRY_INO] = "UPDATE dentries SET ino = ?3 WHERE parent = ?1 AND name = ?2",
	[ST_DROP_INODE] = "DELETE FROM inodes WHERE ino = ?1",
	[ST_SET_MODE] = "UPDATE inodes SET mode = (mode & 61440) | ?2 WHERE ino = ?1",
	[ST_SET_OWNER] = "UPDATE inodes SET uid = CASE WHEN ?2 < 0 THEN uid ELSE ?2 END,"
			 " gid = CASE WHEN ?3 < 0 THEN gid ELSE ?3 END WHERE ino = ?1",
	[ST_BUMP] = "UPDATE meta SET value = value + 1 WHERE key = 'generation'",
	[ST_GENERATION] = "SELECT value FROM meta WHERE key = 'generation'",
};

static const char schema[] =
	"CREATE TABLE meta (key TEXT PRIMARY KEY, value) WITHOUT ROWID;"
	"CREATE TABLE inodes (ino INTEGER PRIMARY KEY, mode INTEGER NOT NULL,"
	" uid INTEGER NOT NULL, gid INTEGER NOT NULL, rdev INTEGER NOT NULL DEFAULT 0, data TEXT);"
	"CREATE TABLE dentries (parent INTEGER NOT NULL, name TEXT NOT NULL, ino INTEGER NOT NULL,"
	" PRIMARY KEY (parent, name)) WITHOUT ROWID;"
	"CREATE INDEX dentries_ino ON dentries (ino);"
	"CREATE INDEX inodes_data ON inodes (data);";

typedef struct image {
	char *dir;		// the image
	char *data;		// dir/data
	char *shadow;		// PRoot's copy of the tree, see rebuild_shadow()
	char *tree;		// shadow/tree, bound at the mount point
	sqlite3 *db;
	sqlite3_stmt *stmt[NB_STATEMENTS];
	struct image *next;
} Image;

typedef struct {
	int64_t ino;
	uint32_t mode;
	int64_t uid;
	int64_t gid;
	uint64_t rdev;
	int64_t nlink;
	char data[PATH_MAX];
} Inode;

static TALLOC_CTX *context;
static Image *images;

/* Database */

static sqlite3_stmt *statement(Image *image, int which)
{
	sqlite3_stmt *stmt = image->stmt[which];

	sqlite3_reset(stmt);
	sqlite3_clear_bindings(stmt);
	return stmt;
}

static int exec_sql(Image *image, const char *sql)
{
	return sqlite3_exec(image->db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -EIO;
}

static int begin(Image *image)
{
	int status;
	int tries;

	// Another PRoot may hold the lock for a moment
	for (tries = 0; tries < 200; tries++) {
		status = sqlite3_exec(image->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
		if (status != SQLITE_BUSY)
			break;
		usleep(10000);
	}
	return status == SQLITE_OK ? 0 : -EIO;
}

static void rollback(Image *image)
{
	(void) sqlite3_exec(image->db, "ROLLBACK", NULL, NULL, NULL);
}

static int64_t generation(Image *image)
{
	sqlite3_stmt *stmt = statement(image, ST_GENERATION);

	if (sqlite3_step(stmt) != SQLITE_ROW)
		return -1;
	return sqlite3_column_int64(stmt, 0);
}

static void write_generation(Image *image, int64_t value)
{
	char path[PATH_MAX];
	char text[32];
	int fd;

	snprintf(path, sizeof(path), "%s/generation", image->shadow);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	snprintf(text, sizeof(text), "%lld\n", (long long) value);
	if (write(fd, text, strlen(text)) < 0) {
		// The shadow is rebuilt next time
	}
	close(fd);
}

/**
 * Bump the generation of @image and commit.  On error the shadow is
 * marked stale, since it was changed already.
 */
static int commit(Image *image)
{
	sqlite3_stmt *stmt = statement(image, ST_BUMP);

	if (sqlite3_step(stmt) != SQLITE_DONE
	    || sqlite3_exec(image->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
		rollback(image);
		write_generation(image, -1);
		return -EIO;
	}
	write_generation(image, generation(image));
	return 0;
}

static int64_t lookup(Image *image, int64_t parent, const char *name)
{
	sqlite3_stmt *stmt = statement(image, ST_LOOKUP);

	sqlite3_bind_int64(stmt, 1, parent);
	sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) != SQLITE_ROW)
		return -ENOENT;
	return sqlite3_column_int64(stmt, 0);
}

static int get_inode(Image *image, int64_t ino, Inode *inode)
{
	sqlite3_stmt *stmt = statement(image, ST_INODE);
	const unsigned char *data;

	sqlite3_bind_int64(stmt, 1, ino);
	if (sqlite3_step(stmt) != SQLITE_ROW)
		return -ENOENT;
	inode->ino = ino;
	inode->mode = (uint32_t) sqlite3_column_int64(stmt, 0);
	inode->uid = sqlite3_column_int64(stmt, 1);
	inode->gid = sqlite3_column_int64(stmt, 2);
	inode->rdev = (uint64_t) sqlite3_column_int64(stmt, 3);
	data = sqlite3_column_text(stmt, 4);
	snprintf(inode->data, sizeof(inode->data), "%s", data != NULL ? (const char *) data : "");
	inode->nlink = sqlite3_column_int64(stmt, 5);
	return 0;
}

static int64_t new_inode(Image *image, mode_t mode, uint64_t rdev, const char *data)
{
	sqlite3_stmt *stmt = statement(image, ST_NEW_INODE);

	sqlite3_bind_int64(stmt, 1, mode);
	sqlite3_bind_int64(stmt, 2, getuid());
	sqlite3_bind_int64(stmt, 3, getgid());
	sqlite3_bind_int64(stmt, 4, (int64_t) rdev);
	if (data != NULL)
		sqlite3_bind_text(stmt, 5, data, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) != SQLITE_DONE)
		return -EIO;
	return sqlite3_last_insert_rowid(image->db);
}

static int new_entry(Image *image, int64_t parent, const char *name, int64_t ino)
{
	sqlite3_stmt *stmt = statement(image, ST_NEW_ENTRY);

	sqlite3_bind_int64(stmt, 1, parent);
	sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, ino);
	return sqlite3_step(stmt) == SQLITE_DONE ? 0 : -EIO;
}

static int drop_entry(Image *image, int64_t parent, const char *name)
{
	sqlite3_stmt *stmt = statement(image, ST_DROP_ENTRY);

	sqlite3_bind_int64(stmt, 1, parent);
	sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);
	return sqlite3_step(stmt) == SQLITE_DONE ? 0 : -EIO;
}

static int run_ino_text(Image *image, int which, int64_t a, const char *b, int64_t c, const char *d)
{
	sqlite3_stmt *stmt = statement(image, which);

	sqlite3_bind_int64(stmt, 1, a);
	sqlite3_bind_text(stmt, 2, b, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, c);
	if (d != NULL)
		sqlite3_bind_text(stmt, 4, d, -1, SQLITE_STATIC);
	return sqlite3_step(stmt) == SQLITE_DONE ? 0 : -EIO;
}

/* Paths */

static void content_path(const Image *image, const char *uuid, char path[PATH_MAX])
{
	snprintf(path, PATH_MAX, "%s/%.2s/%s", image->data, uuid, uuid);
}

static Image *image_of(const char *host_path)
{
	Image *image;

	for (image = images; image != NULL; image = image->next) {
		if (dn_path_in(host_path, image->tree) || dn_path_in(host_path, image->data))
			return image;
	}
	return NULL;
}

/**
 * Inode number of @host_path, a path of the shadow of @image or one
 * of its content files.
 */
static int64_t ino_of(Image *image, const char *host_path)
{
	int64_t stack[PATH_MAX / 2];
	char rel[PATH_MAX];
	char *component;
	char *saveptr;
	size_t depth = 0;

	if (dn_path_in(host_path, image->data)) {
		sqlite3_stmt *stmt = statement(image, ST_BY_DATA);
		const char *uuid = strrchr(host_path, '/') + 1;

		sqlite3_bind_text(stmt, 1, uuid, -1, SQLITE_STATIC);
		if (sqlite3_step(stmt) != SQLITE_ROW)
			return -ENOENT;
		return sqlite3_column_int64(stmt, 0);
	}

	if (!dn_path_in(host_path, image->tree))
		return -ENOENT;
	snprintf(rel, sizeof(rel), "%s", host_path + strlen(image->tree));
	stack[0] = 1;
	for (component = strtok_r(rel, "/", &saveptr); component != NULL;
	     component = strtok_r(NULL, "/", &saveptr)) {
		int64_t ino;

		if (strcmp(component, ".") == 0)
			continue;
		if (strcmp(component, "..") == 0) {
			if (depth > 0)
				depth--;
			continue;
		}
		ino = lookup(image, stack[depth], component);
		if (ino < 0)
			return ino;
		stack[++depth] = ino;
	}
	return stack[depth];
}

/**
 * Split the shadow path @host_path into the inode of its directory
 * and its name.
 */
static int64_t parent_of(Image *image, const char *host_path, char name[NAME_MAX + 1])
{
	char parent[PATH_MAX];
	char *slash;

	snprintf(parent, sizeof(parent), "%s", host_path);
	slash = strrchr(parent, '/');
	if (slash == NULL || strlen(slash + 1) > NAME_MAX)
		return -ENAMETOOLONG;
	strcpy(name, slash + 1);
	*slash = '\0';
	return ino_of(image, parent);
}

/**
 * Read the UUID a placeholder of the shadow holds.
 */
static int read_placeholder(const char *path, char uuid[UUID_SIZE + 1])
{
	ssize_t size;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -errno;
	size = read(fd, uuid, UUID_SIZE);
	close(fd);
	if (size != UUID_SIZE)
		return -EINVAL;
	uuid[UUID_SIZE] = '\0';
	return 0;
}

static int write_placeholder(const char *path, const char *uuid)
{
	int fd;
	ssize_t size;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;
	size = uuid != NULL ? write(fd, uuid, UUID_SIZE) : 0;
	close(fd);
	if (uuid != NULL && size != UUID_SIZE) {
		unlink(path);
		return -EIO;
	}
	return 0;
}

static int new_uuid(char uuid[UUID_SIZE + 1])
{
	unsigned char bytes[16];
	int fd;

	fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd < 0 || read(fd, bytes, sizeof(bytes)) != (ssize_t) sizeof(bytes)) {
		if (fd >= 0)
			close(fd);
		return -EIO;
	}
	close(fd);
	bytes[6] = (bytes[6] & 0x0f) | 0x40;
	bytes[8] = (bytes[8] & 0x3f) | 0x80;
	snprintf(uuid, UUID_SIZE + 1,
		 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		 bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
		 bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
	return 0;
}

/* Shadow */

static int remove_entry(const char *path, const struct stat *st, int flag, struct FTW *ftw)
{
	(void) st; (void) flag; (void) ftw;
	(void) remove(path);
	return 0;
}

/**
 * Create the shadow of the children of the directory @ino at @path.
 */
static int fill_shadow(Image *image, int64_t ino, const char *path)
{
	typedef struct { char *name; int64_t ino; uint32_t mode; char *data; } Child;
	Child *children = NULL;
	size_t count = 0;
	sqlite3_stmt *stmt = statement(image, ST_CHILDREN);
	char child_path[PATH_MAX];
	size_t i;
	int status = 0;

	// Collect first: the statement is used again below
	sqlite3_bind_int64(stmt, 1, ino);
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		const unsigned char *data = sqlite3_column_text(stmt, 3);
		Child *grown = talloc_realloc(context, children, Child, count + 1);

		if (grown == NULL) {
			talloc_free(children);
			return -ENOMEM;
		}
		children = grown;
		children[count].name = talloc_strdup(children, (const char *) sqlite3_column_text(stmt, 0));
		children[count].ino = sqlite3_column_int64(stmt, 1);
		children[count].mode = (uint32_t) sqlite3_column_int64(stmt, 2);
		children[count].data = talloc_strdup(children, data != NULL ? (const char *) data : "");
		count++;
	}

	for (i = 0; i < count && status == 0; i++) {
		Child *child = &children[i];

		snprintf(child_path, sizeof(child_path), "%s/%s", path, child->name);
		switch (child->mode & S_IFMT) {
		case S_IFDIR:
			if (mkdir(child_path, 0700) < 0)
				status = -errno;
			else
				status = fill_shadow(image, child->ino, child_path);
			break;
		case S_IFREG:
			status = write_placeholder(child_path, child->data);
			break;
		case S_IFLNK:
			if (symlink(child->data, child_path) < 0)
				status = -errno;
			break;
		case S_IFIFO:
			if (mkfifo(child_path, 0600) < 0)
				status = -errno;
			break;
		default:
			status = write_placeholder(child_path, NULL);
			break;
		}
	}
	talloc_free(children);
	return status;
}

/**
 * Make the shadow of @image match its database, unless it does
 * already (same generation).
 */
static int rebuild_shadow(Image *image)
{
	char path[PATH_MAX];
	char text[32];
	int64_t current;
	struct stat st;
	ssize_t size;
	int status;
	int fd;

	current = generation(image);
	snprintf(path, sizeof(path), "%s/generation", image->shadow);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		size = read(fd, text, sizeof(text) - 1);
		close(fd);
		if (size > 0) {
			text[size] = '\0';
			if (strtoll(text, NULL, 10) == current && stat(image->tree, &st) == 0)
				return 0;
		}
	}

	if (stat(image->tree, &st) == 0) {
		snprintf(path, sizeof(path), "%s/old-%d", image->shadow, getpid());
		if (rename(image->tree, path) == 0)
			(void) nftw(path, remove_entry, 16, FTW_DEPTH | FTW_PHYS);
	}
	if (mkdir(image->tree, 0700) < 0)
		return -errno;
	status = fill_shadow(image, 1, image->tree);
	if (status < 0)
		return status;
	write_generation(image, current);
	return 0;
}

/* Images */

/**
 * Open the image @dir, creating it if @dir is empty or doesn't exist.
 */
static Image *open_image(const char *dir)
{
	char path[PATH_MAX];
	char uuid[UUID_SIZE + 1];
	sqlite3_stmt *stmt;
	struct stat st;
	Image *image;
	bool create;
	int i;

	if (context == NULL) {
		context = talloc_named_const(talloc_autofree_context(), 0, "dn_image");
		if (context == NULL)
			return NULL;
	}

	if (mkdir(dir, 0700) < 0 && errno != EEXIST)
		return NULL;
	if (realpath(dir, path) == NULL)
		return NULL;
	for (image = images; image != NULL; image = image->next) {
		if (strcmp(image->dir, path) == 0)
			return image;
	}

	image = talloc_zero(context, Image);
	if (image == NULL)
		return NULL;
	image->dir = talloc_strdup(image, path);
	image->data = talloc_asprintf(image, "%s/data", path);

	snprintf(path, sizeof(path), "%s/" DB_NAME, image->dir);
	create = stat(path, &st) < 0;
	if (create) {
		DIR *d = opendir(image->dir);
		struct dirent *entry;

		// Never turn a directory with files into an image
		while (d != NULL && (entry = readdir(d)) != NULL) {
			if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
				closedir(d);
				note(NULL, ERROR, USER, "%s is not empty and no disk image", image->dir);
				talloc_free(image);
				return NULL;
			}
		}
		if (d != NULL)
			closedir(d);
	}

	if (sqlite3_open_v2(path, &image->db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK)
		goto error;
	sqlite3_busy_timeout(image->db, 2000);
	// No -journal file per transaction: creating files is slow on SD cards
	if (exec_sql(image, "PRAGMA journal_mode = PERSIST; PRAGMA synchronous = NORMAL;") < 0)
		goto error;

	if (create) {
		if (new_uuid(uuid) < 0 || mkdir(image->data, 0700) < 0 || begin(image) < 0)
			goto error;
		if (exec_sql(image, schema) < 0)
			goto error;
		snprintf(path, sizeof(path),
			 "INSERT INTO meta VALUES ('format', '" IMAGE_FORMAT "'), ('uuid', '%s'), ('generation', 1);"
			 "INSERT INTO inodes (ino, mode, uid, gid) VALUES (1, %d, %d, %d);",
			 uuid, S_IFDIR | 0755, (int) getuid(), (int) getgid());
		if (exec_sql(image, path) < 0 || exec_sql(image, "COMMIT") < 0)
			goto error;
	}

	for (i = 0; i < NB_STATEMENTS; i++) {
		if (sqlite3_prepare_v2(image->db, statements[i], -1, &image->stmt[i], NULL) != SQLITE_OK)
			goto error;
	}

	if (sqlite3_prepare_v2(image->db, "SELECT value FROM meta WHERE key = 'format'", -1, &stmt, NULL) != SQLITE_OK)
		goto error;
	if (sqlite3_step(stmt) != SQLITE_ROW || strcmp((const char *) sqlite3_column_text(stmt, 0), IMAGE_FORMAT) != 0) {
		sqlite3_finalize(stmt);
		note(NULL, ERROR, USER, "%s: unknown disk image format", image->dir);
		goto error;
	}
	sqlite3_finalize(stmt);

	if (sqlite3_prepare_v2(image->db, "SELECT value FROM meta WHERE key = 'uuid'", -1, &stmt, NULL) != SQLITE_OK)
		goto error;
	if (sqlite3_step(stmt) != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		goto error;
	}
	image->shadow = talloc_asprintf(image, "%s/dnimage-%s", get_temp_directory(),
					(const char *) sqlite3_column_text(stmt, 0));
	sqlite3_finalize(stmt);
	image->tree = talloc_asprintf(image, "%s/tree", image->shadow);
	if (image->shadow == NULL || image->tree == NULL)
		goto error;
	if (mkdir(image->shadow, 0700) < 0 && errno != EEXIST)
		goto error;
	if (rebuild_shadow(image) < 0)
		goto error;

	image->next = images;
	images = image;
	return image;

error:
	note(NULL, ERROR, USER, "can't open the disk image %s: %s", image->dir,
	     image->db != NULL ? sqlite3_errmsg(image->db) : strerror(errno));
	for (i = 0; i < NB_STATEMENTS; i++) {
		if (image->stmt[i] != NULL)
			sqlite3_finalize(image->stmt[i]);
	}
	if (image->db != NULL)
		sqlite3_close(image->db);
	talloc_free(image);
	return NULL;
}

bool dn_image_active(void)
{
	return images != NULL;
}

/**
 * --image=DIR:GUEST: copies into @binding the "HOST:GUEST" binding to
 * add for it.
 */
int dn_storage_add_image(const char *value, char binding[PATH_MAX])
{
	char dir[PATH_MAX];
	const char *colon;
	Image *image;

	colon = strrchr(value, ':');
	if (colon == NULL || colon == value || (size_t) (colon - value) >= sizeof(dir))
		return -1;
	memcpy(dir, value, colon - value);
	dir[colon - value] = '\0';

	image = open_image(dir);
	if (image == NULL)
		return -1;
	if ((size_t) snprintf(binding, PATH_MAX, "%s:%s", image->tree, colon + 1) >= PATH_MAX)
		return -1;
	return 0;
}

/**
 * mount -t dnimage DIR TARGET
 */
int dn_image_mount(Tracee *tracee, const char *source_user, const char *data, char host_path[PATH_MAX])
{
	char dir[PATH_MAX];
	Image *image;
	int status;

	(void) data;
	status = translate_path(tracee, dir, AT_FDCWD, source_user, true);
	if (status < 0)
		return status;
	image = open_image(dir);
	if (image == NULL)
		return -EINVAL;
	snprintf(host_path, PATH_MAX, "%s", image->tree);
	return 1;
}

void dn_image_unmounted(const char *host_path)
{
	(void) host_path;
	// Images stay open: other bindings may use them, PRoot ends soon
}

/* Path translation */

/**
 * A regular file of an image: use its content file instead of the
 * placeholder of the shadow.  Changes of the tree are emulated by
 * dn_image_enter_start(), which asks for the shadow path ("image_raw").
 */
int dn_image_translated(Tracee *tracee, char host_path[PATH_MAX])
{
	char uuid[UUID_SIZE + 1];
	struct stat st;
	Image *image;

	if (tracee->dn.image_raw)
		return 0;
	image = image_of(host_path);
	if (image == NULL || !dn_path_in(host_path, image->tree))
		return 0;
	if (lstat(host_path, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size != UUID_SIZE)
		return 0;
	if (read_placeholder(host_path, uuid) < 0)
		return 0;
	content_path(image, uuid, host_path);
	return 0;
}

/**
 * Translate the path argument @reg of the current syscall of @tracee
 * (relative to @dirfd) into the shadow path @host.  Returns the image
 * the path is in, NULL otherwise (*status < 0: the tracee was parked).
 */
static Image *image_path(Tracee *tracee, int dirfd, Reg reg, bool deref, char host[PATH_MAX], int *status)
{
	char user[PATH_MAX];

	*status = get_sysarg_path(tracee, user, reg);
	if (*status < 0)
		return NULL;
	if (user[0] == '\0') {
		*status = 0;
		return NULL;
	}

	tracee->dn.image_raw = true;
	*status = translate_path(tracee, host, dirfd, user, deref);
	tracee->dn.image_raw = false;
	if (*status < 0) {
		// Let PRoot report the error, unless the tracee waits for FUSE
		if (!tracee->dn.parked)
			*status = 0;
		return NULL;
	}
	*status = 0;

	// "dir/" names the same entry as "dir"
	while (strlen(host) > 1 && host[strlen(host) - 1] == '/')
		host[strlen(host) - 1] = '\0';
	return image_of(host);
}

static int answer(Tracee *tracee, int result)
{
	poke_reg(tracee, SYSARG_RESULT, (word_t) result);
	set_sysnum(tracee, PR_void);
	return 1;
}

/**
 * Create the regular file @host of @image with @mode: content file,
 * placeholder and database rows.
 */
static int create_file(Image *image, const char *host, mode_t mode)
{
	char name[NAME_MAX + 1];
	char uuid[UUID_SIZE + 1];
	char content[PATH_MAX];
	char dir[PATH_MAX];
	int64_t parent;
	int64_t ino;
	int status;
	int fd;

	parent = parent_of(image, host, name);
	if (parent < 0)
		return (int) parent;
	if (new_uuid(uuid) < 0)
		return -EIO;

	snprintf(dir, sizeof(dir), "%s/%.2s", image->data, uuid);
	(void) mkdir(dir, 0700);
	content_path(image, uuid, content);
	fd = open(content, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;
	close(fd);

	status = begin(image);
	if (status < 0)
		goto error;
	ino = new_inode(image, S_IFREG | (mode & 07777), 0, uuid);
	status = ino < 0 ? (int) ino : new_entry(image, parent, name, ino);
	if (status == 0)
		status = write_placeholder(host, uuid);
	if (status < 0) {
		rollback(image);
		goto error;
	}
	status = commit(image);
	if (status < 0)
		goto error;
	return 0;

error:
	unlink(content);
	return status;
}

/**
 * Create the node @host of @image that isn't a regular file, @data is
 * the target of a symlink.
 */
static int create_node(Image *image, const char *host, mode_t mode, uint64_t rdev, const char *data)
{
	char name[NAME_MAX + 1];
	int64_t parent;
	int64_t ino;
	int status;

	parent = parent_of(image, host, name);
	if (parent < 0)
		return (int) parent;

	status = begin(image);
	if (status < 0)
		return status;
	ino = new_inode(image, mode, rdev, data);
	status = ino < 0 ? (int) ino : new_entry(image, parent, name, ino);
	if (status == 0) {
		switch (mode & S_IFMT) {
		case S_IFDIR:
			status = mkdir(host, 0700) < 0 ? -errno : 0;
			break;
		case S_IFLNK:
			status = symlink(data, host) < 0 ? -errno : 0;
			break;
		case S_IFIFO:
			status = mkfifo(host, 0600) < 0 ? -errno : 0;
			break;
		default:
			status = write_placeholder(host, NULL);
			break;
		}
	}
	if (status < 0) {
		rollback(image);
		return status;
	}
	return commit(image);
}

/**
 * Drop the entry @name of @parent; @content gets the content file to
 * remove once committed, if that was its last link.
 */
static int unlink_entry(Image *image, int64_t parent, const char *name, char content[PATH_MAX])
{
	Inode inode;
	int64_t ino;
	int status;

	content[0] = '\0';
	ino = lookup(image, parent, name);
	if (ino < 0)
		return 0;	// Not in the database (a socket)
	status = drop_entry(image, parent, name);
	if (status < 0)
		return status;
	if (get_inode(image, ino, &inode) < 0 || inode.nlink > 0)
		return 0;
	if (S_ISREG(inode.mode) && inode.data[0] != '\0')
		content_path(image, inode.data, content);
	return run_ino_text(image, ST_DROP_INODE, ino, "", 0, NULL) == 0 ? 0 : -EIO;
}

/* Syscalls changing the tree */

static int do_mkdir(Tracee *tracee, int dirfd, Reg path_reg, Reg mode_reg)
{
	char host[PATH_MAX];
	struct stat st;
	Image *image;
	int status;

	image = image_path(tracee, dirfd, path_reg, false, host, &status);
	if (image == NULL)
		return status;
	if (lstat(host, &st) == 0)
		return -EEXIST;

	status = create_node(image, host,
			     S_IFDIR | (peek_reg(tracee, CURRENT, mode_reg) & 07777 & ~dn_umask(tracee)), 0, NULL);
	return status < 0 ? status : answer(tracee, 0);
}

static int do_remove(Tracee *tracee, int dirfd, Reg path_reg, bool dir)
{
	char name[NAME_MAX + 1];
	char content[PATH_MAX];
	char host[PATH_MAX];
	struct stat st;
	int64_t parent;
	Image *image;
	int status;

	image = image_path(tracee, dirfd, path_reg, false, host, &status);
	if (image == NULL)
		return status;
	if (strcmp(host, image->tree) == 0)
		return -EBUSY;
	if (lstat(host, &st) < 0)
		return -errno;
	if (dir && !S_ISDIR(st.st_mode))
		return -ENOTDIR;
	if (!dir && S_ISDIR(st.st_mode))
		return -EISDIR;

	parent = parent_of(image, host, name);
	if (parent < 0)
		return (int) parent;
	status = begin(image);
	if (status < 0)
		return status;
	status = unlink_entry(image, parent, name, content);
	if (status == 0)
		status = (dir ? rmdir(host) : unlink(host)) < 0 ? -errno : 0;
	if (status < 0) {
		rollback(image);
		return status;
	}
	status = commit(image);
	if (status < 0)
		return status;
	if (content[0] != '\0')
		(void) unlink(content);
	return answer(tracee, 0);
}

static int do_rename(Tracee *tracee, int olddirfd, Reg old_reg, int newdirfd, Reg new_reg, unsigned flags)
{
	char old_name[NAME_MAX + 1];
	char new_name[NAME_MAX + 1];
	char content[PATH_MAX];
	char old_host[PATH_MAX];
	char new_host[PATH_MAX];
	int64_t old_parent, new_parent, old_ino, new_ino;
	Image *old_image, *new_image;
	struct stat st;
	int status;

	old_image = image_path(tracee, olddirfd, old_reg, false, old_host, &status);
	if (status < 0)
		return status;
	new_image = image_path(tracee, newdirfd, new_reg, false, new_host, &status);
	if (status < 0)
		return status;
	if (old_image == NULL && new_image == NULL)
		return 0;
	if (old_image != new_image)
		return -EXDEV;
	if (lstat(old_host, &st) < 0)
		return -errno;
	if (strcmp(old_host, new_host) == 0)
		return answer(tracee, 0);

	old_parent = parent_of(old_image, old_host, old_name);
	new_parent = parent_of(old_image, new_host, new_name);
	if (old_parent < 0 || new_parent < 0)
		return -ENOENT;
	old_ino = lookup(old_image, old_parent, old_name);
	new_ino = lookup(old_image, new_parent, new_name);

	status = begin(old_image);
	if (status < 0)
		return status;

	// The shadow checks the semantics (types, empty directories, flags)
	content[0] = '\0';
	if (syscall(SYS_renameat2, AT_FDCWD, old_host, AT_FDCWD, new_host, flags) < 0) {
		status = -errno;
		if (status == -ENOSYS && flags == 0)
			status = rename(old_host, new_host) < 0 ? -errno : 0;
		if (status < 0) {
			rollback(old_image);
			return status;
		}
	}

	if ((flags & RENAME_EXCHANGE) != 0) {
		if (old_ino >= 0)
			status = run_ino_text(old_image, ST_SET_ENTRY_INO, new_parent, new_name, old_ino, NULL);
		if (status == 0 && new_ino >= 0)
			status = run_ino_text(old_image, ST_SET_ENTRY_INO, old_parent, old_name, new_ino, NULL);
	}
	else {
		if (new_ino >= 0)
			status = unlink_entry(old_image, new_parent, new_name, content);
		if (status == 0 && old_ino >= 0)
			status = run_ino_text(old_image, ST_MOVE_ENTRY, old_parent, old_name, new_parent, new_name);
	}
	if (status < 0) {
		rollback(old_image);
		write_generation(old_image, -1);
		return status;
	}
	status = commit(old_image);
	if (status < 0)
		return status;
	if (content[0] != '\0')
		(void) unlink(content);
	return answer(tracee, 0);
}

static int do_link(Tracee *tracee, int olddirfd, Reg old_reg, int newdirfd, Reg new_reg, int flags)
{
	char new_name[NAME_MAX + 1];
	char old_host[PATH_MAX];
	char new_host[PATH_MAX];
	char target[PATH_MAX];
	char uuid[UUID_SIZE + 1];
	Image *old_image, *new_image;
	int64_t new_parent, ino;
	struct stat st;
	ssize_t size;
	int status;

	old_image = image_path(tracee, olddirfd, old_reg, (flags & AT_SYMLINK_FOLLOW) != 0, old_host, &status);
	if (status < 0)
		return status;
	new_image = image_path(tracee, newdirfd, new_reg, false, new_host, &status);
	if (status < 0)
		return status;
	if (old_image == NULL && new_image == NULL)
		return 0;
	if (old_image != new_image)
		return -EXDEV;
	if (lstat(old_host, &st) < 0)
		return -errno;
	if (S_ISDIR(st.st_mode))
		return -EPERM;
	if (lstat(new_host, &(struct stat) {0}) == 0)
		return -EEXIST;

	ino = ino_of(old_image, old_host);
	new_parent = parent_of(old_image, new_host, new_name);
	if (ino < 0 || new_parent < 0)
		return -ENOENT;

	status = begin(old_image);
	if (status < 0)
		return status;
	status = new_entry(old_image, new_parent, new_name, ino);
	if (status == 0) {
		if (S_ISREG(st.st_mode) && read_placeholder(old_host, uuid) == 0)
			status = write_placeholder(new_host, uuid);
		else if (S_ISLNK(st.st_mode)) {
			size = readlink(old_host, target, sizeof(target) - 1);
			if (size < 0)
				status = -errno;
			else {
				target[size] = '\0';
				status = symlink(target, new_host) < 0 ? -errno : 0;
			}
		}
		else if (S_ISFIFO(st.st_mode))
			status = mkfifo(new_host, 0600) < 0 ? -errno : 0;
		else
			status = write_placeholder(new_host, NULL);
	}
	if (status < 0) {
		rollback(old_image);
		return status;
	}
	status = commit(old_image);
	return status < 0 ? status : answer(tracee, 0);
}

static int do_symlink(Tracee *tracee, Reg target_reg, int dirfd, Reg path_reg)
{
	char target[PATH_MAX];
	char host[PATH_MAX];
	Image *image;
	int status;

	image = image_path(tracee, dirfd, path_reg, false, host, &status);
	if (image == NULL)
		return status;
	status = get_sysarg_path(tracee, target, target_reg);
	if (status < 0)
		return status;
	if (target[0] == '\0')
		return -ENOENT;
	if (lstat(host, &(struct stat) {0}) == 0)
		return -EEXIST;

	status = create_node(image, host, S_IFLNK | 0777, 0, target);
	return status < 0 ? status : answer(tracee, 0);
}

static int do_mknod(Tracee *tracee, int dirfd, Reg path_reg, Reg mode_reg, Reg dev_reg)
{
	mode_t mode = (mode_t) peek_reg(tracee, CURRENT, mode_reg);
	char host[PATH_MAX];
	Image *image;
	int status;

	image = image_path(tracee, dirfd, path_reg, false, host, &status);
	if (image == NULL)
		return status;
	if (lstat(host, &(struct stat) {0}) == 0)
		return -EEXIST;

	mode = (mode & S_IFMT) | (mode & 07777 & ~dn_umask(tracee));
	if ((mode & S_IFMT) == 0 || S_ISREG(mode))
		status = create_file(image, host, mode);
	else if (S_ISDIR(mode))
		status = -EINVAL;
	else
		status = create_node(image, host, mode, peek_reg(tracee, CURRENT, dev_reg), NULL);
	return status < 0 ? status : answer(tracee, 0);
}

/**
 * open(2) with O_CREAT of a file that doesn't exist yet: create it, then
 * let the open(2) go on without O_EXCL, on the new content file.  The
 * flags are in @flags_reg, or at @how for openat2(2).
 */
static int do_create(Tracee *tracee, int dirfd, Reg path_reg, word_t flags, mode_t mode,
		     int flags_reg, word_t how)
{
	char host[PATH_MAX];
	Image *image;
	int status;

	if ((flags & O_CREAT) == 0 || (flags & __O_TMPFILE) == __O_TMPFILE)
		return 0;

	image = image_path(tracee, dirfd, path_reg, (flags & (O_EXCL | O_NOFOLLOW)) == 0, host, &status);
	if (image == NULL)
		return status;
	if (lstat(host, &(struct stat) {0}) == 0)
		return (flags & O_EXCL) != 0 ? -EEXIST : 0;

	status = create_file(image, host, mode & 07777 & ~dn_umask(tracee));
	if (status < 0)
		return status;

	if ((flags & O_EXCL) == 0)
		return 0;
	if (how != 0)
		poke_uint64(tracee, how, flags & ~(word_t) O_EXCL);
	else if (flags_reg >= 0)
		poke_reg(tracee, (Reg) flags_reg, flags & ~(word_t) O_EXCL);
	return 0;
}

/* Metadata */

static int set_mode(Tracee *tracee, Image *image, const char *host, mode_t mode)
{
	sqlite3_stmt *stmt;
	int64_t ino = ino_of(image, host);

	if (ino < 0)
		return (int) ino;
	stmt = statement(image, ST_SET_MODE);
	sqlite3_bind_int64(stmt, 1, ino);
	sqlite3_bind_int64(stmt, 2, mode & 07777);
	return sqlite3_step(stmt) == SQLITE_DONE ? answer(tracee, 0) : -EIO;
}

static int set_owner(Tracee *tracee, Image *image, const char *host, int64_t uid, int64_t gid)
{
	sqlite3_stmt *stmt;
	int64_t ino = ino_of(image, host);

	if (ino < 0)
		return (int) ino;
	stmt = statement(image, ST_SET_OWNER);
	sqlite3_bind_int64(stmt, 1, ino);
	sqlite3_bind_int64(stmt, 2, uid);
	sqlite3_bind_int64(stmt, 3, gid);
	return sqlite3_step(stmt) == SQLITE_DONE ? answer(tracee, 0) : -EIO;
}

/**
 * Host path of a path argument for chmod(2)-like syscalls: the shadow
 * path or, for regular files, the content file.  Returns its image.
 */
static Image *meta_path(Tracee *tracee, int dirfd, Reg reg, bool deref, char host[PATH_MAX], int *status)
{
	Image *image = image_path(tracee, dirfd, reg, deref, host, status);

	if (image == NULL && *status == 0) {
		char user[PATH_MAX];

		// fchownat(fd, "", AT_EMPTY_PATH)
		if (get_sysarg_path(tracee, user, reg) >= 0 && user[0] == '\0' && dirfd >= 0
		    && dn_fd_path(tracee, dirfd, host) >= 0)
			return image_of(host);
	}
	return image;
}

static int32_t id_arg(Tracee *tracee, Reg reg)
{
	return (int32_t) peek_reg(tracee, CURRENT, reg);
}

int dn_image_enter_start(Tracee *tracee)
{
	char host[PATH_MAX];
	Image *image;
	int status = 0;
	int fd;

#define FD(reg) ((int) peek_reg(tracee, CURRENT, reg))
	switch (get_sysnum(tracee, ORIGINAL)) {
	case PR_mkdir:
		return do_mkdir(tracee, AT_FDCWD, SYSARG_1, SYSARG_2);
	case PR_mkdirat:
		return do_mkdir(tracee, FD(SYSARG_1), SYSARG_2, SYSARG_3);
	case PR_rmdir:
		return do_remove(tracee, AT_FDCWD, SYSARG_1, true);
	case PR_unlink:
		return do_remove(tracee, AT_FDCWD, SYSARG_1, false);
	case PR_unlinkat:
		return do_remove(tracee, FD(SYSARG_1), SYSARG_2, (FD(SYSARG_3) & AT_REMOVEDIR) != 0);
	case PR_rename:
		return do_rename(tracee, AT_FDCWD, SYSARG_1, AT_FDCWD, SYSARG_2, 0);
	case PR_renameat:
		return do_rename(tracee, FD(SYSARG_1), SYSARG_2, FD(SYSARG_3), SYSARG_4, 0);
	case PR_renameat2:
		return do_rename(tracee, FD(SYSARG_1), SYSARG_2, FD(SYSARG_3), SYSARG_4, (unsigned) FD(SYSARG_5));
	case PR_link:
		return do_link(tracee, AT_FDCWD, SYSARG_1, AT_FDCWD, SYSARG_2, 0);
	case PR_linkat:
		return do_link(tracee, FD(SYSARG_1), SYSARG_2, FD(SYSARG_3), SYSARG_4, FD(SYSARG_5));
	case PR_symlink:
		return do_symlink(tracee, SYSARG_1, AT_FDCWD, SYSARG_2);
	case PR_symlinkat:
		return do_symlink(tracee, SYSARG_1, FD(SYSARG_2), SYSARG_3);
	case PR_mknod:
		return do_mknod(tracee, AT_FDCWD, SYSARG_1, SYSARG_2, SYSARG_3);
	case PR_mknodat:
		return do_mknod(tracee, FD(SYSARG_1), SYSARG_2, SYSARG_3, SYSARG_4);
	case PR_open:
		return do_create(tracee, AT_FDCWD, SYSARG_1, peek_reg(tracee, CURRENT, SYSARG_2),
				 (mode_t) FD(SYSARG_3), SYSARG_2, 0);
	case PR_openat:
		return do_create(tracee, FD(SYSARG_1), SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_3),
				 (mode_t) FD(SYSARG_4), SYSARG_3, 0);
	case PR_openat2: {
		word_t how = peek_reg(tracee, CURRENT, SYSARG_3);
		word_t flags, mode;

		errno = 0;
		flags = peek_uint64(tracee, how);
		mode = peek_uint64(tracee, how + 8);
		if (errno != 0)
			return 0;
		return do_create(tracee, FD(SYSARG_1), SYSARG_2, flags, (mode_t) mode, -1, how);
	}
	case PR_creat:
		return do_create(tracee, AT_FDCWD, SYSARG_1, O_WRONLY | O_CREAT | O_TRUNC,
				 (mode_t) FD(SYSARG_2), -1, 0);

	case PR_chmod:
		image = meta_path(tracee, AT_FDCWD, SYSARG_1, true, host, &status);
		return image == NULL ? status : set_mode(tracee, image, host, (mode_t) FD(SYSARG_2));
	case PR_fchmodat:
		image = meta_path(tracee, FD(SYSARG_1), SYSARG_2, true, host, &status);
		return image == NULL ? status : set_mode(tracee, image, host, (mode_t) FD(SYSARG_3));
	case PR_fchmod:
		fd = FD(SYSARG_1);
		if (dn_fd_path(tracee, fd, host) < 0 || (image = image_of(host)) == NULL)
			return 0;
		return set_mode(tracee, image, host, (mode_t) FD(SYSARG_2));

	case PR_chown:
	case PR_chown32:
	case PR_lchown:
	case PR_lchown32: {
		Sysnum sysnum = get_sysnum(tracee, ORIGINAL);
		bool deref = sysnum == PR_chown || sysnum == PR_chown32;

		image = meta_path(tracee, AT_FDCWD, SYSARG_1, deref, host, &status);
		return image == NULL ? status : set_owner(tracee, image, host, id_arg(tracee, SYSARG_2), id_arg(tracee, SYSARG_3));
	}
	case PR_fchownat:
		image = meta_path(tracee, FD(SYSARG_1), SYSARG_2, (FD(SYSARG_5) & AT_SYMLINK_NOFOLLOW) == 0, host, &status);
		return image == NULL ? status : set_owner(tracee, image, host, id_arg(tracee, SYSARG_3), id_arg(tracee, SYSARG_4));
	case PR_fchown:
	case PR_fchown32:
		fd = FD(SYSARG_1);
		if (dn_fd_path(tracee, fd, host) < 0 || (image = image_of(host)) == NULL)
			return 0;
		return set_owner(tracee, image, host, id_arg(tracee, SYSARG_2), id_arg(tracee, SYSARG_3));

	default:
		return 0;
	}
#undef FD
}

/* What the guest sees */

/**
 * Mode the image gives @host_path, a path of an image.  Returns -1 if
 * it isn't one.
 */
int dn_image_presented_mode(const char *host_path, mode_t *mode)
{
	Inode inode;
	Image *image = image_of(host_path);
	int64_t ino;

	if (image == NULL)
		return -1;
	ino = ino_of(image, host_path);
	if (ino < 0 || get_inode(image, ino, &inode) < 0)
		return -1;
	*mode = inode.mode;
	return 0;
}

static int inode_of_path(const char *host_path, Inode *inode)
{
	Image *image = image_of(host_path);
	int64_t ino;

	if (image == NULL)
		return -1;
	ino = ino_of(image, host_path);
	if (ino < 0 || get_inode(image, ino, inode) < 0)
		return -1;
	return 0;
}

/**
 * Put mode, owner, link count and device number of @inode into the
 * stat structure at @address.
 */
static void poke_stat(Tracee *tracee, word_t address, const Inode *inode, uint32_t host_mode)
{
	uint32_t mode = inode->mode;

	// A directory keeps the link count of its shadow
	if (S_ISDIR(host_mode) != S_ISDIR(mode))
		mode = (host_mode & S_IFMT) | (mode & 07777);

	poke_uint32(tracee, address + offsetof_stat_mode(tracee), mode);
	poke_uint32(tracee, address + offsetof_stat_uid(tracee), (uint32_t) inode->uid);
	poke_uint32(tracee, address + offsetof_stat_gid(tracee), (uint32_t) inode->gid);

	if (is_32on64_mode(tracee)) {
		// struct stat64: st_nlink at 20, st_rdev at 32
		if (!S_ISDIR(mode))
			poke_uint32(tracee, address + 20, (uint32_t) inode->nlink);
		poke_uint64(tracee, address + 32, inode->rdev);
		return;
	}
	if (!S_ISDIR(mode)) {
		if (sizeof(((struct stat *) 0)->st_nlink) == 8)
			poke_uint64(tracee, address + offsetof(struct stat, st_nlink), (uint64_t) inode->nlink);
		else
			poke_uint32(tracee, address + offsetof(struct stat, st_nlink), (uint32_t) inode->nlink);
	}
	if (sizeof(((struct stat *) 0)->st_rdev) == 8)
		poke_uint64(tracee, address + offsetof(struct stat, st_rdev), inode->rdev);
	else
		poke_uint32(tracee, address + offsetof(struct stat, st_rdev), (uint32_t) inode->rdev);
}

void dn_image_exit_end(Tracee *tracee)
{
	char path[PATH_MAX];
	word_t address;
	Inode inode;
	uint32_t mode;
	Reg buf_reg;

	switch (get_sysnum(tracee, ORIGINAL)) {
	case PR_stat:
	case PR_stat64:
	case PR_lstat:
	case PR_lstat64:
	case PR_fstat:
	case PR_fstat64:
		buf_reg = SYSARG_2;
		break;
	case PR_newfstatat:
	case PR_fstatat64:
		buf_reg = SYSARG_3;
		break;
	default:
		return;
	}

	if (peek_reg(tracee, CURRENT, SYSARG_RESULT) != 0)
		return;
	if (dn_stat_target(tracee, path) < 0 || inode_of_path(path, &inode) < 0)
		return;

	address = peek_reg(tracee, ORIGINAL, buf_reg);
	errno = 0;
	mode = peek_uint32(tracee, address + offsetof_stat_mode(tracee));
	if (errno != 0)
		return;
	poke_stat(tracee, address, &inode, mode);
}

void dn_image_statx(struct statx_syscall_state *state)
{
	Inode inode;
	uint16_t mode;

	if (inode_of_path(state->host_path, &inode) < 0)
		return;

	mode = (uint16_t) inode.mode;
	if (S_ISDIR(state->statx_buf.stx_mode) != S_ISDIR(mode))
		mode = (state->statx_buf.stx_mode & S_IFMT) | (mode & 07777);
	state->statx_buf.stx_mode = mode;
	state->statx_buf.stx_uid = (uint32_t) inode.uid;
	state->statx_buf.stx_gid = (uint32_t) inode.gid;
	if (!S_ISDIR(mode))
		state->statx_buf.stx_nlink = (uint32_t) inode.nlink;
	state->statx_buf.stx_rdev_major = major(inode.rdev);
	state->statx_buf.stx_rdev_minor = minor(inode.rdev);
	state->updated_stats = true;
}

/**
 * /proc/PID/fd/N of a content file: report the path of the file in the
 * image instead (through the shadow, which PRoot detranslates).
 */
void dn_image_proc_fd(struct readlink_proc_fd_state *state)
{
	char rel[PATH_MAX] = "";
	char joined[PATH_MAX];
	sqlite3_stmt *stmt;
	Image *image;
	int64_t ino;
	int depth;

	image = image_of(state->host_path);
	if (image == NULL || !dn_path_in(state->host_path, image->data))
		return;
	ino = ino_of(image, state->host_path);

	for (depth = 0; ino > 1 && depth < 256; depth++) {
		stmt = statement(image, ST_ENTRY_OF);
		sqlite3_bind_int64(stmt, 1, ino);
		if (sqlite3_step(stmt) != SQLITE_ROW)
			return;
		snprintf(joined, sizeof(joined), "/%s%s", (const char *) sqlite3_column_text(stmt, 1), rel);
		strcpy(rel, joined);
		ino = sqlite3_column_int64(stmt, 0);
	}
	if (ino != 1)
		return;
	snprintf(state->host_path, PATH_MAX, "%s%s", image->tree, rel);
	state->substituted = true;
}

int dn_image_initialize(Tracee *tracee)
{
	(void) tracee;
	return 0;
}
