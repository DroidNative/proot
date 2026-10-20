/* Read-only view of a directory through FUSE (libfuse3), for the tests
 * of the FUSE emulation (extension/dn_storage/fuse.c).
 *
 * Usage: fuse-ro <source dir> <mount point> [-f] [libfuse options]
 * Build: cc -O2 fuse-ro.c $(pkg-config --cflags --libs fuse3) -o fuse-ro
 */
#define FUSE_USE_VERSION 31
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char source[PATH_MAX];

static void full(char out[PATH_MAX], const char *path)
{
	snprintf(out, PATH_MAX, "%s%s", source, path);
}

static int ro_getattr(const char *path, struct stat *st, struct fuse_file_info *fi)
{
	char p[PATH_MAX];

	(void) fi;
	full(p, path);
	return lstat(p, st) < 0 ? -errno : 0;
}

static int ro_readlink(const char *path, char *buf, size_t size)
{
	char p[PATH_MAX];
	ssize_t n;

	full(p, path);
	n = readlink(p, buf, size - 1);
	if (n < 0)
		return -errno;
	buf[n] = '\0';
	return 0;
}

static int ro_readdir(const char *path, void *buf, fuse_fill_dir_t fill, off_t off,
		      struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
	char p[PATH_MAX];
	struct dirent *e;
	DIR *d;

	(void) off; (void) fi; (void) flags;
	full(p, path);
	d = opendir(p);
	if (d == NULL)
		return -errno;
	while ((e = readdir(d)) != NULL)
		fill(buf, e->d_name, NULL, 0, 0);
	closedir(d);
	return 0;
}

static int ro_open(const char *path, struct fuse_file_info *fi)
{
	char p[PATH_MAX];
	int fd;

	if ((fi->flags & O_ACCMODE) != O_RDONLY)
		return -EROFS;
	full(p, path);
	fd = open(p, O_RDONLY);
	if (fd < 0)
		return -errno;
	fi->fh = fd;
	return 0;
}

static int ro_read(const char *path, char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
	ssize_t n;

	(void) path;
	n = pread(fi->fh, buf, size, off);
	return n < 0 ? -errno : (int) n;
}

static int ro_release(const char *path, struct fuse_file_info *fi)
{
	(void) path;
	close(fi->fh);
	return 0;
}

static const struct fuse_operations ops = {
	.getattr = ro_getattr,
	.readlink = ro_readlink,
	.readdir = ro_readdir,
	.open = ro_open,
	.read = ro_read,
	.release = ro_release,
};

int main(int argc, char *argv[])
{
	if (argc < 3 || realpath(argv[1], source) == NULL) {
		fprintf(stderr, "usage: %s <source dir> <mount point> [options]\n", argv[0]);
		return 2;
	}
	argv[1] = argv[0];
	return fuse_main(argc - 1, argv + 1, &ops, NULL);
}
