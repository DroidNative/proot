/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * DroidNative storage: FUSE file-systems without the kernel's FUSE.
 *
 * open("/dev/fuse") gives the tracee one end of a SOCK_SEQPACKET
 * socket instead (a packet is a FUSE message, as a read(2) or write(2)
 * of /dev/fuse is), and PRoot plays the kernel at the other end.  A
 * mount(2) of type "fuse*" binds a directory of PRoot's temporary
 * directory at the mount point.  What the guest looks at is copied
 * there on demand: the entries of a directory when a path goes through
 * it, the content of a file when it is opened or executed.  Programs
 * can run from there, which noexec storage and Android's own FUSE
 * mounts don't allow.  The emulated file-systems are read-only.
 *
 * A syscall that needs an answer of the file-system daemon can't wait
 * for it in place: the daemon is a tracee too, and it can only answer
 * while PRoot goes on handling its syscalls.  Such a syscall "parks"
 * its tracee instead (see translate_syscall()): it stays stopped at
 * its sysenter stage, untouched, and is handled again from scratch
 * once the daemon has answered (see resume_parked_tracee()).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 */

#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <linux/fuse.h>
#include <talloc.h>

#include "extension/dn_storage/dn_storage.h"
#include "syscall/sysnum.h"
#include "syscall/chain.h"
#include "syscall/syscall.h"
#include "tracee/mem.h"
#include "tracee/tracee.h"
#include "path/temp.h"
#include "path/path.h"
#include "path/binding.h"
#include "cli/note.h"

/* Protocol version PRoot speaks, as Linux 5.10 does.  */
#define PROTO_MINOR 31

/* Size of READ and READDIR requests; a reply has to fit in one packet.  */
#define CHUNK (64 * 1024)

/* Reads of one file in flight at once.  */
#define READ_WINDOW 8

typedef struct mount Mount;

typedef struct node {
	char *rel;		// path below the mount point, "" for its root
	uint64_t nodeid;
	struct fuse_attr attr;

	enum { UNLISTED = 0, LISTING, LISTED } list;
	enum { NO_DATA = 0, FETCHING, FETCHED } data;
	int error;		// what the daemon answered, -errno

	uint64_t fh;
	uint64_t dir_offset;
	uint64_t next_read;	// offset of the next READ to send
	int in_flight;		// LOOKUP/READLINK (listing) or READ replies
	bool dir_done;		// READDIR said there was nothing left
	int data_fd;		// placeholder being filled

	struct node *hash_next;
} Node;

typedef struct request {
	uint64_t unique;
	uint32_t opcode;
	Node *node;		// what the answer is for
	char *name;		// LOOKUP: entry of node
	uint64_t offset;	// READ
	struct request *next;
} Request;

typedef struct packet {
	size_t size;
	struct packet *next;
	char data[];
} Packet;

struct mount {
	int conn;
	char *cache;		// host directory bound at the mount point
	bool ready;		// INIT answered
	bool dead;		// daemon gone or unmounted
	uint32_t max_write;

	Node **nodes;
	size_t nb_buckets;
	size_t nb_nodes;

	Request *requests;
	uint64_t next_unique;
	Packet *out_head, *out_tail;

	Mount *next;
};

/* Sockets that were /dev/fuse for the tracee, not mounted yet.  */
typedef struct device {
	ino_t ino;		// of the tracee's end
	int conn;
	struct device *next;
} Device;

static TALLOC_CTX *context;
static const char *device_path;
static Mount *mounts;
static Device *devices;
static int wake_pipe[2] = { -1, -1 };

/* Parked tracees, see park().  */
static pid_t *parked;
static size_t nb_parked;

static void send_request(Mount *mount, uint32_t opcode, Node *node, const void *body,
			 size_t size, const char *name, uint64_t offset);

/* Setup */

static void sigchld_handler(int signum)
{
	int saved_errno = errno;

	(void) signum;
	if (write(wake_pipe[1], "c", 1) < 0) {
		// Full pipe: the event loop wakes up anyway
	}
	errno = saved_errno;
}

/**
 * Enable the emulation (--fuse): a placeholder for /dev/fuse, and a
 * SIGCHLD handler that interrupts dn_fuse_poll() when a tracee stops.
 */
int dn_storage_enable_fuse(void)
{
	struct sigaction action;

	if (device_path != NULL)
		return 0;

	context = talloc_named_const(talloc_autofree_context(), 0, "dn_fuse");
	if (context == NULL)
		return -1;

	device_path = create_temp_file(context, "proot-fuse-dev");
	if (device_path == NULL)
		return -1;
	(void) chmod(device_path, 0666);

	if (pipe2(wake_pipe, O_NONBLOCK | O_CLOEXEC) < 0)
		return -1;

	memset(&action, 0, sizeof(action));
	action.sa_handler = sigchld_handler;
	action.sa_flags = SA_RESTART;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGCHLD, &action, NULL) < 0)
		return -1;

	return 0;
}

/**
 * Host path of the /dev/fuse placeholder, NULL when the emulation is
 * off.  The command line binds it at /dev/fuse.
 */
const char *dn_fuse_device(void)
{
	return device_path;
}

bool dn_fuse_active(void)
{
	return mounts != NULL || devices != NULL;
}

/* Nodes */

static size_t hash_string(const char *string)
{
	size_t hash = 2166136261u;

	for (; *string != '\0'; string++)
		hash = (hash ^ (unsigned char) *string) * 16777619u;
	return hash;
}

static Node *find_node(const Mount *mount, const char *rel)
{
	Node *node;

	for (node = mount->nodes[hash_string(rel) % mount->nb_buckets]; node != NULL; node = node->hash_next) {
		if (strcmp(node->rel, rel) == 0)
			return node;
	}
	return NULL;
}

static Node *add_node(Mount *mount, const char *rel, uint64_t nodeid, const struct fuse_attr *attr)
{
	Node *node;
	size_t i;

	node = find_node(mount, rel);
	if (node != NULL)
		return node;

	// Grow at a load of 1
	if (mount->nb_nodes >= mount->nb_buckets) {
		size_t nb_buckets = mount->nb_buckets * 2;
		Node **buckets = talloc_zero_array(mount, Node *, nb_buckets);

		if (buckets == NULL)
			return NULL;
		for (i = 0; i < mount->nb_buckets; i++) {
			while (mount->nodes[i] != NULL) {
				Node *moved = mount->nodes[i];
				size_t slot = hash_string(moved->rel) % nb_buckets;

				mount->nodes[i] = moved->hash_next;
				moved->hash_next = buckets[slot];
				buckets[slot] = moved;
			}
		}
		talloc_free(mount->nodes);
		mount->nodes = buckets;
		mount->nb_buckets = nb_buckets;
	}

	node = talloc_zero(mount, Node);
	if (node == NULL)
		return NULL;
	node->rel = talloc_strdup(node, rel);
	if (node->rel == NULL)
		return NULL;
	node->nodeid = nodeid;
	if (attr != NULL)
		node->attr = *attr;
	node->data_fd = -1;

	i = hash_string(rel) % mount->nb_buckets;
	node->hash_next = mount->nodes[i];
	mount->nodes[i] = node;
	mount->nb_nodes++;
	return node;
}

/**
 * Copy into @path the host path of @node.
 */
static void node_path(const Mount *mount, const Node *node, char path[PATH_MAX])
{
	if (node->rel[0] == '\0')
		snprintf(path, PATH_MAX, "%s", mount->cache);
	else
		snprintf(path, PATH_MAX, "%s/%s", mount->cache, node->rel);
}

static void set_times(const char *path, const struct fuse_attr *attr)
{
	struct timespec times[2] = {
		{ .tv_sec = (time_t) attr->atime, .tv_nsec = attr->atimensec },
		{ .tv_sec = (time_t) attr->mtime, .tv_nsec = attr->mtimensec },
	};

	(void) utimensat(AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW);
}

/**
 * Create the placeholder of a new entry @rel of @dir: directories and
 * files get the daemon's mode, files their size too (sparse until
 * fetch_data() fills them).  PRoot keeps write access for itself;
 * check_access() makes the mount read-only for the tracees.
 */
static void create_entry(Mount *mount, Node *dir, const char *name, const struct fuse_entry_out *entry)
{
	char rel[PATH_MAX];
	char path[PATH_MAX];
	mode_t mode = entry->attr.mode;
	Node *node;
	int fd;

	if (dir->rel[0] == '\0')
		snprintf(rel, sizeof(rel), "%s", name);
	else
		snprintf(rel, sizeof(rel), "%s/%s", dir->rel, name);

	node = add_node(mount, rel, entry->nodeid, &entry->attr);
	if (node == NULL)
		return;
	node_path(mount, node, path);

	if (S_ISDIR(mode)) {
		if (mkdir(path, 0700) < 0 && errno != EEXIST)
			return;
		(void) chmod(path, (mode & 07777) | S_IRWXU);
		set_times(path, &entry->attr);
	}
	else if (S_ISLNK(mode)) {
		// The target comes with READLINK, see handle_reply()
		dir->in_flight++;
		send_request(mount, FUSE_READLINK, node, NULL, 0, NULL, 0);
	}
	else {
		fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
		if (fd < 0)
			return;
		if (!S_ISREG(mode))
			node->data = FETCHED;	// Nothing to read from devices, FIFOs, sockets
		else if (ftruncate(fd, (off_t) entry->attr.size) < 0)
			node->error = -errno;
		(void) fchmod(fd, (mode & 07777) | S_IRUSR | S_IWUSR);
		close(fd);
		set_times(path, &entry->attr);
	}
}

/* Messages */

static void queue_packet(Mount *mount, const void *data, size_t size)
{
	Packet *packet = talloc_size(mount, sizeof(Packet) + size);

	if (packet == NULL)
		return;
	talloc_set_name_const(packet, "Packet");
	packet->size = size;
	packet->next = NULL;
	memcpy(packet->data, data, size);

	if (mount->out_tail != NULL)
		mount->out_tail->next = packet;
	else
		mount->out_head = packet;
	mount->out_tail = packet;
}

static void flush_packets(Mount *mount)
{
	while (mount->out_head != NULL && !mount->dead) {
		Packet *packet = mount->out_head;

		if (send(mount->conn, packet->data, packet->size, MSG_DONTWAIT | MSG_NOSIGNAL) < 0) {
			if (errno == EAGAIN || errno == EINTR)
				return;
			mount->dead = true;
			return;
		}
		mount->out_head = packet->next;
		if (mount->out_head == NULL)
			mount->out_tail = NULL;
		talloc_free(packet);
	}
}

/**
 * Send the request @opcode about @node with the given @body; @name is
 * appended for LOOKUP.  The answer goes to handle_reply().
 */
static void send_request(Mount *mount, uint32_t opcode, Node *node, const void *body,
			 size_t size, const char *name, uint64_t offset)
{
	char buffer[sizeof(struct fuse_in_header) + sizeof(struct fuse_read_in) + NAME_MAX + 1];
	struct fuse_in_header *header = (struct fuse_in_header *) buffer;
	size_t name_size = name != NULL ? strlen(name) + 1 : 0;
	Request *request;

	if (size + name_size > sizeof(buffer) - sizeof(*header))
		return;

	memset(header, 0, sizeof(*header));
	header->len = sizeof(*header) + size + name_size;
	header->opcode = opcode;
	header->unique = mount->next_unique++;
	header->nodeid = node != NULL ? node->nodeid : FUSE_ROOT_ID;
	if (size > 0)
		memcpy(buffer + sizeof(*header), body, size);
	if (name_size > 0)
		memcpy(buffer + sizeof(*header) + size, name, name_size);

	// FORGET-like requests get no answer; all of these do
	request = talloc_zero(mount, Request);
	if (request == NULL)
		return;
	request->unique = header->unique;
	request->opcode = opcode;
	request->node = node;
	request->offset = offset;
	if (name != NULL)
		request->name = talloc_strdup(request, name);
	request->next = mount->requests;
	mount->requests = request;

	queue_packet(mount, buffer, header->len);
}

static void send_read(Mount *mount, Node *node, uint32_t opcode, uint64_t offset)
{
	struct fuse_read_in in;

	memset(&in, 0, sizeof(in));
	in.fh = node->fh;
	in.offset = offset;
	in.size = CHUNK;
	send_request(mount, opcode, node, &in, sizeof(in), NULL, offset);
}

static void send_release(Mount *mount, Node *node, uint32_t opcode)
{
	struct fuse_release_in in;

	memset(&in, 0, sizeof(in));
	in.fh = node->fh;
	send_request(mount, opcode, node, &in, sizeof(in), NULL, 0);
}

/* Listing directories and fetching files */

static void start_listing(Mount *mount, Node *node)
{
	struct fuse_open_in in;

	memset(&in, 0, sizeof(in));
	in.flags = O_RDONLY | O_DIRECTORY;
	node->list = LISTING;
	node->dir_offset = 0;
	node->dir_done = false;
	node->in_flight = 0;
	send_request(mount, FUSE_OPENDIR, node, &in, sizeof(in), NULL, 0);
}

static void finish_listing(Mount *mount, Node *node)
{
	char path[PATH_MAX];

	if (node->list != LISTING || !node->dir_done || node->in_flight > 0)
		return;
	node->list = LISTED;

	// Creating the entries changed the directory's times
	node_path(mount, node, path);
	if (node->nodeid != FUSE_ROOT_ID || node->attr.mtime != 0)
		set_times(path, &node->attr);
}

static void start_fetching(Mount *mount, Node *node)
{
	struct fuse_open_in in;
	char path[PATH_MAX];

	node_path(mount, node, path);
	node->data_fd = open(path, O_WRONLY | O_CLOEXEC);
	if (node->data_fd < 0) {
		node->data = FETCHED;
		node->error = -errno;
		return;
	}

	memset(&in, 0, sizeof(in));
	in.flags = O_RDONLY;
	node->data = FETCHING;
	node->next_read = 0;
	node->in_flight = 0;
	send_request(mount, FUSE_OPEN, node, &in, sizeof(in), NULL, 0);
}

static void read_more(Mount *mount, Node *node)
{
	while (node->in_flight < READ_WINDOW && node->next_read < node->attr.size) {
		send_read(mount, node, FUSE_READ, node->next_read);
		node->next_read += CHUNK;
		node->in_flight++;
	}
}

static void finish_fetching(Mount *mount, Node *node)
{
	char path[PATH_MAX];

	if (node->data != FETCHING || node->in_flight > 0 || node->next_read < node->attr.size)
		return;

	send_release(mount, node, FUSE_RELEASE);
	close(node->data_fd);
	node->data_fd = -1;
	node->data = FETCHED;

	node_path(mount, node, path);
	set_times(path, &node->attr);
}

static void fail_node(Mount *mount, Node *node, int error)
{
	node->error = error;
	if (node->list == LISTING)
		node->list = LISTED;
	if (node->data == FETCHING) {
		if (node->data_fd >= 0)
			close(node->data_fd);
		node->data_fd = -1;
		node->data = FETCHED;
	}
	(void) mount;
}

/* Answers of the daemon */

static Request *take_request(Mount *mount, uint64_t unique)
{
	Request **link;

	for (link = &mount->requests; *link != NULL; link = &(*link)->next) {
		Request *request = *link;

		if (request->unique == unique) {
			*link = request->next;
			return request;
		}
	}
	return NULL;
}

static void handle_init(Mount *mount, int error, const char *body, size_t size)
{
	const struct fuse_init_out *out = (const struct fuse_init_out *) body;

	if (error != 0 || size < 8 || out->major != FUSE_KERNEL_VERSION) {
		note(NULL, WARNING, USER, "FUSE: the file-system daemon refused INIT (%d)", error);
		mount->dead = true;
		return;
	}
	mount->max_write = size >= 24 ? out->max_write : 4096;
	mount->ready = true;

	// Mode and times of the mount point
	send_request(mount, FUSE_GETATTR, find_node(mount, ""), &(struct fuse_getattr_in) {0},
		     sizeof(struct fuse_getattr_in), NULL, 0);
}

static void handle_readdir(Mount *mount, Node *node, const char *body, size_t size)
{
	struct fuse_entry_out none;
	size_t offset = 0;

	(void) none;
	if (size == 0) {
		node->dir_done = true;
		send_release(mount, node, FUSE_RELEASEDIR);
		finish_listing(mount, node);
		return;
	}

	while (offset + FUSE_NAME_OFFSET <= size) {
		const struct fuse_dirent *entry = (const struct fuse_dirent *) (body + offset);
		char name[NAME_MAX + 1];

		if (entry->namelen == 0 || entry->namelen > NAME_MAX
		    || offset + FUSE_DIRENT_SIZE(entry) > size)
			break;

		memcpy(name, entry->name, entry->namelen);
		name[entry->namelen] = '\0';
		node->dir_offset = entry->off;
		offset += FUSE_DIRENT_SIZE(entry);

		if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
			continue;

		node->in_flight++;
		send_request(mount, FUSE_LOOKUP, node, NULL, 0, name, 0);
	}

	send_read(mount, node, FUSE_READDIR, node->dir_offset);
}

static void handle_reply(Mount *mount, const char *packet, size_t size)
{
	const struct fuse_out_header *header = (const struct fuse_out_header *) packet;
	const char *body = packet + sizeof(*header);
	size_t body_size;
	char path[PATH_MAX];
	Request *request;
	Node *node;

	if (size < sizeof(*header) || header->unique == 0)
		return;		// Notifications are of no use here
	body_size = size - sizeof(*header);

	request = take_request(mount, header->unique);
	if (request == NULL)
		return;
	node = request->node;

	switch (request->opcode) {
	case FUSE_INIT:
		handle_init(mount, header->error, body, body_size);
		break;

	case FUSE_GETATTR:
		if (header->error == 0 && body_size >= sizeof(struct fuse_attr_out) && node != NULL) {
			node->attr = ((const struct fuse_attr_out *) body)->attr;
			node_path(mount, node, path);
			(void) chmod(path, (node->attr.mode & 07777) | S_IRWXU);
			set_times(path, &node->attr);
		}
		break;

	case FUSE_OPENDIR:
		if (header->error != 0) {
			fail_node(mount, node, header->error);
			break;
		}
		if (body_size >= sizeof(struct fuse_open_out))
			node->fh = ((const struct fuse_open_out *) body)->fh;
		send_read(mount, node, FUSE_READDIR, 0);
		break;

	case FUSE_READDIR:
		if (header->error != 0) {
			node->dir_done = true;
			if (node->in_flight == 0)
				fail_node(mount, node, header->error);
			break;
		}
		handle_readdir(mount, node, body, body_size);
		break;

	case FUSE_LOOKUP:
		node->in_flight--;
		if (header->error == 0 && body_size >= sizeof(struct fuse_entry_out))
			create_entry(mount, node, request->name, (const struct fuse_entry_out *) body);
		finish_listing(mount, node);
		break;

	case FUSE_READLINK: {
		Node *dir;
		char target[PATH_MAX];
		char dir_rel[PATH_MAX];
		char *slash;

		if (header->error == 0 && body_size > 0 && body_size < sizeof(target)) {
			memcpy(target, body, body_size);
			target[body_size] = '\0';
			node_path(mount, node, path);
			if (symlink(target, path) < 0)
				node->error = -errno;
			set_times(path, &node->attr);
		}

		// The listing waits for the target
		snprintf(dir_rel, sizeof(dir_rel), "%s", node->rel);
		slash = strrchr(dir_rel, '/');
		if (slash != NULL)
			*slash = '\0';
		else
			dir_rel[0] = '\0';
		dir = find_node(mount, dir_rel);
		if (dir != NULL) {
			dir->in_flight--;
			finish_listing(mount, dir);
		}
		break;
	}

	case FUSE_OPEN:
		if (header->error != 0) {
			fail_node(mount, node, header->error);
			break;
		}
		if (body_size >= sizeof(struct fuse_open_out))
			node->fh = ((const struct fuse_open_out *) body)->fh;
		read_more(mount, node);
		finish_fetching(mount, node);
		break;

	case FUSE_READ:
		if (node->data != FETCHING)
			break;
		node->in_flight--;
		if (header->error != 0) {
			fail_node(mount, node, header->error);
			break;
		}
		if (body_size > 0
		    && pwrite(node->data_fd, body, body_size, (off_t) request->offset) != (ssize_t) body_size) {
			fail_node(mount, node, -EIO);
			break;
		}
		read_more(mount, node);
		finish_fetching(mount, node);
		break;

	default:
		break;
	}

	talloc_free(request);
}

/**
 * The daemon is gone or the file-system was unmounted: whatever waits
 * for it fails with ENOTCONN, as with the kernel.
 */
static void kill_mount(Mount *mount)
{
	size_t i;
	Node *node;

	mount->dead = true;
	if (mount->conn >= 0) {
		close(mount->conn);
		mount->conn = -1;
	}
	for (i = 0; i < mount->nb_buckets; i++) {
		for (node = mount->nodes[i]; node != NULL; node = node->hash_next) {
			if (node->list == LISTING || node->data == FETCHING)
				fail_node(mount, node, -ENOTCONN);
		}
	}
}

static void receive_packets(Mount *mount)
{
	size_t capacity = sizeof(struct fuse_out_header) + CHUNK + 4096;
	char *buffer = talloc_size(mount, capacity);

	if (buffer == NULL)
		return;

	for (;;) {
		ssize_t size = recv(mount->conn, buffer, capacity, MSG_DONTWAIT);

		if (size < 0) {
			if (errno != EAGAIN && errno != EINTR)
				kill_mount(mount);
			break;
		}
		if (size == 0) {
			kill_mount(mount);
			break;
		}
		handle_reply(mount, buffer, (size_t) size);
	}
	talloc_free(buffer);
}

/* Parking */

/**
 * Keep @tracee stopped until the daemon of @mount made progress: its
 * sysenter stage is handled again then.  Returns the status that ends
 * the translation of the current syscall, or 0 when the tracee can't
 * wait (outside of a sysenter stage), in which case it goes on with
 * whatever is there.
 */
static int park(Tracee *tracee)
{
	pid_t *list;

	if (!tracee->dn.can_park)
		return 0;

	list = talloc_realloc(context, parked, pid_t, nb_parked + 1);
	if (list == NULL)
		return 0;
	parked = list;
	parked[nb_parked++] = tracee->pid;
	tracee->dn.parked = true;
	VERBOSE(tracee, 2, "vpid %" PRIu64 ": parked for FUSE", tracee->vpid);
	return -EAGAIN;
}

static void resume_parked(void)
{
	pid_t *list = parked;
	size_t count = nb_parked;
	size_t i;

	if (count == 0)
		return;

	// Resumed tracees may park again
	parked = NULL;
	nb_parked = 0;
	for (i = 0; i < count; i++) {
		Tracee *tracee = get_tracee(NULL, list[i], false);

		if (tracee != NULL && tracee->dn.parked && !tracee->terminated)
			resume_parked_tracee(tracee);
	}
	talloc_free(list);
}

/**
 * Remove every binding of @host_path, in all name spaces.
 */
static void drop_bindings(const char *host_path)
{
	Tracee *tracee;

	LIST_FOREACH(tracee, get_tracees_list_head(), link) {
		Binding *binding;
		Binding *next;

		if (tracee->fs == NULL || tracee->fs->bindings.guest == NULL)
			continue;
		for (binding = CIRCLEQ_FIRST(tracee->fs->bindings.guest);
		     binding != (void *) tracee->fs->bindings.guest; binding = next) {
			next = CIRCLEQ_NEXT(binding, link.guest);
			if (strcmp(binding->host.path, host_path) == 0)
				remove_binding_from_all_lists(tracee, binding);
		}
	}
}

/**
 * Unmount the file-systems whose daemon is gone.  The kernel would keep
 * them ("Transport endpoint is not connected") until fusermount -u, which
 * can't work here: emulated mounts aren't in /proc/mounts.
 */
static void reap_mounts(void)
{
	Mount **link = &mounts;

	while (*link != NULL) {
		Mount *mount = *link;

		if (!mount->dead) {
			link = &mount->next;
			continue;
		}
		*link = mount->next;
		drop_bindings(mount->cache);
		talloc_free(mount);	// Removes the copies too
	}
}

/**
 * Wait for the daemons of the emulated file-systems or a tracee, and
 * handle what the daemons said.  Returns -EINTR when a signal came.
 */
int dn_fuse_poll(void)
{
	struct pollfd fds[64];
	Mount *index[64];
	char drain[64];
	Mount *mount;
	size_t count = 1;
	size_t i;
	int status;

	fds[0].fd = wake_pipe[0];
	fds[0].events = POLLIN;
	for (mount = mounts; mount != NULL && count < 64; mount = mount->next) {
		if (mount->dead)
			continue;
		fds[count].fd = mount->conn;
		fds[count].events = POLLIN | (mount->out_head != NULL ? POLLOUT : 0);
		index[count] = mount;
		count++;
	}

	// A tracee may stop between waitpid(WNOHANG) and poll(2): SIGCHLD
	// wakes the pipe, the timeout covers the rest.
	status = poll(fds, count, 1000);
	if (status < 0)
		return errno == EINTR ? -EINTR : 0;

	while (read(wake_pipe[0], drain, sizeof(drain)) > 0)
		;

	for (i = 1; i < count; i++) {
		mount = index[i];
		if ((fds[i].revents & POLLOUT) != 0)
			flush_packets(mount);
		if ((fds[i].revents & (POLLIN | POLLHUP | POLLERR)) != 0)
			receive_packets(mount);
		if (mount->dead)
			kill_mount(mount);
		else
			flush_packets(mount);
	}

	reap_mounts();
	resume_parked();
	return 0;
}

/* Syscalls */

static Mount *find_mount(const char *host_path)
{
	Mount *mount;

	for (mount = mounts; mount != NULL; mount = mount->next) {
		if (dn_path_in(host_path, mount->cache))
			return mount;
	}
	return NULL;
}

/**
 * Open flags of the current syscall of @tracee, or -1 if it isn't an
 * open(2)-like syscall.
 */
static long open_flags(const Tracee *tracee)
{
	switch (get_sysnum(tracee, ORIGINAL)) {
	case PR_open:
		return (long) peek_reg(tracee, ORIGINAL, SYSARG_2);
	case PR_openat:
		return (long) peek_reg(tracee, ORIGINAL, SYSARG_3);
	case PR_openat2: {
		uint64_t flags;

		errno = 0;
		flags = peek_uint64(tracee, peek_reg(tracee, ORIGINAL, SYSARG_3));
		return errno != 0 ? 0 : (long) flags;
	}
	case PR_creat:
		return O_WRONLY | O_CREAT | O_TRUNC;
	default:
		return -1;
	}
}

static bool is_write_syscall(Sysnum sysnum)
{
	switch (sysnum) {
	case PR_mkdir: case PR_mkdirat: case PR_rmdir:
	case PR_unlink: case PR_unlinkat:
	case PR_rename: case PR_renameat: case PR_renameat2:
	case PR_link: case PR_linkat: case PR_symlink: case PR_symlinkat:
	case PR_mknod: case PR_mknodat:
	case PR_truncate: case PR_truncate64:
	case PR_chmod: case PR_fchmodat: case PR_fchmodat2:
	case PR_chown: case PR_chown32: case PR_lchown: case PR_lchown32: case PR_fchownat:
	case PR_utime: case PR_utimes: case PR_utimensat: case PR_futimesat:
	case PR_setxattr: case PR_lsetxattr: case PR_removexattr: case PR_lremovexattr:
		return true;
	default:
		return false;
	}
}

/**
 * Called for each host path PRoot walks through while it translates a
 * guest path: the directory it's in must be listed before PRoot looks
 * at it.  @final tells whether it is the end of the walk.
 */
int dn_fuse_host_path(Tracee *tracee, const char *host_path, bool final)
{
	char dir_rel[PATH_MAX];
	const char *rel;
	char *slash;
	Mount *mount;
	Node *dir;

	(void) final;
	mount = find_mount(host_path);
	if (mount == NULL)
		return 0;
	if (mount->dead)
		return -ENOTCONN;

	rel = host_path + strlen(mount->cache);
	while (*rel == '/')
		rel++;
	if (*rel == '\0')
		return 0;	// The mount point itself is always there

	if (!mount->ready)
		return park(tracee);

	snprintf(dir_rel, sizeof(dir_rel), "%s", rel);
	slash = strrchr(dir_rel, '/');
	if (slash != NULL)
		*slash = '\0';
	else
		dir_rel[0] = '\0';

	dir = find_node(mount, dir_rel);
	if (dir == NULL)
		return 0;	// Not reachable through listed directories
	if (dir->list == LISTED)
		return dir->error;
	if (dir->list == UNLISTED) {
		start_listing(mount, dir);
		flush_packets(mount);
	}
	return park(tracee);
}

/**
 * Called with the final host path of each path the current syscall of
 * @tracee is about to use: refuse changes, list a directory that is
 * opened, fetch a file that is opened or executed.
 */
static int check_access(Tracee *tracee, const char *host_path)
{
	Sysnum sysnum = get_sysnum(tracee, ORIGINAL);
	long flags = open_flags(tracee);

	const char *rel;
	struct stat host;
	Mount *mount;
	Node *node;
	bool exists;

	mount = find_mount(host_path);
	if (mount == NULL)
		return 0;
	if (mount->dead)
		return -ENOTCONN;
	if (!mount->ready)
		return park(tracee);

	rel = host_path + strlen(mount->cache);
	while (*rel == '/')
		rel++;
	node = find_node(mount, rel);
	exists = lstat(host_path, &host) == 0;

	if (is_write_syscall(sysnum))
		return -EROFS;
	if (flags >= 0) {
		if ((flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC) != 0
		    || ((flags & O_CREAT) != 0 && !exists))
			return -EROFS;
		if ((flags & O_PATH) != 0)
			return 0;
	}
	else if (sysnum != PR_execve && sysnum != PR_execveat && sysnum != PR_uselib)
		return 0;

	if (node == NULL || !exists)
		return 0;

	if (S_ISDIR(host.st_mode)) {
		if (node->list == LISTED)
			return node->error;
		if (node->list == UNLISTED) {
			start_listing(mount, node);
			flush_packets(mount);
		}
		return park(tracee);
	}

	if (!S_ISREG(host.st_mode))
		return 0;
	if (node->data == FETCHED)
		return node->error;
	if (node->data == NO_DATA) {
		// READs follow the answer to OPEN, which gives the handle
		start_fetching(mount, node);
		flush_packets(mount);
		if (node->data == FETCHED)
			return node->error;
	}
	return park(tracee);
}

int dn_fuse_translated(Tracee *tracee, const char *host_path)
{
	if (mounts == NULL)
		return 0;
	return check_access(tracee, host_path);
}

/* /dev/fuse */

/**
 * open("/dev/fuse") becomes socket(AF_UNIX, SOCK_SEQPACKET), connected
 * at the exit stage to a socket PRoot listens on (see
 * dn_fuse_exit_end() and dn_fuse_chained_exit()).
 */
int dn_fuse_enter_end(Tracee *tracee)
{
	struct sockaddr_un address;
	char path[PATH_MAX];
	const char *socket_path;
	long flags = open_flags(tracee);
	word_t type;
	int listener;
	Reg reg;

	switch (get_sysnum(tracee, ORIGINAL)) {
	case PR_open:	reg = SYSARG_1; break;
	case PR_openat:
	case PR_openat2: reg = SYSARG_2; break;
	default:
		return 0;
	}
	if (read_path(tracee, path, peek_reg(tracee, CURRENT, reg)) < 0)
		return 0;
	if (strcmp(path, device_path) != 0)
		return 0;

	socket_path = create_temp_name(context, "proot-fuse");
	if (socket_path == NULL || strlen(socket_path) >= sizeof(address.sun_path))
		return -ENODEV;

	listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (listener < 0)
		return -ENODEV;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	strcpy(address.sun_path, socket_path);
	if (bind(listener, (struct sockaddr *) &address, sizeof(address)) < 0
	    || listen(listener, 1) < 0) {
		close(listener);
		return -ENODEV;
	}

	tracee->dn.fuse_listener = listener;
	tracee->dn.fuse_socket = socket_path;
	tracee->dn.fuse_address = alloc_mem(tracee, sizeof(address));
	if (tracee->dn.fuse_address == 0
	    || write_data(tracee, tracee->dn.fuse_address, &address, sizeof(address)) < 0) {
		close(listener);
		unlink(socket_path);
		return -ENODEV;
	}

	type = SOCK_SEQPACKET;
	if ((flags & O_CLOEXEC) != 0)
		type |= SOCK_CLOEXEC;
	if ((flags & O_NONBLOCK) != 0)
		type |= SOCK_NONBLOCK;
	set_sysnum(tracee, PR_socket);
	poke_reg(tracee, SYSARG_1, AF_UNIX);
	poke_reg(tracee, SYSARG_2, type);
	poke_reg(tracee, SYSARG_3, 0);

	tracee->dn.fuse_open = 1;
	tracee->sysexit_pending = true;
	tracee->restart_how = PTRACE_SYSCALL;
	return 0;
}

void dn_fuse_exit_end(Tracee *tracee)
{
	word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);

	if (tracee->dn.fuse_open != 1)
		return;
	if ((long) result < 0) {
		close(tracee->dn.fuse_listener);
		(void) unlink(tracee->dn.fuse_socket);
		tracee->dn.fuse_open = 0;
		return;
	}

	tracee->dn.fuse_open = 2;
	tracee->dn.fuse_fd = (int) result;
	register_chained_syscall(tracee, PR_connect, result, tracee->dn.fuse_address,
				 sizeof(struct sockaddr_un), 0, 0, 0);
	force_chain_final_result(tracee, result);
}

/**
 * The tracee's end is connected: take PRoot's end, it stays a device
 * until a mount(2) names the tracee's end (dn_fuse_mount()).
 */
void dn_fuse_chained_exit(Tracee *tracee)
{
	word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	char path[PATH_MAX];
	Device *device;
	int conn = -1;

	if (tracee->dn.fuse_open != 2)
		return;
	tracee->dn.fuse_open = 0;

	if ((long) result == 0)
		conn = accept4(tracee->dn.fuse_listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	close(tracee->dn.fuse_listener);
	(void) unlink(tracee->dn.fuse_socket);

	if (conn < 0 || dn_fd_path(tracee, tracee->dn.fuse_fd, path) < 0) {
		if (conn >= 0)
			close(conn);
		force_chain_final_result(tracee, (word_t) -ENODEV);
		return;
	}

	device = talloc_zero(context, Device);
	if (device == NULL) {
		close(conn);
		return;
	}
	device->conn = conn;
	device->ino = (ino_t) strtoull(path + strcspn(path, "0123456789"), NULL, 10);
	device->next = devices;
	devices = device;
}

/**
 * mount(2) of a FUSE file-system: @data holds "fd=N", the tracee's
 * /dev/fuse.  Copies into @host_path the directory to bind at the
 * mount point.  Returns -errno on error, otherwise 1.
 */
int dn_fuse_mount(Tracee *tracee, const char *data, char host_path[PATH_MAX])
{
	struct fuse_init_in init;
	char path[PATH_MAX];
	const char *option;
	Device **link;
	Device *device = NULL;
	Mount *mount;
	ino_t ino;
	int fd;

	option = strstr(data, "fd=");
	if (option == NULL)
		return -EINVAL;
	fd = atoi(option + 3);
	if (dn_fd_path(tracee, fd, path) < 0 || strncmp(path, "socket:[", 8) != 0)
		return -EINVAL;
	ino = (ino_t) strtoull(path + 8, NULL, 10);

	for (link = &devices; *link != NULL; link = &(*link)->next) {
		if ((*link)->ino == ino) {
			device = *link;
			*link = device->next;
			break;
		}
	}
	if (device == NULL)
		return -EINVAL;

	mount = talloc_zero(context, Mount);
	if (mount == NULL)
		return -ENOMEM;
	mount->conn = device->conn;
	mount->next_unique = 1;
	mount->nb_buckets = 64;
	mount->nodes = talloc_zero_array(mount, Node *, mount->nb_buckets);
	mount->cache = (char *) create_temp_directory(mount, "proot-fuse");
	talloc_free(device);
	if (mount->nodes == NULL || mount->cache == NULL || add_node(mount, "", FUSE_ROOT_ID, NULL) == NULL) {
		close(mount->conn);
		talloc_free(mount);
		return -ENOMEM;
	}

	memset(&init, 0, sizeof(init));
	init.major = FUSE_KERNEL_VERSION;
	init.minor = PROTO_MINOR;
	init.max_readahead = CHUNK;
	// The 7.31 layout ends with the flags
	send_request(mount, FUSE_INIT, NULL, &init, offsetof(struct fuse_init_in, flags) + sizeof(init.flags), NULL, 0);
	flush_packets(mount);

	mount->next = mounts;
	mounts = mount;

	snprintf(host_path, PATH_MAX, "%s", mount->cache);
	return 1;
}

/**
 * The binding of @host_path is gone (umount(2)): stop the file-system,
 * the daemon sees its /dev/fuse end and quits.
 */
void dn_fuse_unmounted(const char *host_path)
{
	Mount **link;

	for (link = &mounts; *link != NULL; link = &(*link)->next) {
		Mount *mount = *link;

		if (strcmp(mount->cache, host_path) != 0)
			continue;
		kill_mount(mount);
		*link = mount->next;
		talloc_free(mount);	// Removes the copies too
		resume_parked();
		return;
	}
}
