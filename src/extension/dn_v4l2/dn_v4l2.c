/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * DroidNative: V4L2 capture devices without kernel support.
 *
 * /dev/videoN in the guest is a FIFO owned by the host application.  This
 * extension answers the V4L2 ioctls on it, turns VIDIOC_DQBUF into a read
 * of one frame token from the FIFO (so blocking, O_NONBLOCK, poll and epoll
 * behave as the kernel implements them for pipes) and copies the frame from
 * memory shared with the host into the buffer the tracee queued.  mmap on
 * the device becomes an anonymous mapping that PRoot remembers; stat reports
 * a character device 81:N.  Protocol: dn_v4l2_proto.h.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/un.h>
#include <linux/videodev2.h>

#include "extension/extension.h"
#include "extension/dn_v4l2/dn_v4l2_proto.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/seccomp.h"
#include "tracee/tracee.h"
#include "tracee/abi.h"
#include "tracee/mem.h"
#include "tracee/reg.h"
#include "tracee/statx.h"
#include "cli/note.h"

#define MAX_DEVICES 8
#define MAX_BUFFERS 8
#define V4L2_MAJOR  81
/* mmap offset of buffer i, as reported by VIDIOC_QUERYBUF */
#define BUFFER_OFFSET_SHIFT 24

/* The stat structure of the native ABI's stat syscalls.  */
#if defined(__LP64__)
typedef struct stat native_stat;
#else
typedef struct stat64 native_stat;
#endif

struct buffer {
	word_t addr;    /* in the tracee, 0 until mapped or queued (userptr) */
	word_t length;
	bool queued;
};

struct device {
	int index;                 /* N of videoN */
	dev_t st_dev;
	ino_t st_ino;
	char fifo[PATH_MAX];
	char sock_path[PATH_MAX];

	int sock;                  /* -1 until connected */
	struct dn_v4l2_hello hello;
	uint8_t *shm;

	uint32_t width, height, pixelformat;
	uint32_t memory;           /* V4L2_MEMORY_MMAP or _USERPTR */
	unsigned int nbuffers;
	struct buffer buffers[MAX_BUFFERS];
	bool streaming;
};

static struct device devices[MAX_DEVICES];
static int ndevices;

static const struct {
	uint32_t fourcc;
	const char *description;
} formats[] = {
	{ V4L2_PIX_FMT_YUYV, "YUYV 4:2:2" },
	{ V4L2_PIX_FMT_NV12, "Y/UV 4:2:0" },
};
#define NFORMATS (sizeof(formats) / sizeof(formats[0]))

/* Device lookup */

static void scan_devices(const char *dir)
{
	struct dirent *entry;
	DIR *d = opendir(dir);
	if (d == NULL)
		return;

	while ((entry = readdir(d)) != NULL && ndevices < MAX_DEVICES) {
		struct device *dev = &devices[ndevices];
		struct stat st;
		char *end;
		long n;

		if (strncmp(entry->d_name, "video", 5) != 0 || entry->d_name[5] == '\0')
			continue;
		n = strtol(entry->d_name + 5, &end, 10);
		if (*end != '\0' || n < 0 || n > 255)
			continue;

		memset(dev, 0, sizeof(*dev));
		snprintf(dev->fifo, sizeof(dev->fifo), "%s/%s", dir, entry->d_name);
		snprintf(dev->sock_path, sizeof(dev->sock_path), "%s/%s.sock", dir, entry->d_name);
		if (stat(dev->fifo, &st) < 0 || !S_ISFIFO(st.st_mode))
			continue;

		dev->index = n;
		dev->st_dev = st.st_dev;
		dev->st_ino = st.st_ino;
		dev->sock = -1;
		ndevices++;
	}
	closedir(d);
}

static struct device *find_device(dev_t st_dev, ino_t st_ino)
{
	int i;
	for (i = 0; i < ndevices; i++) {
		if (devices[i].st_ino == st_ino && devices[i].st_dev == st_dev)
			return &devices[i];
	}
	return NULL;
}

/* The device behind a descriptor of the tracee, or NULL.  */
static struct device *device_of_fd(const Tracee *tracee, int fd)
{
	char path[64];
	struct stat st;

	if (fd < 0)
		return NULL;
	snprintf(path, sizeof(path), "/proc/%d/fd/%d", tracee->pid, fd);
	if (stat(path, &st) < 0 || !S_ISFIFO(st.st_mode))
		return NULL;
	return find_device(st.st_dev, st.st_ino);
}

/* Connection to the host */

static void disconnect(struct device *dev)
{
	if (dev->shm != NULL)
		munmap(dev->shm, dev->hello.shm_size);
	if (dev->sock >= 0)
		close(dev->sock);
	dev->shm = NULL;
	dev->sock = -1;
}

static int connect_host(struct device *dev)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct timeval timeout = { .tv_sec = 2 };
	char control[CMSG_SPACE(sizeof(int))];
	struct iovec iov = { .iov_base = &dev->hello, .iov_len = sizeof(dev->hello) };
	struct msghdr msg = {
		.msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = control, .msg_controllen = sizeof(control),
	};
	struct cmsghdr *cmsg;
	int fd = -1;
	ssize_t n;
	unsigned int i;

	if (dev->sock >= 0)
		return 0;
	if (strlen(dev->sock_path) >= sizeof(addr.sun_path))
		return -ENAMETOOLONG;
	strcpy(addr.sun_path, dev->sock_path);

	dev->sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (dev->sock < 0)
		return -ENODEV;
	/* Never let a stuck host application stall every tracee.  */
	setsockopt(dev->sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	setsockopt(dev->sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	if (connect(dev->sock, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		goto fail;

	n = recvmsg(dev->sock, &msg, MSG_CMSG_CLOEXEC | MSG_WAITALL);
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
			memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	}
	if (n != sizeof(dev->hello) || fd < 0
	    || dev->hello.magic != DN_V4L2_HELLO_MAGIC || dev->hello.version != 1
	    || dev->hello.n_sizes == 0 || dev->hello.n_sizes > DN_V4L2_MAX_SIZES
	    || dev->hello.n_slots == 0 || dev->hello.slot_size == 0
	    || (uint64_t) dev->hello.slot_offset
	       + (uint64_t) dev->hello.n_slots * dev->hello.slot_size > dev->hello.shm_size) {
		if (fd >= 0)
			close(fd);
		goto fail;
	}
	dev->hello.name[sizeof(dev->hello.name) - 1] = '\0';

	dev->shm = mmap(NULL, dev->hello.shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (dev->shm == MAP_FAILED) {
		dev->shm = NULL;
		goto fail;
	}

	/* Default format: 640x480 when the camera has it, else its first size.  */
	if (dev->width == 0) {
		dev->width = dev->hello.sizes[0].width;
		dev->height = dev->hello.sizes[0].height;
		for (i = 0; i < dev->hello.n_sizes; i++) {
			if (dev->hello.sizes[i].width == 640 && dev->hello.sizes[i].height == 480) {
				dev->width = 640;
				dev->height = 480;
			}
		}
		dev->pixelformat = V4L2_PIX_FMT_YUYV;
	}
	return 0;

fail:
	disconnect(dev);
	return -ENODEV;
}

static int send_command(struct device *dev, uint32_t cmd)
{
	struct dn_v4l2_cmd msg = {
		.cmd = cmd, .width = dev->width, .height = dev->height,
		.pixelformat = dev->pixelformat,
	};
	if (dev->sock < 0)
		return -ENODEV;
	if (send(dev->sock, &msg, sizeof(msg), MSG_NOSIGNAL) != sizeof(msg)) {
		/* The host application went away; a later ioctl reconnects.  */
		disconnect(dev);
		return -ENODEV;
	}
	return 0;
}

static void stop_streaming(struct device *dev)
{
	unsigned int i;
	if (dev->streaming)
		(void) send_command(dev, DN_V4L2_CMD_STOP);
	dev->streaming = false;
	for (i = 0; i < MAX_BUFFERS; i++)
		dev->buffers[i].queued = false;
}

/* Tokens of an earlier stream must not be taken for frames of this one.  */
static void drain_fifo(const struct device *dev)
{
	char scratch[256];
	int fd = open(dev->fifo, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return;
	while (read(fd, scratch, sizeof(scratch)) > 0)
		;
	close(fd);
}

/* Formats */

static uint32_t bytes_per_line(uint32_t fourcc, uint32_t width)
{
	return fourcc == V4L2_PIX_FMT_YUYV ? width * 2 : width;
}

static uint32_t size_image(uint32_t fourcc, uint32_t width, uint32_t height)
{
	return fourcc == V4L2_PIX_FMT_YUYV ? width * height * 2 : width * height * 3 / 2;
}

static bool known_format(uint32_t fourcc)
{
	unsigned int i;
	for (i = 0; i < NFORMATS; i++) {
		if (formats[i].fourcc == fourcc)
			return true;
	}
	return false;
}

/* Rounds the request to what the device delivers.  */
static void fit_format(const struct device *dev, struct v4l2_pix_format *pix)
{
	uint64_t best = UINT64_MAX;
	uint32_t width = pix->width, height = pix->height;
	unsigned int i;

	if (!known_format(pix->pixelformat))
		pix->pixelformat = V4L2_PIX_FMT_YUYV;
	for (i = 0; i < dev->hello.n_sizes; i++) {
		int64_t dw = (int64_t) dev->hello.sizes[i].width - width;
		int64_t dh = (int64_t) dev->hello.sizes[i].height - height;
		uint64_t distance = (uint64_t) (dw * dw + dh * dh);
		if (distance < best) {
			best = distance;
			pix->width = dev->hello.sizes[i].width;
			pix->height = dev->hello.sizes[i].height;
		}
	}
	pix->field = V4L2_FIELD_NONE;
	pix->bytesperline = bytes_per_line(pix->pixelformat, pix->width);
	pix->sizeimage = size_image(pix->pixelformat, pix->width, pix->height);
	/* Android's YUV_420_888 is full range BT.601, like JFIF.  */
	pix->colorspace = V4L2_COLORSPACE_JPEG;
	pix->priv = 0;
	pix->flags = 0;
	pix->ycbcr_enc = V4L2_YCBCR_ENC_DEFAULT;
	pix->quantization = V4L2_QUANTIZATION_DEFAULT;
	pix->xfer_func = V4L2_XFER_FUNC_DEFAULT;
}

static void fill_buffer(const struct device *dev, struct v4l2_buffer *buf, unsigned int index)
{
	const struct buffer *b = &dev->buffers[index];

	buf->index = index;
	buf->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	buf->memory = dev->memory;
	buf->field = V4L2_FIELD_NONE;
	buf->flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
	if (b->queued)
		buf->flags |= V4L2_BUF_FLAG_QUEUED;
	if (dev->memory == V4L2_MEMORY_MMAP) {
		if (b->addr != 0)
			buf->flags |= V4L2_BUF_FLAG_MAPPED;
		buf->m.offset = index << BUFFER_OFFSET_SHIFT;
		buf->length = size_image(dev->pixelformat, dev->width, dev->height);
	} else {
		buf->m.userptr = b->addr;
		buf->length = b->addr != 0 ? b->length
			: size_image(dev->pixelformat, dev->width, dev->height);
	}
}

/* ioctl */

#define READ_ARG(var)  do { if (read_data(tracee, &(var), arg, sizeof(var)) < 0) return -EFAULT; } while (0)
#define WRITE_ARG(var) do { if (write_data(tracee, arg, &(var), sizeof(var)) < 0) return -EFAULT; } while (0)

/* Answers one V4L2 request; VIDIOC_DQBUF is handled by the caller.  */
static int emulate_ioctl(Tracee *tracee, struct device *dev, word_t request, word_t arg)
{
	switch (request) {
	case VIDIOC_QUERYCAP: {
		struct v4l2_capability cap;
		memset(&cap, 0, sizeof(cap));
		strcpy((char *) cap.driver, "droidnative");
		snprintf((char *) cap.card, sizeof(cap.card), "%s", dev->hello.name);
		snprintf((char *) cap.bus_info, sizeof(cap.bus_info), "platform:droidnative-%d", dev->index);
		cap.version = (6 << 16) | (1 << 8);
		cap.device_caps = V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_STREAMING;
		cap.capabilities = cap.device_caps | V4L2_CAP_DEVICE_CAPS;
		WRITE_ARG(cap);
		return 0;
	}

	case VIDIOC_ENUM_FMT: {
		struct v4l2_fmtdesc desc;
		uint32_t index;
		READ_ARG(desc);
		index = desc.index;
		if (desc.type != V4L2_BUF_TYPE_VIDEO_CAPTURE || index >= NFORMATS)
			return -EINVAL;
		memset(&desc, 0, sizeof(desc));
		desc.index = index;
		desc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		desc.pixelformat = formats[index].fourcc;
		strcpy((char *) desc.description, formats[index].description);
		WRITE_ARG(desc);
		return 0;
	}

	case VIDIOC_ENUM_FRAMESIZES: {
		struct v4l2_frmsizeenum size;
		READ_ARG(size);
		if (!known_format(size.pixel_format) || size.index >= dev->hello.n_sizes)
			return -EINVAL;
		size.type = V4L2_FRMSIZE_TYPE_DISCRETE;
		size.discrete.width = dev->hello.sizes[size.index].width;
		size.discrete.height = dev->hello.sizes[size.index].height;
		WRITE_ARG(size);
		return 0;
	}

	case VIDIOC_ENUM_FRAMEINTERVALS: {
		struct v4l2_frmivalenum ival;
		READ_ARG(ival);
		if (!known_format(ival.pixel_format) || ival.index != 0)
			return -EINVAL;
		ival.type = V4L2_FRMIVAL_TYPE_DISCRETE;
		ival.discrete.numerator = 1;
		ival.discrete.denominator = 30;
		WRITE_ARG(ival);
		return 0;
	}

	case VIDIOC_G_FMT:
	case VIDIOC_S_FMT:
	case VIDIOC_TRY_FMT: {
		struct v4l2_format fmt;
		READ_ARG(fmt);
		if (fmt.type != V4L2_BUF_TYPE_VIDEO_CAPTURE)
			return -EINVAL;
		if (request == VIDIOC_G_FMT) {
			memset(&fmt.fmt, 0, sizeof(fmt.fmt));
			fmt.fmt.pix.width = dev->width;
			fmt.fmt.pix.height = dev->height;
			fmt.fmt.pix.pixelformat = dev->pixelformat;
		}
		fit_format(dev, &fmt.fmt.pix);
		if (request == VIDIOC_S_FMT) {
			/* A client that went away without STREAMOFF cannot
			 * be told apart from a live one: the newest request
			 * wins instead of EBUSY.  */
			stop_streaming(dev);
			dev->width = fmt.fmt.pix.width;
			dev->height = fmt.fmt.pix.height;
			dev->pixelformat = fmt.fmt.pix.pixelformat;
		}
		WRITE_ARG(fmt);
		return 0;
	}

	case VIDIOC_G_PARM:
	case VIDIOC_S_PARM: {
		struct v4l2_streamparm parm;
		READ_ARG(parm);
		if (parm.type != V4L2_BUF_TYPE_VIDEO_CAPTURE)
			return -EINVAL;
		memset(&parm.parm, 0, sizeof(parm.parm));
		parm.parm.capture.capability = V4L2_CAP_TIMEPERFRAME;
		parm.parm.capture.timeperframe.numerator = 1;
		parm.parm.capture.timeperframe.denominator = 30;
		parm.parm.capture.readbuffers = 2;
		WRITE_ARG(parm);
		return 0;
	}

	case VIDIOC_ENUMINPUT: {
		struct v4l2_input input;
		READ_ARG(input);
		if (input.index != 0)
			return -EINVAL;
		memset(&input, 0, sizeof(input));
		strcpy((char *) input.name, "Camera");
		input.type = V4L2_INPUT_TYPE_CAMERA;
		WRITE_ARG(input);
		return 0;
	}

	case VIDIOC_G_INPUT: {
		int input = 0;
		WRITE_ARG(input);
		return 0;
	}

	case VIDIOC_S_INPUT: {
		int input;
		READ_ARG(input);
		return input == 0 ? 0 : -EINVAL;
	}

	case VIDIOC_G_PRIORITY: {
		uint32_t priority = V4L2_PRIORITY_DEFAULT;
		WRITE_ARG(priority);
		return 0;
	}

	case VIDIOC_S_PRIORITY:
		return 0;

	case VIDIOC_REQBUFS: {
		struct v4l2_requestbuffers req;
		READ_ARG(req);
		if (req.type != V4L2_BUF_TYPE_VIDEO_CAPTURE
		    || (req.memory != V4L2_MEMORY_MMAP && req.memory != V4L2_MEMORY_USERPTR))
			return -EINVAL;
		stop_streaming(dev);
		memset(dev->buffers, 0, sizeof(dev->buffers));
		if (req.count > MAX_BUFFERS)
			req.count = MAX_BUFFERS;
		dev->nbuffers = req.count;
		dev->memory = req.memory;
		req.capabilities = 0;
		WRITE_ARG(req);
		return 0;
	}

	case VIDIOC_QUERYBUF: {
		struct v4l2_buffer buf;
		uint32_t index;
		READ_ARG(buf);
		index = buf.index;
		if (buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE || index >= dev->nbuffers)
			return -EINVAL;
		memset(&buf, 0, sizeof(buf));
		fill_buffer(dev, &buf, index);
		WRITE_ARG(buf);
		return 0;
	}

	case VIDIOC_QBUF: {
		struct v4l2_buffer buf;
		READ_ARG(buf);
		if (buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE || buf.index >= dev->nbuffers
		    || buf.memory != dev->memory)
			return -EINVAL;
		if (dev->memory == V4L2_MEMORY_USERPTR) {
			if (buf.m.userptr == 0
			    || buf.length < size_image(dev->pixelformat, dev->width, dev->height))
				return -EINVAL;
			dev->buffers[buf.index].addr = buf.m.userptr;
			dev->buffers[buf.index].length = buf.length;
		}
		dev->buffers[buf.index].queued = true;
		fill_buffer(dev, &buf, buf.index);
		WRITE_ARG(buf);
		return 0;
	}

	case VIDIOC_STREAMON: {
		int type, status;
		READ_ARG(type);
		if (type != V4L2_BUF_TYPE_VIDEO_CAPTURE || dev->nbuffers == 0)
			return -EINVAL;
		if (dev->streaming)
			return 0;
		drain_fifo(dev);
		((struct dn_v4l2_shm *) dev->shm)->consumed = 0;
		status = send_command(dev, DN_V4L2_CMD_START);
		if (status < 0)
			return status;
		dev->streaming = true;
		return 0;
	}

	case VIDIOC_STREAMOFF: {
		int type;
		READ_ARG(type);
		if (type != V4L2_BUF_TYPE_VIDEO_CAPTURE)
			return -EINVAL;
		stop_streaming(dev);
		return 0;
	}

	default:
		/* No controls, standards, crop or events.  */
		return -ENOTTY;
	}
}

static int handle_ioctl_enter(Tracee *tracee)
{
	word_t request = peek_reg(tracee, CURRENT, SYSARG_2);
	word_t arg = peek_reg(tracee, CURRENT, SYSARG_3);
	struct device *dev;
	unsigned int i;
	int status;

	if (_IOC_TYPE(request) != 'V' || is_32on64_mode(tracee))
		return 0;
	dev = device_of_fd(tracee, (int) peek_reg(tracee, CURRENT, SYSARG_1));
	if (dev == NULL)
		return 0;

	status = connect_host(dev);
	if (status < 0)
		return status;

	if (request == VIDIOC_DQBUF) {
		struct v4l2_buffer buf;
		if (read_data(tracee, &buf, arg, sizeof(buf)) < 0)
			return -EFAULT;
		if (buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE || !dev->streaming)
			return -EINVAL;
		for (i = 0; i < dev->nbuffers && !dev->buffers[i].queued; i++)
			;
		if (i == dev->nbuffers)
			return -EINVAL;

		/* Wait for a frame the way the tracee asked for: read the
		 * token into its v4l2_buffer, which is larger and rewritten
		 * at the exit stage anyway.  */
		set_sysnum(tracee, PR_read);
		poke_reg(tracee, SYSARG_2, arg);
		poke_reg(tracee, SYSARG_3, sizeof(struct dn_v4l2_token));
		tracee->sysexit_pending = true;
		tracee->restart_how = PTRACE_SYSCALL;
		return 1;
	}

	status = emulate_ioctl(tracee, dev, request, arg);
	if (status < 0)
		return status;
	poke_reg(tracee, SYSARG_RESULT, 0);
	set_sysnum(tracee, PR_void);
	return 1;
}

/* Exit stage of VIDIOC_DQBUF: the read of the token has returned.  */
static int handle_dqbuf_exit(Tracee *tracee)
{
	word_t arg = peek_reg(tracee, ORIGINAL, SYSARG_3);
	int result = (int) peek_reg(tracee, CURRENT, SYSARG_RESULT);
	struct dn_v4l2_token token;
	struct v4l2_buffer buf;
	struct device *dev;
	struct buffer *b;
	unsigned int index;
	word_t size;

	if (result < 0)
		return 0;       /* EAGAIN, EINTR: as reported by the kernel */

	dev = device_of_fd(tracee, (int) peek_reg(tracee, ORIGINAL, SYSARG_1));
	if (dev == NULL || dev->shm == NULL || result != sizeof(token)
	    || read_data(tracee, &token, arg, sizeof(token)) < 0
	    || token.magic != DN_V4L2_TOKEN_MAGIC || token.slot >= dev->hello.n_slots
	    || token.bytesused > dev->hello.slot_size)
		return -EIO;

	((struct dn_v4l2_shm *) dev->shm)->consumed++;

	for (index = 0; index < dev->nbuffers && !dev->buffers[index].queued; index++)
		;
	if (index == dev->nbuffers)
		return -EINVAL;   /* STREAMOFF from another thread meanwhile */
	b = &dev->buffers[index];

	size = token.bytesused;
	if (dev->memory == V4L2_MEMORY_MMAP) {
		word_t length = size_image(dev->pixelformat, dev->width, dev->height);
		if (size > length)
			size = length;
	} else if (size > b->length) {
		size = b->length;
	}
	if (b->addr == 0
	    || write_data(tracee, b->addr,
			  dev->shm + dev->hello.slot_offset
			  + (size_t) token.slot * dev->hello.slot_size, size) < 0)
		return -EFAULT;

	b->queued = false;
	memset(&buf, 0, sizeof(buf));
	fill_buffer(dev, &buf, index);
	buf.bytesused = size;
	buf.sequence = token.sequence;
	buf.timestamp.tv_sec = token.timestamp_us / 1000000;
	buf.timestamp.tv_usec = token.timestamp_us % 1000000;
	if (write_data(tracee, arg, &buf, sizeof(buf)) < 0)
		return -EFAULT;

	poke_reg(tracee, SYSARG_RESULT, 0);
	return 0;
}

/* mmap */

static bool is_mmap(Sysnum sysnum)
{
	return sysnum == PR_mmap || sysnum == PR_mmap2;
}

/* Byte offset of an mmap request: mmap2 counts in 4096 byte units.  */
static uint64_t mmap_offset(const Tracee *tracee, RegVersion version)
{
	uint64_t offset = peek_reg(tracee, version, SYSARG_6);
	return get_sysnum(tracee, ORIGINAL) == PR_mmap2 ? offset * 4096 : offset;
}

static int handle_mmap_enter(Tracee *tracee)
{
	word_t flags = peek_reg(tracee, CURRENT, SYSARG_4);
	struct device *dev;
	uint64_t index;

	if ((flags & MAP_ANONYMOUS) != 0 || is_32on64_mode(tracee))
		return 0;
	dev = device_of_fd(tracee, (int) peek_reg(tracee, CURRENT, SYSARG_5));
	if (dev == NULL)
		return 0;

	index = mmap_offset(tracee, CURRENT) >> BUFFER_OFFSET_SHIFT;
	if (dev->memory != V4L2_MEMORY_MMAP || index >= dev->nbuffers)
		return -EINVAL;

	/* Plain memory of the tracee; frames are copied into it at DQBUF.  */
	poke_reg(tracee, SYSARG_4, flags | MAP_ANONYMOUS);
	poke_reg(tracee, SYSARG_5, (word_t) -1);
	poke_reg(tracee, SYSARG_6, 0);
	tracee->sysexit_pending = true;
	tracee->restart_how = PTRACE_SYSCALL;
	return 0;
}

static void handle_mmap_exit(Tracee *tracee)
{
	word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	struct device *dev;
	uint64_t index;

	/* Only the requests rewritten above: those lost their descriptor.  */
	if ((peek_reg(tracee, ORIGINAL, SYSARG_4) & MAP_ANONYMOUS) != 0
	    || (peek_reg(tracee, MODIFIED, SYSARG_4) & MAP_ANONYMOUS) == 0
	    || ((long) result < 0 && (long) result > -4096))
		return;
	dev = device_of_fd(tracee, (int) peek_reg(tracee, ORIGINAL, SYSARG_5));
	if (dev == NULL)
		return;
	index = mmap_offset(tracee, ORIGINAL) >> BUFFER_OFFSET_SHIFT;
	if (index >= dev->nbuffers)
		return;
	dev->buffers[index].addr = result;
	dev->buffers[index].length = peek_reg(tracee, ORIGINAL, SYSARG_2);
}

/* stat: the FIFO is presented as character device 81:N */

static void handle_stat_exit(Tracee *tracee, Reg stat_reg)
{
	word_t address = peek_reg(tracee, ORIGINAL, stat_reg);
	const struct device *dev;
	native_stat st;

	if ((int) peek_reg(tracee, CURRENT, SYSARG_RESULT) != 0 || is_32on64_mode(tracee)
	    || read_data(tracee, &st, address, sizeof(st)) < 0 || !S_ISFIFO(st.st_mode))
		return;
	dev = find_device(st.st_dev, st.st_ino);
	if (dev == NULL)
		return;
	st.st_mode = (st.st_mode & ~S_IFMT) | S_IFCHR;
	st.st_rdev = makedev(V4L2_MAJOR, dev->index);
	(void) write_data(tracee, address, &st, sizeof(st));
}

static void handle_statx(struct statx_syscall_state *state)
{
	const struct device *dev;

	if (!S_ISFIFO(state->statx_buf.stx_mode))
		return;
	dev = find_device(makedev(state->statx_buf.stx_dev_major, state->statx_buf.stx_dev_minor),
			  state->statx_buf.stx_ino);
	if (dev == NULL)
		return;
	state->statx_buf.stx_mode = (state->statx_buf.stx_mode & ~S_IFMT) | S_IFCHR;
	state->statx_buf.stx_rdev_major = V4L2_MAJOR;
	state->statx_buf.stx_rdev_minor = dev->index;
	state->updated_stats = true;
}

/* Extension entry point; "data1" of INITIALIZATION is the device directory.  */

static FilteredSysnum filtered_sysnums[] = {
	{ PR_ioctl,		FILTER_SYSEXIT },
	{ PR_mmap,		0 },
	{ PR_mmap2,		0 },
	{ PR_fstat,		FILTER_SYSEXIT },
	{ PR_fstat64,		FILTER_SYSEXIT },
	{ PR_fstatat64,		FILTER_SYSEXIT },
	{ PR_newfstatat,	FILTER_SYSEXIT },
	{ PR_stat,		FILTER_SYSEXIT },
	{ PR_stat64,		FILTER_SYSEXIT },
	{ PR_lstat,		FILTER_SYSEXIT },
	{ PR_lstat64,		FILTER_SYSEXIT },
	FILTERED_SYSNUM_END,
};

int dn_v4l2_callback(Extension *extension, ExtensionEvent event, intptr_t data1, intptr_t data2 UNUSED)
{
	Tracee *tracee;

	switch (event) {
	case INITIALIZATION:
		if (ndevices == 0)
			scan_devices((const char *) data1);
		if (ndevices == 0)
			return -1;
		extension->filtered_sysnums = filtered_sysnums;
		return 0;

	case INHERIT_PARENT:
		return 0;       /* shared: the device state is global */

	case SYSCALL_ENTER_START:
		tracee = TRACEE(extension);
		if (get_sysnum(tracee, CURRENT) == PR_ioctl)
			return handle_ioctl_enter(tracee);
		return 0;

	case SYSCALL_ENTER_END:
		/* After PRoot's own handling, which does not touch mmap.  */
		tracee = TRACEE(extension);
		if ((int) data1 >= 0 && is_mmap(get_sysnum(tracee, CURRENT)))
			return handle_mmap_enter(tracee);
		return 0;

	case SYSCALL_EXIT_END:
		tracee = TRACEE(extension);
		switch (get_sysnum(tracee, ORIGINAL)) {
		case PR_ioctl:
			if (peek_reg(tracee, ORIGINAL, SYSARG_2) == VIDIOC_DQBUF
			    && get_sysnum(tracee, MODIFIED) == PR_read)
				return handle_dqbuf_exit(tracee);
			return 0;
		case PR_mmap:
		case PR_mmap2:
			handle_mmap_exit(tracee);
			return 0;
		case PR_fstat:
		case PR_fstat64:
		case PR_stat:
		case PR_stat64:
		case PR_lstat:
		case PR_lstat64:
			handle_stat_exit(tracee, SYSARG_2);
			return 0;
		case PR_fstatat64:
		case PR_newfstatat:
			handle_stat_exit(tracee, SYSARG_3);
			return 0;
		default:
			return 0;
		}

	case STATX_SYSCALL:
		handle_statx((struct statx_syscall_state *) data1);
		return 0;

	default:
		return 0;
	}
}
