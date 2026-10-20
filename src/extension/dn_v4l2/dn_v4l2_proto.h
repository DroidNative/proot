/* DroidNative camera passthrough: protocol between PRoot (which emulates
 * the V4L2 capture device) and the host application (which owns the
 * camera).  See docs/device-passthrough.md in the DroidNative tree.
 *
 * Host directory, named by $PROOT_DN_VIDEO_DIR, one set per camera N:
 *   videoN       FIFO, bound into the guest as /dev/videoN.  The host writes
 *                one dn_v4l2_token per captured frame.
 *   videoN.sock  Unix stream socket the host listens on.  On connect it
 *                sends dn_v4l2_hello with the frame memory attached
 *                (SCM_RIGHTS); PRoot then sends dn_v4l2_cmd records.
 *
 * All integers are native endian; both ends run on the same machine.  */
#ifndef DN_V4L2_PROTO_H
#define DN_V4L2_PROTO_H

#include <stdint.h>

#define DN_V4L2_HELLO_MAGIC 0x31564e44u /* "DNV1" */
#define DN_V4L2_TOKEN_MAGIC 0x54564e44u /* "DNVT" */
#define DN_V4L2_MAX_SIZES   16

struct dn_v4l2_hello {
	uint32_t magic;
	uint32_t version;       /* 1 */
	uint32_t shm_size;      /* size of the attached memory */
	uint32_t n_slots;       /* frame slots in it */
	uint32_t slot_size;     /* bytes per slot, largest frame fits */
	uint32_t slot_offset;   /* offset of slot 0 */
	uint32_t n_sizes;
	struct { uint32_t width, height; } sizes[DN_V4L2_MAX_SIZES];
	char name[32];          /* NUL terminated card name */
};

/* First words of the shared memory.  */
struct dn_v4l2_shm {
	uint32_t consumed;      /* frames dequeued by the guest (PRoot writes) */
};

enum { DN_V4L2_CMD_START = 1, DN_V4L2_CMD_STOP = 2 };

struct dn_v4l2_cmd {
	uint32_t cmd;
	uint32_t width, height;
	uint32_t pixelformat;   /* V4L2 fourcc: YUYV or NV12 */
};

struct dn_v4l2_token {
	uint32_t magic;
	uint32_t slot;          /* which slot holds the frame */
	uint32_t bytesused;
	uint32_t sequence;
	uint64_t timestamp_us;  /* CLOCK_MONOTONIC */
};

#endif
