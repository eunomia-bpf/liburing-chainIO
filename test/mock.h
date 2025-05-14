#ifndef IOU_MOCK_H
#define IOU_MOCK_H

#include <linux/types.h>

enum {
	IORING_MOCK_FEAT_COPY_CMD		= 1,
};

struct io_uring_mock_probe {
	__u64		features;
	__u64		__resv[9];
};

struct io_uring_mock_create {
	__u32		out_fd;
	__u32		flags;
	__u64		__resv[15];
};

enum {
	IORING_MOCK_MGR_CMD_PROBE,
	IORING_MOCK_MGR_CMD_CREATE,
};

enum {
	IORING_MOCK_CMD_COPY_REGBUF,
};

enum {
	IORING_MOCK_COPY_FROM			= 1,
};

#endif