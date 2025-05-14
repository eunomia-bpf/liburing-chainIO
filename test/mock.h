#ifndef IOU_MOCK_H
#define IOU_MOCK_H

#include <linux/types.h>

struct io_uring_mock_create {
	__u32		out_fd;
	__u32		__resv1;
	__u64		__resv2[7];
};

enum {
	IORING_MOCK_MGR_CMD_CREATE,
};

enum {
	IORING_MOCK_CMD_COPY_REGBUF,
};

enum {
	IORING_MOCK_COPY_FROM			= 1,
};

#endif