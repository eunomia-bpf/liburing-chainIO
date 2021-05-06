#pragma once

#ifndef ARRAY_SIZE
	#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#endif

struct counting_ctx {
	struct __kernel_timespec ts;
};

struct ping_ctx {
	int idx;
};

#define FILL_QD			4
#define FILL_BLOCKS		16
#define FILL_BLOCK_SIZE		(4096 * 4)
#define FILL_FSIZE		(FILL_BLOCKS * FILL_BLOCK_SIZE)
