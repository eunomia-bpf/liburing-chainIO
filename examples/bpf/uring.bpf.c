#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

static inline void io_uring_prep_rw(int op, struct io_uring_sqe *sqe, int fd,
				    const void *addr, unsigned len,
				    __u64 offset)
{
	sqe->opcode = op;
	sqe->flags = 0;
	sqe->ioprio = 0;
	sqe->fd = fd;
	sqe->off = offset;
	sqe->addr = (unsigned long) addr;
	sqe->len = len;
	sqe->rw_flags = 0;
	sqe->user_data = 0;
	sqe->__pad2[0] = sqe->__pad2[1] = sqe->__pad2[2] = 0;
}

static inline void io_uring_prep_nop(struct io_uring_sqe *sqe)
{
	io_uring_prep_rw(IORING_OP_NOP, sqe, -1, 0, 0, 0);
}

static long (*iouring_queue_sqe)(void *ctx, struct io_uring_sqe *sqe, u32) = (void *) 164;
static long (*iouring_emit_cqe)(void *ctx, u32 cq, u64 data, u32 res, u32 flags) = (void *) 165;
static long (*iouring_reap_cqe)(void *ctx, u32 cq, struct io_uring_cqe *cqe, u32) = (void *) 166;

struct bpf_map_def SEC("maps") arr = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = 256,
};

#define ARR_SLOT 0

static void writev(u32 kv, long v)
{
	u32 key = kv;
	long *val;

	val = bpf_map_lookup_elem(&arr, &key);
	if (val)
		*val = v;
}

SEC("iouring.s/")
int test(void *ctx, void *b0, int b1, int b2, int b3)
{
	struct io_uring_sqe sqe;
	struct io_uring_cqe cqe = {};
	u32 key = 0;
	long *val;
	int ret, cq_idx = 1;

	// just write some value
	writev(ARR_SLOT, 11);

	// emit CQE to the main CQ
	iouring_emit_cqe(ctx, 0, 3, 13, 0);

	// emit 2 CQEs to a second CQ and reap it
	iouring_emit_cqe(ctx, cq_idx, 4, 17, 0);
	iouring_emit_cqe(ctx, cq_idx, 5, 19, 0);
	ret = iouring_reap_cqe(ctx, cq_idx, &cqe, sizeof(cqe));
	writev(ARR_SLOT + 1, ret ? ret : cqe.user_data);
	ret = iouring_reap_cqe(ctx, cq_idx, &cqe, sizeof(cqe));
	writev(ARR_SLOT + 2, ret ? ret : cqe.user_data);

	// submit nop SQE
	io_uring_prep_nop(&sqe);
	sqe.user_data = 2;
	sqe.flags = 0;
	ret = iouring_queue_sqe(ctx, &sqe, sizeof(sqe));
	writev(ARR_SLOT + 3, ret < 0 ? ret : 21);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
