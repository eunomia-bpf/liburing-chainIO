#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "uring.h"

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
static long (*bpf_copy_to_user)(void *user_ptr, const void *src, __u32 size) = (void *) 167;


struct bpf_map_def SEC("maps") arr = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(unsigned long),
	.max_entries = 256,
};

#define ARR_SLOT 0
#define REENTER_SLOT 10

static void writev(u32 kv, unsigned long v)
{
	unsigned long *val = bpf_map_lookup_elem(&arr, &kv);

	if (val)
		*val = v;
}

static unsigned long readv(u32 kv)
{
	unsigned long *val = bpf_map_lookup_elem(&arr, &kv);

	return val ? *val : -1UL;
}

SEC("iouring.s/")
int test(struct io_uring_bpf_ctx *ctx)
{
	struct io_uring_sqe sqe;
	struct io_uring_cqe cqe = {};
	u32 key = 0;
	long *val;
	int ret, cq_idx = 1;
	unsigned long secret, f1;
	__u32 vvv;
	u64 *uptr;

	/* make sure we don't repeat it twice */
	if (readv(REENTER_SLOT))
		return 0;
	writev(REENTER_SLOT, 1);

	// just write some value
	writev(ARR_SLOT, 11);

	// emit CQE to the main CQ
	iouring_emit_cqe(ctx, 0, 3, 13, 0);

	// emit 2 CQEs to a second CQ and reap them
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

	// write back user_data
	writev(ARR_SLOT + 4, ctx->user_data);

	// demo for reading from userspace
	uptr = (u64 *)(unsigned long)ctx->user_data;
	bpf_copy_from_user(&secret, sizeof(secret), uptr);
	writev(ARR_SLOT + 5, secret);

	// copy to userspace
	secret = 31;
	bpf_copy_to_user(uptr, &secret, sizeof(secret));

	ctx->wait_idx = 0;
	ctx->wait_nr = 1;
	return 0;
}

static inline void io_uring_prep_timeout(struct io_uring_sqe *sqe,
					 struct __kernel_timespec *ts,
					 unsigned count, unsigned flags)
{
	io_uring_prep_rw(IORING_OP_TIMEOUT, sqe, -1, ts, 1, count);
	sqe->timeout_flags = flags;
}

SEC("iouring.s/")
int counting(struct io_uring_bpf_ctx *ctx)
{
	struct counting_ctx *uctx = (void *)(unsigned long)ctx->user_data;
	struct io_uring_sqe sqe;
	struct io_uring_cqe cqe;
	unsigned long v = readv(0);
	unsigned int cq_idx = 1;

	if (v > 10)
		return 0;
	writev(0, v + 1);

	if (v != 0) {
		int ret = iouring_reap_cqe(ctx, cq_idx, &cqe, sizeof(cqe));
		writev(1, ret ? ret : cqe.user_data);
	}

	io_uring_prep_timeout(&sqe, &uctx->ts, 0, 0);
	sqe.user_data = 5;
	sqe.cq_idx = cq_idx;
	iouring_queue_sqe(ctx, &sqe, sizeof(sqe));

	ctx->wait_idx = cq_idx;
	ctx->wait_nr = 1;

	return 0;
}

SEC("iouring.s/")
int pingpong(struct io_uring_bpf_ctx *ctx)
{
	struct ping_ctx *uctx = (void *)(unsigned long)ctx->user_data;
	struct io_uring_sqe sqe;
	struct io_uring_cqe cqe;
	unsigned long v;
	int idx, ret, iter;
	int cq_idx2;

	bpf_copy_from_user(&idx, sizeof(idx), &uctx->idx);
	if (!readv(idx)) {
		writev(idx, 1);
wait:
		ctx->wait_idx = idx + 1;
		ctx->wait_nr = 1;
		return 0;
	}

	ret = iouring_reap_cqe(ctx, idx + 1, &cqe, sizeof(cqe));
	iter = cqe.user_data;
	cq_idx2 = (idx ^ 1) + 1;
	iouring_emit_cqe(ctx, cq_idx2, iter + 1, 0, 0);

	if (iter < 20)
		goto wait;
	writev(5 + idx, iter);
	return 0;
}

static inline void io_uring_prep_write(struct io_uring_sqe *sqe, int fd,
				       const void *buf, unsigned nbytes, off_t offset)
{
	io_uring_prep_rw(IORING_OP_WRITE, sqe, fd, buf, nbytes, offset);
}

#define IOSQE_FIXED_FILE	(1U << IOSQE_FIXED_FILE_BIT)

SEC("iouring.s/")
int write_file(struct io_uring_bpf_ctx *ctx)
{
	const int off_idx = 1, infl_idx = 0;
	struct io_uring_sqe sqe;
	struct io_uring_cqe cqe;
	void *buf = (void *)(unsigned long)ctx->user_data;
	u64 ret, i, inflight = readv(infl_idx);
	u64 cur_off = readv(off_idx);

	for (i = 0; i < FILL_QD; i++) {
		if (inflight) {
			ret = iouring_reap_cqe(ctx, 1, &cqe, sizeof(cqe));
			inflight--;
		}
	}
	for (i = 0; i < FILL_QD; i++) {
		if (inflight >= FILL_QD || cur_off >= FILL_FSIZE)
			break;
		io_uring_prep_write(&sqe, 0, buf, 1, cur_off);
		sqe.flags = IOSQE_FIXED_FILE;
		sqe.cq_idx = 1;
		ret = iouring_queue_sqe(ctx, &sqe, sizeof(sqe));
		inflight++;
		cur_off++;
	}

	writev(off_idx, cur_off);
	writev(infl_idx, inflight);
	ctx->wait_idx = 1;
	ctx->wait_nr = inflight;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
