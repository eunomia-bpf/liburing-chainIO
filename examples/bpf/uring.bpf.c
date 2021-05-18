#include "liburing_bpf.h"
#include "uring.h"

#define MAIN_CQ 0

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

SEC("iouring")
int test(struct io_uring_bpf_ctx *ctx)
{
	struct io_uring_sqe sqe;
	struct io_uring_cqe cqe;
	u32 key = 0;
	long *val;
	int ret, cq_idx = 1;
	unsigned long secret, f1;
	__u32 vvv;
	u64 *uptr;

	/* will be called twice, see CQ waiting at the end */
	if (readv(REENTER_SLOT))
		return 0;
	writev(REENTER_SLOT, 1);

	/* just write some value to a BPF array */
	writev(ARR_SLOT, 11);

	/* emit a new CQE to the main CQ */
	bpf_io_uring_emit_cqe(ctx, MAIN_CQ, 3, 13, 0);

	/* emit 2 CQEs to the second CQ and reap them */
	bpf_io_uring_emit_cqe(ctx, cq_idx, 4, 17, 0);
	bpf_io_uring_emit_cqe(ctx, cq_idx, 5, 19, 0);

	/* reap just submitted CQEs */
	ret = bpf_io_uring_reap_cqe(ctx, cq_idx, &cqe, sizeof(cqe));
	writev(ARR_SLOT + 1, ret ? ret : cqe.user_data);
	ret = bpf_io_uring_reap_cqe(ctx, cq_idx, &cqe, sizeof(cqe));
	writev(ARR_SLOT + 2, ret ? ret : cqe.user_data);

	/* submit a nop request */
	io_uring_prep_nop(&sqe);
	sqe.user_data = 2;
	sqe.flags = 0;
	ret = bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));
	writev(ARR_SLOT + 3, ret < 0 ? ret : 21);

	/* make sure we can read ctx->user_data */
	writev(ARR_SLOT + 4, ctx->user_data);

	/* read userspace memory */
	uptr = (u64 *)(unsigned long)ctx->user_data;
	bpf_copy_from_user(&secret, sizeof(secret), uptr);
	writev(ARR_SLOT + 5, secret);

	/* write to userspace memory */
	secret = 31;
	bpf_copy_to_user(uptr, &secret, sizeof(secret));

	 /* instruct io_uring that the BPF request wants to wait for CQEs */
	ctx->wait_idx = 0;
	ctx->wait_nr = 1;
	return 0;
}

struct bpf_ctx {
	struct __kernel_timespec ts;
};

SEC("iouring")
int counting(struct io_uring_bpf_ctx *ctx)
{
	struct __kernel_timespec *ts = (void *)(unsigned long)ctx->user_data;
	struct io_uring_sqe sqe;
	struct io_uring_cqe cqe;
	unsigned long v = readv(0);
	unsigned int cq_idx = 1;

	if (v > 10)
		return 0;
	writev(0, v + 1);

	if (v != 0) {
		int ret = bpf_io_uring_reap_cqe(ctx, cq_idx, &cqe, sizeof(cqe));
		writev(1, ret ? ret : cqe.user_data);
	}

	io_uring_prep_timeout(&sqe, ts, 0, 0);
	sqe.user_data = 5;
	sqe.cq_idx = cq_idx;
	bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));

	ctx->wait_idx = cq_idx;
	ctx->wait_nr = 1;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
