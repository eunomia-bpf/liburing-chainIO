// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include "bpf/bpf_helpers.h"
#include "liburing/io_uring.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

enum {
	IOU_BPF_OK,
	IOU_BPF_STOP,
};

struct io_uring_bpf_ctx {};

extern int bpf_io_uring_queue_sqe(struct io_uring_bpf_ctx *user_ctx, void *bpf_sqe, int mem__sz) __weak __ksym;
extern int bpf_io_uring_submit_sqes(struct io_uring_bpf_ctx *user_ctx, unsigned int nr) __weak __ksym;
extern int bpf_io_uring_get_cqe(struct io_uring_bpf_ctx *user_ctx, struct io_uring_cqe *res__uninit) __weak __ksym;
extern struct io_uring_cqe *bpf_io_uring_get_cqe2(struct io_uring_bpf_ctx *user_ctx) __weak __ksym;
extern void bpf_io_uring_set_wait_params(struct io_uring_bpf_ctx *user_ctx, unsigned int wait_nr) __weak __ksym;

int reqs_to_run;

SEC("iouring")
int run_test(struct io_uring_bpf_ctx *ctx)
{
	struct io_uring_cqe *cqe;
	int ret;

	cqe = bpf_io_uring_get_cqe2(ctx);
	if (cqe) {
		int left;

		left = --reqs_to_run;
		if (left <= 0) {
			// bpf_printk("stop bpf\n");
			return IOU_BPF_STOP;
		}
	}

	struct io_uring_sqe sqe = {};
	bpf_io_uring_queue_sqe(ctx, &sqe, sizeof(sqe));
	ret = bpf_io_uring_submit_sqes(ctx, 1);
	if (ret != 1) {
		bpf_printk("bpf submit failed %i\n", ret);
		return IOU_BPF_STOP;
	}
	bpf_io_uring_set_wait_params(ctx, 1);
	return 0;
}
