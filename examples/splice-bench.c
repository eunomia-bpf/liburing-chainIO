/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <pthread.h>

#include "liburing.h"

#define MAX_INFLIGHT 128
#define LINK_BIT 0xf000

static unsigned long gettimeofday_ms(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

struct op {
	int idx;
	int buf_idx;
	int io_fd;
	int io_idx;
	int pipe[2];
	int pipe_idx[2];
};

struct ctx {
	struct io_uring ring;
	int nr_ops;
	struct op *ops;
	bool fixed_files;

	unsigned long stat_nr_reqs;
	int io_len;
};

static void iterate_buf_get(struct ctx *ctx, bool do_nop)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	unsigned long head;
	int i, ret;

	for (i = 0; i < ctx->nr_ops; i++) {
		struct op *op = &ctx->ops[i];

		sqe = io_uring_get_sqe(&ctx->ring);
		io_uring_prep_nop(sqe);
		sqe->opcode = IORING_OP_GET_BUF;
		sqe->off = 0;
		sqe->buf_index = op->idx;
		sqe->user_data = op->idx;
		sqe->len = ctx->io_len;
		sqe->fd = op->io_fd;
		if (ctx->fixed_files) {
			sqe->fd = op->io_idx;
			sqe->flags |= IOSQE_FIXED_FILE;
		}
	}

	ret = io_uring_submit_and_wait(&ctx->ring, ctx->nr_ops);
	assert(ret == ctx->nr_ops);

	i = 0;
	io_uring_for_each_cqe(&ctx->ring, head, cqe) {
		if (cqe->res != ctx->io_len) {
			fprintf(stderr, "unexpected splice res %i\n", cqe->res);
			exit(1);
		}
		i++;
	}
	assert(i == ctx->nr_ops);
	io_uring_cq_advance(&ctx->ring, i);

	for (i = 0; i < ctx->nr_ops; i++) {
		struct op *op = &ctx->ops[i];

		sqe = io_uring_get_sqe(&ctx->ring);
		io_uring_prep_write_fixed(sqe, op->io_fd, NULL, ctx->io_len,
					  0, op->idx);
		if (ctx->fixed_files) {
			sqe->fd = op->io_idx;
			sqe->flags |= IOSQE_FIXED_FILE;
		}
		sqe->user_data = op->idx;
	}
	ret = io_uring_submit_and_wait(&ctx->ring, ctx->nr_ops);
	assert(ret == ctx->nr_ops);

	i = 0;
	io_uring_for_each_cqe(&ctx->ring, head, cqe) {
		if (cqe->res != ctx->io_len) {
			fprintf(stderr, "unexpected write res %i, idx %i\n",
					 cqe->res, i);
			exit(1);
		}
		i++;
	}
	assert(i == ctx->nr_ops);
	io_uring_cq_advance(&ctx->ring, i);
	ctx->stat_nr_reqs += i;

	if (do_nop) {
		for (i = 0; i < ctx->nr_ops; i++) {
			struct op *op = &ctx->ops[i];

			sqe = io_uring_get_sqe(&ctx->ring);
			io_uring_prep_nop(sqe);
			sqe->user_data = op->idx;
		}
		ret = io_uring_submit_and_wait(&ctx->ring, ctx->nr_ops);
		assert(ret == ctx->nr_ops);

		i = 0;
		io_uring_for_each_cqe(&ctx->ring, head, cqe)
			i++;
		assert(i == ctx->nr_ops);
		io_uring_cq_advance(&ctx->ring, i);
	}
}

static void iterate_buf_get_link(struct ctx *ctx)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	unsigned long head;
	int i, ret;

	for (i = 0; i < ctx->nr_ops; i++) {
		struct op *op = &ctx->ops[i];

		sqe = io_uring_get_sqe(&ctx->ring);
		io_uring_prep_nop(sqe);
		sqe->opcode = IORING_OP_GET_BUF;
		sqe->off = 0;
		sqe->buf_index = op->idx;
		sqe->user_data = op->idx | LINK_BIT;
		sqe->len = ctx->io_len;
		sqe->fd = op->io_fd;
		sqe->flags = IOSQE_IO_LINK | IOSQE_CQE_SKIP_SUCCESS;
		if (ctx->fixed_files) {
			sqe->fd = op->io_idx;
			sqe->flags |= IOSQE_FIXED_FILE;
		}

		sqe = io_uring_get_sqe(&ctx->ring);
		io_uring_prep_write_fixed(sqe, op->io_fd, NULL, ctx->io_len,
					  0, op->idx);
		if (ctx->fixed_files) {
			sqe->fd = op->io_idx;
			sqe->flags |= IOSQE_FIXED_FILE;
		}
		sqe->user_data = op->idx;
	}

	ret = io_uring_submit_and_wait(&ctx->ring, ctx->nr_ops);
	assert(ret == 2 * ctx->nr_ops);

	i = 0;
	io_uring_for_each_cqe(&ctx->ring, head, cqe) {
		if (cqe->user_data >= ctx->nr_ops) {
			fprintf(stderr, "user_data\n");
			exit(1);
		}
		if (cqe->res != ctx->io_len) {
			fprintf(stderr, "unexpected splice res %i\n", cqe->res);
			exit(1);
		}
		i++;
	}
	assert(i == ctx->nr_ops);
	io_uring_cq_advance(&ctx->ring, i);
	ctx->stat_nr_reqs += i;
}

static void iterate_iou_splice(struct ctx *ctx)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	unsigned long head;
	int i, ret;

	for (i = 0; i < ctx->nr_ops; i++) {
		struct op *op = &ctx->ops[i];

		sqe = io_uring_get_sqe(&ctx->ring);
		if (ctx->fixed_files) {
			io_uring_prep_splice(sqe, op->io_idx, -1, op->pipe_idx[1], -1,
					     ctx->io_len, SPLICE_F_FD_IN_FIXED);
			sqe->flags |= IOSQE_FIXED_FILE;
		} else {
			io_uring_prep_splice(sqe, op->io_fd, -1, op->pipe[1], -1,
					     ctx->io_len, 0);
		}
		sqe->user_data = op->idx;
	}

	ret = io_uring_submit_and_wait(&ctx->ring, ctx->nr_ops);
	assert(ret == ctx->nr_ops);

	i = 0;
	io_uring_for_each_cqe(&ctx->ring, head, cqe) {
		if (cqe->res != ctx->io_len) {
			fprintf(stderr, "unexpected splice res %i\n", cqe->res);
			exit(1);
		}
		i++;
	}
	assert(i == ctx->nr_ops);
	io_uring_cq_advance(&ctx->ring, i);

	for (i = 0; i < ctx->nr_ops; i++) {
		struct op *op = &ctx->ops[i];

		sqe = io_uring_get_sqe(&ctx->ring);
		if (ctx->fixed_files) {
			io_uring_prep_splice(sqe, op->pipe_idx[0], -1, op->io_idx,
					     -1, ctx->io_len, SPLICE_F_FD_IN_FIXED);
			sqe->flags |= IOSQE_FIXED_FILE;
		} else {
			io_uring_prep_splice(sqe, op->pipe[0], -1, op->io_fd,
					     -1, ctx->io_len, 0);
		}
		sqe->user_data = op->idx;
	}
	ret = io_uring_submit_and_wait(&ctx->ring, ctx->nr_ops);
	assert(ret == ctx->nr_ops);

	i = 0;
	io_uring_for_each_cqe(&ctx->ring, head, cqe) {
		if (cqe->res != ctx->io_len) {
			fprintf(stderr, "unexpected write res %i, idx %i\n",
					 cqe->res, i);
			exit(1);
		}
		i++;
	}
	assert(i == ctx->nr_ops);
	io_uring_cq_advance(&ctx->ring, i);
	ctx->stat_nr_reqs += i;
}

static void iterate_splice2(struct ctx *ctx)
{
	int ret;

	for (int i = 0; i < ctx->nr_ops; i++) {
		struct op *op = &ctx->ops[i];

		ret = splice(op->io_fd, NULL, op->pipe[1], NULL, ctx->io_len, 0);
		assert(ret == ctx->io_len);
	}

	for (int i = 0; i < ctx->nr_ops; i++) {
		struct op *op = &ctx->ops[i];

		ret = splice(op->pipe[0], NULL, op->io_fd, NULL, ctx->io_len, 0);
		assert(ret == ctx->io_len);
	}
	ctx->stat_nr_reqs += ctx->nr_ops;
}

static void *pthread_foo(void *arg)
{
	while (1)
		sleep(10);
	return NULL;
}

int main(int argc, char *argv[])
{
	bool dummy_thread = true;
	pthread_t thread;
	struct ctx ctx = {};
	struct op ops[MAX_INFLIGHT];
	unsigned long runtime_ms, tstop_ms;
	int ret, type, i, qd;
	int io_fd;

	if (argc != 4) {
		fprintf(stderr, "./splice-bench <op type> <QD> <runtime(ms)>\n"
			"    op type: 0 -- splice(2)\n"
			"             1 -- IORING_OP_SPLICE\n"
			"             2 -- IORING_OP_GET_BUF\n"
			"             3 -- IORING_OP_GET_BUF + IOSQE_IO_LINK\n"
			"             4 -- IORING_OP_GET_BUF + nop\n");
		return 1;
	}

	type = strtoul(argv[1], NULL, 0);
	qd = strtoul(argv[2], NULL, 0);
	runtime_ms = strtoul(argv[3], NULL, 0) * 1000;

	/* fget is more expensive for multi threaded apps */
	if (dummy_thread) {
		ret = pthread_create(&thread, NULL, pthread_foo, NULL);
		if (ret) {
			fprintf(stderr, "pthread failed %i\n", ret);
			return 1;
		}
	}

	ctx.ops = ops;
	ctx.nr_ops = qd;
	ctx.stat_nr_reqs = 0;
	ctx.io_len = 4096;
	ctx.fixed_files = true;

	io_fd = open("/dev/null", O_RDWR);
	if (io_fd < 0) {
		perror("open /dev/null");
		exit(1);
	}

	ret = io_uring_queue_init(qd * 4, &ctx.ring,
				  IORING_SETUP_COOP_TASKRUN |
				  IORING_SETUP_SINGLE_ISSUER |
				  IORING_SETUP_DEFER_TASKRUN);
	assert(ret == 0);

	ret = io_uring_register_buffers_sparse(&ctx.ring, qd + 10);
	assert(ret == 0);

	ret = io_uring_register_ring_fd(&ctx.ring);
	assert(ret >= 0);

	ret = io_uring_register_files_sparse(&ctx.ring, qd * 2 + 1);
	assert(ret == 0);

	ret = io_uring_register_files_update(&ctx.ring, qd * 2, &io_fd, 1);
	assert(ret == 1);

	for (i = 0; i < qd; i++) {
		struct op *op = &ops[i];

		op->idx = i;
		op->buf_idx = i + 1;
		op->io_fd = io_fd;
		op->io_idx = qd * 2;
		if (pipe2(op->pipe, 0) < 0) {
			fprintf(stderr, "pipe() failed\n");
			return 1;
		}

		op->pipe_idx[0] = i * 2;
		op->pipe_idx[1] = op->pipe_idx[0] + 1;
		ret = io_uring_register_files_update(&ctx.ring, op->pipe_idx[0],
						     op->pipe, 2);
		assert(ret == 2);
	}

	tstop_ms = gettimeofday_ms() + runtime_ms;
	do {
		/* avoid gettimeofday_ms() every iteration */
		for (i = 0; i < 16; i++) {
			switch (type) {
			case 0:
				iterate_splice2(&ctx);
				break;
			case 1:
				iterate_iou_splice(&ctx);
				break;
			case 2:
				iterate_buf_get(&ctx, false);
				break;
			case 3:
				iterate_buf_get_link(&ctx);
				break;
			case 4:
				iterate_buf_get(&ctx, true);
				break;
			default:
				exit(1);
			}
		}
	} while (gettimeofday_ms() < tstop_ms);

	printf("reqs/s %lu\n", ctx.stat_nr_reqs / (runtime_ms / 1000));

	return 0;
}

