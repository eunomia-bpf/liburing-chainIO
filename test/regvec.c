/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/resource.h>

#include "helpers.h"
#include "liburing.h"

static bool has_regvec;

struct buf_desc {
	char			*buf_wr;
	char			*buf_rd;
	size_t			size;

	struct io_uring 	ring;
	bool			ring_init;
	bool			fixed;
	int			buf_idx;
	bool			rw;
};

#define BUFFER_SIZE	(4096 * 16)
#define BUF_BASE_IDX	1

static void probe_support(void)
{
	struct io_uring_probe *p;
	struct io_uring ring;
	int ret = 0;

	ret = io_uring_queue_init(1, &ring, 0);
	if (ret) {
		fprintf(stderr, "queue init failed: %d\n", ret);
		exit(ret);
	}

	p = t_calloc(1, sizeof(*p) + 256 * sizeof(struct io_uring_probe_op));
	ret = io_uring_register_probe(&ring, p, 256);

	/* if we don't have PROBE_REGISTER, we don't have OP_READ/WRITE */
	if (ret == -EINVAL)
		goto out;
	if (ret) {
		fprintf(stderr, "register_probe: %d\n", ret);
		goto out;
	}

	has_regvec = p->ops_len > IORING_OP_READV_FIXED &&
		     (p->ops[IORING_OP_READV_FIXED].flags & IO_URING_OP_SUPPORTED);
out:
	io_uring_queue_exit(&ring);
	if (p)
		free(p);
}

static void bind_ring(struct buf_desc *bd, struct io_uring *ring, unsigned buf_idx)
{
	size_t size = bd->size;
	struct iovec iov[2];
	int ret;

	iov[0].iov_len = size;
	iov[0].iov_base = bd->buf_rd;
	iov[1].iov_len = size;
	iov[1].iov_base = bd->buf_wr;

	ret = io_uring_register_buffers_update_tag(ring, buf_idx, iov, NULL, 2);
	if (ret != 2) {
		fprintf(stderr, "buf reg failed %i\n", ret);
		exit(1);
	}
	bd->buf_idx = buf_idx;
}

static void reinit_ring(struct buf_desc *bd)
{
	struct io_uring *ring = &bd->ring;
	int ret;

	if (bd->ring_init) {
		io_uring_queue_exit(ring);
		bd->ring_init = false;
	}

	ret = io_uring_queue_init(32, ring, 0);
	if (ret) {
		fprintf(stderr, "ring init error %i\n", ret);
		exit(1);
	}

	ret = io_uring_register_buffers_sparse(ring, 128);
	if (ret) {
		fprintf(stderr, "table reg error %i\n", ret);
		exit(1);
	}

	bind_ring(bd, &bd->ring, BUF_BASE_IDX);
	bd->ring_init = true;
}

static void init_buffers(struct buf_desc *bd, size_t size)
{
	memset(bd, 0, sizeof(*bd));
	bd->size = size;
	bd->buf_wr = malloc(BUFFER_SIZE);
	bd->buf_rd = malloc(BUFFER_SIZE);
	if (!bd->buf_rd || !bd->buf_wr) {
		fprintf(stderr, "malloc fail\n");
		exit(1);
	}
}

static void verify_data(struct buf_desc *bd, struct iovec *wr_vecs, int nr_iovec,
			int pipefd)
{
	int iov_idx, ret;

	for (iov_idx = 0; iov_idx < nr_iovec; iov_idx++) {
		struct iovec *vec = &wr_vecs[iov_idx];
		size_t seg_size = vec->iov_len;

		ret = read(pipefd, bd->buf_rd, seg_size);
		if (ret != seg_size) {
			fprintf(stderr, "read error %i", ret);
			exit(1);
		}

		ret = memcmp(bd->buf_rd, vec->iov_base, seg_size);
		if (ret != 0) {
			fprintf(stderr, "data mismatch %i\n", ret);
			exit(1);
		}
	}
}

static int test_rw(struct buf_desc *bd, struct iovec *vecs, int nr_vec,
		      bool expect_fail, size_t total_len)
{
	unsigned buf_idx = bd->buf_idx + 1;
	struct io_uring *ring = &bd->ring;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int pipefd[2];
	int ret;

	if (pipe(pipefd) != 0) {
		perror("pipe");
		exit(1);
	}

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_writev(sqe, pipefd[1], vecs, nr_vec, 0);
	if (bd->fixed)
		sqe->buf_index = buf_idx;

	ret = io_uring_submit(ring);
	if (ret != 1) {
		fprintf(stderr, "submit failed %i\n", ret);
		exit(1);
	}
	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait_cqe=%d\n", ret);
		exit(1);
	}

	printf("cqe: data %i, res %i\n", (int)cqe->user_data, (int)cqe->res);
	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);

	if (ret != total_len) {
		if (!expect_fail)
			fprintf(stderr, "invalid cqe %i, expected %lu\n",
					 ret, (unsigned long)total_len);
		return ret;
	}

	verify_data(bd, vecs, nr_vec, pipefd[0]);
	close(pipefd[0]);
	close(pipefd[1]);
	return 0;
}

static int test_sendzc(struct buf_desc *bd, struct iovec *vecs, int nr_vec,
		       bool expect_fail, size_t total_len)
{
	unsigned buf_idx = bd->buf_idx + 1;
	struct io_uring *ring = &bd->ring;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct sockaddr_storage addr;
	int sock_serv, sock_client;
	int ret, cqe_ret, more;
	struct msghdr msghdr;

	ret = t_create_socketpair_ip(&addr, &sock_client, &sock_serv,
					true, true, false, true, "::1");
	if (ret) {
		fprintf(stderr, "sock prep failed %d\n", ret);
		return 1;
	}

	memset(&msghdr, 0, sizeof(msghdr));
	msghdr.msg_iov = vecs;
	msghdr.msg_iovlen = nr_vec;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_sendmsg_zc_fixed(sqe, sock_client, &msghdr, 0, buf_idx);

	ret = io_uring_submit(ring);
	if (ret != 1) {
		fprintf(stderr, "submit failed %i\n", ret);
		exit(1);
	}
	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait_cqe=%d\n", ret);
		exit(1);
	}

	printf("cqe: data %i, res %i\n", (int)cqe->user_data, (int)cqe->res);
	cqe_ret = cqe->res;
	more = cqe->flags & IORING_CQE_F_MORE;
	io_uring_cqe_seen(ring, cqe);

	if (more) {
		ret = io_uring_wait_cqe(ring, &cqe);
		if (ret) {
			fprintf(stderr, "wait_cqe=%d\n", ret);
			exit(1);
		}
		io_uring_cqe_seen(ring, cqe);
	}

	if (cqe_ret != total_len) {
		if (!expect_fail)
			fprintf(stderr, "invalid cqe %i, expected %lu\n",
					 cqe_ret, (unsigned long)total_len);
		return cqe_ret;
	}

	verify_data(bd, vecs, nr_vec, sock_serv);
	close(sock_client);
	close(sock_serv);
	return 0;
}


static int test_vec(struct buf_desc *bd, struct iovec *vecs, int nr_vec,
		    bool expect_fail)
{
	size_t total_len = 0;
	int i;

	for (i = 0; i < bd->size; i++)
		bd->buf_wr[i] = i;
	memset(bd->buf_rd, 0, bd->size);

	for (i = 0; i < nr_vec; i++)
		total_len += vecs[i].iov_len;

	if (bd->rw)
		return test_rw(bd, vecs, nr_vec, expect_fail, total_len);

	return test_sendzc(bd, vecs, nr_vec, expect_fail, total_len);
}

struct work {
	struct iovec	*vecs;
	unsigned	nr_vecs;
};

static int test_sequence(struct buf_desc *bd, unsigned nr, struct work *ws)
{
	int i, ret;

	reinit_ring(bd);

	for (i = 0; i < nr; i++) {
		ret = test_vec(bd, ws[i].vecs, ws[i].nr_vecs, false);
		if (ret) {
			fprintf(stderr, "sequence failed, idx %i/%i\n", i, nr);
			return ret;
		}
	}
	return 0;
}

static void test(struct buf_desc *bd)
{
	int ret;
	struct iovec vecs[] = {
		{ .iov_base = bd->buf_wr, .iov_len = 4096, },
		{ .iov_base = bd->buf_wr, .iov_len = 4096 * 2 + 12, },
		{ .iov_base = bd->buf_wr + 1, .iov_len = 3, },
		{ .iov_base = bd->buf_wr + 1, .iov_len = 4096 * 5, },
	};
	struct iovec vecs2[] = {
		{ .iov_base = bd->buf_wr, .iov_len = 4096, },
		{ .iov_base = bd->buf_wr, .iov_len = 4096, },
		{ .iov_base = bd->buf_wr, .iov_len = 4096, },
	};

	ret = test_sequence(bd, 2, (struct work[]) {
			{ &vecs[0], 1},
			{ &vecs[0], 1}});
	if (ret) {
		fprintf(stderr, "seq failure: basic aligned, %i\n", ret);
		exit(1);
	}

	ret = test_sequence(bd, 2, (struct work[]) {
			{ &vecs[1], 1},
			{ &vecs[1], 1}});
	if (ret) {
		fprintf(stderr, "seq failure: multi page buffer, %i\n", ret);
		exit(1);
	}

	ret = test_sequence(bd, 2, (struct work[]) {
			{ &vecs[2], 1},
			{ &vecs[2], 1}});
	if (ret) {
		fprintf(stderr, "seq failure: misaligned buffer, %i\n", ret);
		exit(1);
	}

	ret = test_sequence(bd, 2, (struct work[]) {
			{ &vecs[3], 1},
			{ &vecs[3], 1}});
	if (ret) {
		fprintf(stderr, "seq failure: misaligned multipage buffer, %i\n", ret);
		exit(1);
	}

	ret = test_sequence(bd, 2, (struct work[]) {
			{ &vecs[0], 1},
			{ &vecs[3], 1}});
	if (ret) {
		fprintf(stderr, "seq failure: realloc + increase bvec, %i\n", ret);
		exit(1);
	}

	ret = test_sequence(bd, 2, (struct work[]) {
			{ &vecs[3], 1},
			{ &vecs[0], 1}});
	if (ret) {
		fprintf(stderr, "seq failure: realloc + decrease bvec, %i\n", ret);
		exit(1);
	}

	ret = test_sequence(bd, 2, (struct work[]) {
			{ &vecs[0], 4},
			{ &vecs[0], 4}});
	if (ret) {
		fprintf(stderr, "seq failure: multisegment, %i\n", ret);
		exit(1);
	}

	ret = test_sequence(bd, 3, (struct work[]) {
			{ &vecs[0], 2},
			{ &vecs[0], 3},
			{ &vecs[0], 4}});
	if (ret) {
		fprintf(stderr, "seq failure: multisegment 2, %i\n", ret);
		exit(1);
	}

	ret = test_sequence(bd, 3, (struct work[]) {
			{ &vecs2[0], 1},
			{ &vecs2[0], 2},
			{ &vecs2[0], 3}});
	if (ret) {
		fprintf(stderr, "seq failure: increase iovec, %i\n", ret);
		exit(1);
	}

	ret = test_sequence(bd, 3, (struct work[]) {
			{ &vecs2[0], 3},
			{ &vecs2[0], 2},
			{ &vecs2[0], 1}});
	if (ret) {
		fprintf(stderr, "seq failure: decrease iovec, %i\n", ret);
		exit(1);
	}
}

int main(void)
{
	struct buf_desc bd = {};

	probe_support();
	if (!has_regvec) {
		printf("doesn't support registered vector ops, skip\n");
		return 0;
	}

	init_buffers(&bd, BUFFER_SIZE);

	bd.fixed = false;
	bd.rw = true;
	test(&bd);

	io_uring_queue_exit(&bd.ring);
	free(bd.buf_rd);
	free(bd.buf_wr);
	return 0;
}