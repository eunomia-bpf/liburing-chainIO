/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>

#include "liburing.h"
#include "test.h"
#include "helpers.h"

enum {
	IORING_OP_SPLICE_FROM = IORING_OP_SENDMSG_ZC + 1,
};

static char buffer[4096];
static char buffer2[4096];

int main(int argc, char *argv[])
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct io_uring ring;
	int ret;
	int fds[2];
	int len = 64;

	memset(buffer, 0xe, sizeof(buffer));
	ret = t_create_socket_pair(fds, true);
	assert(!ret);
	ret = io_uring_queue_init(8, &ring, IORING_SETUP_COOP_TASKRUN |
					    IORING_SETUP_SINGLE_ISSUER |
					    IORING_SETUP_DEFER_TASKRUN);
	assert(ret == 0);
	ret = io_uring_register_buffers_sparse(&ring, 5);
	assert(ret == 0);

	ret = send(fds[1], buffer, len, 0);
	assert(ret == len);

	/* splice */
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_nop(sqe);
	sqe->fd = fds[0];
	sqe->opcode = IORING_OP_SPLICE_FROM;
	sqe->len = len;
	sqe->off = 0;
	sqe->buf_index = 0;

	ret = io_uring_submit(&ring);
	assert(ret == 1);
	ret = io_uring_wait_cqe(&ring, &cqe);
	assert(ret == 0);
	assert(cqe->res == len);
	io_uring_cqe_seen(&ring, cqe);

	/* check empty */
	ret = recv(fds[0], buffer2, len, MSG_DONTWAIT);
	assert(ret == 0 || (ret < 0 && errno == EAGAIN));

	/* data is in buffer=0, extract into buffer2 via fds[1] */
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_write_fixed(sqe, fds[0], NULL /* buffer3 */, len, 0, 0);
	ret = io_uring_submit(&ring);
	assert(ret == 1);
	ret = io_uring_wait_cqe(&ring, &cqe);
	assert(ret == 0);
	assert(cqe->res == len);
	io_uring_cqe_seen(&ring, cqe);

	memset(buffer2, 0xa, sizeof(buffer2));
	ret = recv(fds[1], buffer2, len, 0);
	assert(ret == len);

	for (int j = 0; j < len; j++) {
		// fprintf(stderr, "0x%x 0x%x\n", buffer2[j], 0xe);
		assert(buffer2[j] == 0xe);
	}
	return 0;
}
