#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>

#include "liburing.h"
#include "test.h"
#include "helpers.h"

#include "mock.h"

static int open_mock_file(struct io_uring_mock_create *mc)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct io_uring ring;
	int mgr_fd = -1, ret;

	ret = io_uring_queue_init(1, &ring, 0);
	if (ret)
		return ret;

	ret = mgr_fd = open("/dev/io_uring_mock", O_RDWR);
	if (mgr_fd < 0)
		goto fail;

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_rw(IORING_OP_URING_CMD, sqe, mgr_fd, NULL, 0, 0);
	sqe->cmd_op = IORING_MOCK_MGR_CMD_CREATE;
	sqe->addr  = (__u64)(unsigned long)mc;
	sqe->len = sizeof(*mc);
	sqe->buf_index = 0;

	ret = io_uring_submit(&ring);
	if (ret <= 0) {
		ret = ret < 0 ? ret : -1;
		goto fail;
	}
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret < 0)
		goto fail;

	ret = cqe->res < 0 ? cqe->res : 0;
fail:
	if (mgr_fd >= 0)
		close(mgr_fd);
	io_uring_queue_exit(&ring);
	return ret;
}

static int test_submit_and_wait_single(struct io_uring *ring,
					struct io_uring_cqe **pcqe)
{
	int ret;

	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		return -1;
	}
	ret = io_uring_wait_cqe(ring, pcqe);
	if (ret < 0) {
		fprintf(stderr, "wait completion %d\n", ret);
		return ret;
	}
	return 0;
}

static int test_regvec_cmd(struct io_uring *ring, int mock_fd)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	size_t size = 4096 * 16;
	struct iovec reg_iov = {};
	char *buf1, *buf2;
	int i, ret;

	buf1 = aligned_alloc(4096, size);
	buf2 = aligned_alloc(4096, size);
	if (!buf1 || !buf2)
		t_error(0, -ENOMEM, "can't allocate buffers");

	for (i = 0; i < size; i++)
		buf1[i] = 'a' + (i % 26);
	memset(buf2, 0, size);

	reg_iov.iov_len = size;
	reg_iov.iov_base = buf1;
	ret = io_uring_register_buffers(ring, &reg_iov, 1);
	if (ret) {
		free(buf1);
		free(buf2);
		return 0;
	}

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_rw(IORING_OP_URING_CMD, sqe, mock_fd, NULL, 0, 0);
	sqe->cmd_op = IORING_MOCK_CMD_COPY_REGBUF;
	sqe->addr3 = (__u64)(unsigned long)buf2;
	sqe->addr = (__u64)(unsigned long)&reg_iov;
	sqe->len = 1;
	sqe->rw_flags = IORING_MOCK_COPY_FROM;
	sqe->buf_index = 0;
	sqe->user_data = 43;

	ret = test_submit_and_wait_single(ring, &cqe);
	if (ret) {
		fprintf(stderr, "submit 1 failed\n");
		return -1;
	}
	if (cqe->res != size) {
		fprintf(stderr, "Unexpected cqe result %i\n", cqe->res);
		return -1;
	}
	io_uring_cqe_seen(ring, cqe);

	ret = memcmp(buf1, buf2, size);
	if (ret) {
		fprintf(stderr, "data mismatch %i\n", ret);
		return -1;
	}

	free(buf1);
	free(buf2);
	return 0;
}

int main(int argc, char *argv[])
{
	struct io_uring_mock_create mc;
	struct io_uring ring;
	int ret, mock_fd;

	memset(&mc, 0, sizeof(mc));
	if (open_mock_file(&mc))
		return T_EXIT_SKIP;
	mock_fd = mc.out_fd;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return 1;
	}

	ret = test_regvec_cmd(&ring, mock_fd);
	if (ret) {
		fprintf(stderr, "test_regvec_cmd() failed\n");
		return T_EXIT_FAIL;
	}

	io_uring_queue_exit(&ring);
	return 0;
}
