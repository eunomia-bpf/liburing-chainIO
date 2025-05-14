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

static struct io_uring mgr_ring;
static __u64 mock_features;
static int mgr_fd;

static int setup_mgr(void)
{
	struct io_uring_mock_probe mp;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;

	ret = io_uring_queue_init(8, &mgr_ring, 0);
	if (ret) {
		fprintf(stderr, "mgr ring setup failed %i\n", ret);
		return T_EXIT_FAIL;
	}

	ret = mgr_fd = open("/dev/io_uring_mock", O_RDWR);
	if (mgr_fd < 0) {
		io_uring_queue_exit(&mgr_ring);
		return T_EXIT_SKIP;
	}

	memset(&mp, 0, sizeof(mp));
	sqe = io_uring_get_sqe(&mgr_ring);
	t_sqe_prep_cmd(sqe, mgr_fd, IORING_MOCK_MGR_CMD_PROBE);
	sqe->addr  = (__u64)(unsigned long)&mp;
	sqe->len = sizeof(mp);

	ret = t_submit_and_wait_single(&mgr_ring, &cqe);
	if (ret || cqe->res) {
		fprintf(stderr, "probe cmd failed %i %i\n", ret, cqe->res);
		return T_EXIT_FAIL;
	}

	io_uring_cqe_seen(&mgr_ring, cqe);
	mock_features = mp.features;
	return 0;
}

static int create_mock_file(struct io_uring_mock_create *mc)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(&mgr_ring);
	t_sqe_prep_cmd(sqe, mgr_fd, IORING_MOCK_MGR_CMD_CREATE);
	sqe->addr  = (__u64)(unsigned long)mc;
	sqe->len = sizeof(*mc);

	ret = t_submit_and_wait_single(&mgr_ring, &cqe);
	if (ret || cqe->res) {
		fprintf(stderr, "file create cmd failed %i %i\n", ret, cqe->res);
		return T_EXIT_FAIL;
	}
	io_uring_cqe_seen(&mgr_ring, cqe);
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

	ret = t_submit_and_wait_single(ring, &cqe);
	if (ret) {
		fprintf(stderr, "submit 1 failed\n");
		return T_EXIT_FAIL;
	}
	if (cqe->res != size) {
		fprintf(stderr, "Unexpected cqe result %i\n", cqe->res);
		return T_EXIT_FAIL;
	}
	io_uring_cqe_seen(ring, cqe);

	ret = memcmp(buf1, buf2, size);
	if (ret) {
		fprintf(stderr, "data mismatch %i\n", ret);
		return T_EXIT_FAIL;
	}

	free(buf1);
	free(buf2);
	return 0;
}

static int test_cmds(void)
{
	struct io_uring_mock_create mc;
	struct io_uring ring;
	int ret, mock_fd;

	memset(&mc, 0, sizeof(mc));
	if (create_mock_file(&mc))
		return T_EXIT_FAIL;
	mock_fd = mc.out_fd;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return 1;
	}

	if (mock_features & IORING_MOCK_FEAT_COPY_CMD) {
		ret = test_regvec_cmd(&ring, mock_fd);
		if (ret) {
			fprintf(stderr, "test_regvec_cmd() failed\n");
			return T_EXIT_FAIL;
		}
	}

	io_uring_queue_exit(&ring);
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	ret = setup_mgr();
	if (ret)
		return ret;

	ret = test_cmds();
	if (ret) {
		fprintf(stderr, "test_cmds failed %i\n", ret);
		return T_EXIT_FAIL;
	}

	io_uring_queue_exit(&mgr_ring);
	close(mgr_fd);
	return 0;
}
