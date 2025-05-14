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

	ret = mgr_fd = open("/dev/io_uring_mock", O_RDWR);
	if (mgr_fd < 0) {
		printf("no io_uring mock files, skip\n");
		return T_EXIT_SKIP;
	}

	ret = io_uring_queue_init(8, &mgr_ring, 0);
	if (ret) {
		fprintf(stderr, "mgr ring setup failed %i\n", ret);
		return T_EXIT_FAIL;
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

static int t_copy_regvec(struct io_uring *ring, int mock_fd,
			 struct iovec *iov, unsigned iov_len, char *buf)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	t_sqe_prep_cmd(sqe, mock_fd, IORING_MOCK_CMD_COPY_REGBUF);
	sqe->addr3 = (__u64)(unsigned long)buf;
	sqe->addr = (__u64)(unsigned long)iov;
	sqe->len = iov_len;
	sqe->rw_flags = IORING_MOCK_COPY_FROM;
	sqe->buf_index = 0;
	sqe->user_data = 43;

	ret = t_submit_and_wait_single(ring, &cqe);
	if (ret)
		t_error(1, ret, "submit/wait failed");

	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	return ret;
}

static int t_copy_verify_regvec(struct io_uring *ring, int mock_fd,
				struct iovec *iov, unsigned iov_len, char *buf)
{
	struct iovec iov2;
	int ret;

	ret = t_copy_regvec(ring, mock_fd, iov, iov_len, buf);
	if (ret < 0 || ret != t_iovec_data_length(iov, iov_len)) {
		fprintf(stderr, "iovec1 failed %i\n", ret);
		return ret < 0 ? ret : -1;
	}

	iov2.iov_base = buf;
	iov2.iov_len = -1U;

	ret = t_compare_data_iovec(iov, iov_len, &iov2, 1);
	if (ret) {
		fprintf(stderr, "iovec1 data mismatch %i\n", ret);
		return -1;
	}
	return 0;
}

static int test_regvec_cmd(struct io_uring *ring, int mock_fd)
{
	struct iovec buf_iovec[2];
	struct iovec iov[8];
	size_t size = 4096 * 16;
	char *buf_src, *buf_dst;
	int i, ret;

	buf_src = aligned_alloc(4096, size);
	buf_dst = aligned_alloc(4096, size);
	if (!buf_src || !buf_dst)
		t_error(0, -ENOMEM, "can't allocate buffers");

	for (i = 0; i < size; i++)
		buf_src[i] = 'a' + (i % 26);
	memset(buf_dst, 0, size);

	buf_iovec[0].iov_base = buf_src;
	buf_iovec[0].iov_len = size;
	buf_iovec[1].iov_base = buf_dst;
	buf_iovec[1].iov_len = size;
	ret = t_register_buffers(ring, buf_iovec, 2);
	if (ret) {
		free(buf_src);
		free(buf_dst);
		return ret == T_SETUP_SKIP ? 0 : T_EXIT_FAIL;
	}

	iov[0].iov_len = size;
	iov[0].iov_base = buf_src;
	ret = t_copy_verify_regvec(ring, mock_fd, iov, 1, buf_dst);
	if (ret < 0) {
		fprintf(stderr, "t_copy_verify_regvec iovec1 failed %i\n", ret);
		return T_EXIT_FAIL;
	}

	free(buf_src);
	free(buf_dst);
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
	} else {
		printf("skip test_regvec_cmd()\n");
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
