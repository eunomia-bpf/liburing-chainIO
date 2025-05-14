#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <assert.h>

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
			 struct iovec *iov, unsigned iov_len, char *buf,
			 bool from_iov)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	t_sqe_prep_cmd(sqe, mock_fd, IORING_MOCK_CMD_COPY_REGBUF);
	sqe->addr3 = (__u64)(unsigned long)buf;
	sqe->addr = (__u64)(unsigned long)iov;
	sqe->len = iov_len;
	if (from_iov)
		sqe->file_index = IORING_MOCK_COPY_FROM;
	sqe->buf_index = from_iov ? 0 : 1;
	sqe->user_data = 43;
	sqe->uring_cmd_flags |= IORING_URING_CMD_FIXED;

	ret = t_submit_and_wait_single(ring, &cqe);
	if (ret)
		t_error(1, ret, "submit/wait failed");

	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	return ret;
}

static int t_copy_verify_regvec(struct io_uring *ring, int mock_fd,
				struct iovec *iov, unsigned iov_len, char *buf,
				bool from_iov)
{
	struct iovec iov2;
	int ret;

	ret = t_copy_regvec(ring, mock_fd, iov, iov_len, buf, from_iov);
	if (ret < 0 || ret != t_iovec_data_length(iov, iov_len))
		return ret < 0 ? ret : -1;

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
	size_t size = 4096 * 32;
	char *buf_src, *buf_dst;
	int i, ret;

	buf_src = aligned_alloc(4096, size);
	buf_dst = aligned_alloc(4096, size);
	if (!buf_src || !buf_dst)
		t_error(0, -ENOMEM, "can't allocate buffers");

	for (i = 0; i < size; i++)
		buf_src[i] = 'a' + (i % 26);

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

	memset(buf_dst, 0, size);
	iov[0].iov_len = size;
	iov[0].iov_base = buf_src;
	ret = t_copy_verify_regvec(ring, mock_fd, iov, 1, buf_dst, true);
	if (ret < 0) {
		fprintf(stderr, "t_copy_verify_regvec iovec1 failed %i\n", ret);
		return T_EXIT_FAIL;
	}

	memset(buf_dst, 0, size);
	iov[0].iov_len = size;
	iov[0].iov_base = buf_dst;
	ret = t_copy_verify_regvec(ring, mock_fd, iov, 1, buf_src, false);
	if (ret < 0) {
		fprintf(stderr, "t_copy_verify_regvec iovec1 reverse failed %i\n", ret);
		return T_EXIT_FAIL;
	}

	memset(buf_dst, 0, size);
	iov[0].iov_base = buf_src;
	iov[0].iov_len = 5;
	iov[1].iov_base = buf_src + 5;
	iov[1].iov_len = 11;
	iov[2].iov_base = buf_src + (4096 - 127);
	iov[2].iov_len = 127;
	iov[3].iov_base = buf_src + (4096 - 127);
	iov[3].iov_len = 127 + 4096 + 13;
	iov[4].iov_base = buf_src + 4 * 4096;
	iov[4].iov_len = 4096 + 73;
	iov[5].iov_base = buf_src + 7 * 4096 + 127;
	iov[5].iov_len = 4096 * 11 + 132;
	assert(t_iovec_data_length(iov, 6) <= size);
	ret = t_copy_verify_regvec(ring, mock_fd, iov, 6, buf_dst, true);
	if (ret < 0) {
		fprintf(stderr, "t_copy_verify_regvec iovec6 failed %i\n", ret);
		return T_EXIT_FAIL;
	}

	memset(buf_dst, 0, size);
	iov[0].iov_base = buf_dst;
	iov[0].iov_len = 5;
	iov[1].iov_base = buf_dst + 5;
	iov[1].iov_len = 11;
	iov[2].iov_base = buf_dst + (4096 - 127);
	iov[2].iov_len = 127;
	iov[3].iov_base = buf_dst + 4 * 4096;
	iov[3].iov_len = 4096 + 73;
	iov[4].iov_base = buf_dst + 7 * 4096 + 127;
	iov[4].iov_len = 4096 * 11 + 132;
	assert(t_iovec_data_length(iov, 5) <= size);
	ret = t_copy_verify_regvec(ring, mock_fd, iov, 5, buf_src, false);
	if (ret < 0) {
		fprintf(stderr, "t_copy_verify_regvec iovec6 reverse failed %i\n", ret);
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

	if (IORING_MOCK_FEAT_CMD_COPY < mock_features) {
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
	if (ret)
		return T_EXIT_FAIL;

	io_uring_queue_exit(&mgr_ring);
	close(mgr_fd);
	return 0;
}
