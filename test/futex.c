/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>

#include "liburing.h"

static void *addr;

#define __NR_futex 202

static inline void io_uring_futex_wake_prep(struct io_uring_sqe *sqe,
					    void *uaddr, unsigned int nr_wake,
					    unsigned int op)
{
	io_uring_prep_rw(IORING_OP_UNLINKAT + 1, sqe, -1, uaddr, 0,
			((__u64)op << 32) | nr_wake);
}

static inline void io_uring_futex_wait_prep(struct io_uring_sqe *sqe,
					    void *uaddr, unsigned int val)
{
	io_uring_prep_rw(IORING_OP_UNLINKAT + 1, sqe, -1, uaddr, 0, val);
}

static void *foo(void *arg)
{
	struct io_uring *ring = arg;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;
	unsigned int op;

	sleep(1);

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "get sqe failed\n");
		return (void *)1;
	}
	op = FUTEX_OP(FUTEX_OP_ADD, 1, FUTEX_OP_CMP_EQ, 0);
	io_uring_futex_wake_prep(sqe, addr, 1, op);
	sqe->fsync_flags = 1; // TODO: futex flags
	sqe->user_data = 42;

	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		return (void *)1;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait completion %d\n", ret);
		return (void *)1;
	}
	fprintf(stderr, "%i %i\n", cqe->res, (int)cqe->user_data);
	io_uring_cqe_seen(ring, cqe);
	return NULL;
}

static int test_wake()
{
	struct io_uring ring;
	pthread_t th;
	void *res;
	int ret;
	__u32 u = 0;

	addr = &u;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return 1;
	}
	if (pthread_create(&th, NULL, foo, &ring)) {
		fprintf(stderr, "pthread_create() failed\n");
		return 1;
	}

	ret = syscall(__NR_futex, addr, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
	if (ret) {
		fprintf(stderr, "syscall failed\n");
		return 1;
	}

	if (pthread_join(th, &res) || res) {
		fprintf(stderr, "pthread_join() failed\n");
		return 1;
	}
	fprintf(stderr, "%i\n", u);
	io_uring_queue_exit(&ring);
	return 0;
}

static int test_wait(void)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct io_uring ring;
	int ret;
	int wait_value = 2;
	__u32 u = 1;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return 1;
	}

	sqe = io_uring_get_sqe(&ring);
	if (!sqe) {
		fprintf(stderr, "get sqe failed\n");
		return 1;
	}
	io_uring_futex_wait_prep(sqe, &u, wait_value);
	sqe->fsync_flags = 1; // TODO: futex_flags
	sqe->user_data = 42;

	ret = io_uring_submit(&ring);
	if (ret <= 0) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		return 1;
	}

	u = wait_value;
	ret = syscall(__NR_futex, &u, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
	if (ret) {
		fprintf(stderr, "syscall failed\n");
		return 1;
	}

	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait completion %d\n", ret);
		return 1;
	}
	fprintf(stderr, "%i %i\n", cqe->res, (int)cqe->user_data);
	fprintf(stderr, "%i\n", u);
	io_uring_cqe_seen(&ring, cqe);
	io_uring_queue_exit(&ring);
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return 0;

	ret = test_wake();
	if (ret) {
		fprintf(stderr, "test_wake failed %i\n", ret);
		return 1;
	}

	ret = test_wait();
	if (ret) {
		fprintf(stderr, "test_wait failed %i\n", ret);
		return 1;
	}

	return 0;
}
