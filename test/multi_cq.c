/* SPDX-License-Identifier: MIT */
/*
 * Description: run various nop tests
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/mman.h>

#include "liburing.h"

static int test_invalid_cq_index(void)
{
	struct io_uring_sqe *sqe;
	struct io_uring ring;
	int ret;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return 1;
	}

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_nop(sqe);
	sqe->cq_idx = 2;
	ret = io_uring_submit(&ring);
	assert(ret == 1);

	io_uring_queue_exit(&ring);
	return 0;
}

static int test_invalid_multi_cq(void)
{
	struct io_uring_params params;
	struct io_uring ring;
	int ret;
	__u32 sz = ~(__u32)0;

	memset(&params, 0, sizeof(params));

	params.nr_cq = 1;
	params.cq_sizes = 0;
	ret = io_uring_queue_init_params(4, &ring, &params);
	assert(ret == -EINVAL);

	params.nr_cq = 0;
	params.cq_sizes = 1;
	ret = io_uring_queue_init_params(4, &ring, &params);
	assert(ret == -EINVAL);

	params.nr_cq = 5;
	params.cq_sizes = 1;
	ret = io_uring_queue_init_params(4, &ring, &params);
	assert(ret == -EFAULT);

	params.nr_cq = 1;
	params.cq_sizes = (__u64)(unsigned long)&sz;
	ret = io_uring_queue_init_params(4, &ring, &params);
	assert(ret == -EINVAL);

	params.nr_cq = 1 << 31;
	sz = 4096;
	params.cq_sizes = (__u64)(unsigned long)&sz;
	ret = io_uring_queue_init_params(4, &ring, &params);
	assert(ret == -EINVAL);

	return 0;
}

static int mmap_cq(struct io_uring_params *p, struct io_uring *r,
		   struct io_uring_cq *cq, unsigned long off)
{
	cq->ring_sz = p->cq_off.cqes + p->cq_entries * sizeof(struct io_uring_cqe);
	cq->ring_ptr = mmap(0, cq->ring_sz, PROT_READ | PROT_WRITE,
			    MAP_SHARED | MAP_POPULATE, r->ring_fd, off);
	if (cq->ring_ptr == MAP_FAILED)
		return -EFAULT;

	cq->khead = cq->ring_ptr + p->cq_off.head;
	cq->ktail = cq->ring_ptr + p->cq_off.tail;
	cq->kring_mask = cq->ring_ptr + p->cq_off.ring_mask;
	cq->kring_entries = cq->ring_ptr + p->cq_off.ring_entries;
	cq->koverflow = cq->ring_ptr + p->cq_off.overflow;
	cq->cqes = cq->ring_ptr + p->cq_off.cqes;
	if (p->cq_off.flags)
		cq->kflags = cq->ring_ptr + p->cq_off.flags;

	return 0;
}

static int test_mcq_mmap(void)
{
	struct io_uring_cq cq;
	struct io_uring_params p;
	struct io_uring ring;
	__u32 sz = 128;
	int ret, cq_idx = 1;

	memset(&p, 0, sizeof(p));
	p.nr_cq = 1;
	p.cq_sizes = (__u64)(unsigned long)&sz;
	ret = io_uring_queue_init_params(4, &ring, &p);
	assert(!ret);

	ret = mmap_cq(&p, &ring, &cq,
		      IORING_OFF_CQ_RING_EXTRA + 2 * IORING_STRIDE_CQ_RING);
	assert(ret < 0);
	ret = mmap_cq(&p, &ring, &cq,
		      IORING_OFF_CQ_RING_EXTRA + IORING_STRIDE_CQ_RING / 2);
	assert(ret < 0);
	ret = mmap_cq(&p, &ring, &cq,
			IORING_OFF_CQ_RING_EXTRA - 100);
	assert(ret < 0);

	ret = mmap_cq(&p, &ring, &cq,
		      IORING_OFF_CQ_RING_EXTRA + cq_idx * IORING_STRIDE_CQ_RING);
	assert(!ret);

	munmap(cq.ring_ptr, cq.ring_sz);
	io_uring_queue_exit(&ring);
	return 0;
}

static int test_mcq_requests(void)
{
	unsigned head, tail;
	struct io_uring_cq cq;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct io_uring_params params;
	struct io_uring ring;
	int ret;
	__u32 sz = 128;

	memset(&params, 0, sizeof(params));
	params.nr_cq = 1;
	params.cq_sizes = (__u64)(unsigned long)&sz;
	ret = io_uring_queue_init_params(4, &ring, &params);
	assert(!ret);

	ret = mmap_cq(&params, &ring, &cq, IORING_OFF_CQ_RING_EXTRA + IORING_STRIDE_CQ_RING);
	assert(!ret);

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_nop(sqe);
	sqe->user_data = 1;
	sqe->cq_idx = 0;
	ret = io_uring_submit(&ring);
	assert(ret == 1);

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_nop(sqe);
	sqe->user_data = 2;
	sqe->cq_idx = 1;
	ret = io_uring_submit(&ring);
	assert(ret == 1);

	ret = io_uring_wait_cqe(&ring, &cqe);
	assert(!ret && cqe->res == 0);
	io_uring_cqe_seen(&ring, cqe);
	ret = io_uring_peek_cqe(&ring, &cqe);
	assert(ret == -EAGAIN);

	head = *cq.khead;
	tail = io_uring_smp_load_acquire(cq.ktail);
	assert(tail - head == 1);
	cqe = &cq.cqes[head & *cq.kring_mask];
	assert(cqe->user_data == 2);
	assert(cqe->res == 0);

	munmap(cq.ring_ptr, cq.ring_sz);
	io_uring_queue_exit(&ring);
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return 0;

	ret = test_invalid_cq_index();
	if (ret) {
		fprintf(stderr, "test_invalid_cq_index failed\n");
		return ret;
	}

	ret = test_invalid_multi_cq();
	if (ret) {
		fprintf(stderr, "test_invalid_multi_cq failed\n");
		return ret;
	}

	ret = test_mcq_mmap();
	if (ret) {
		fprintf(stderr, "test_mcq_mmap failed\n");
		return ret;
	}

	ret = test_mcq_requests();
	if (ret) {
		fprintf(stderr, "test_mcq_requests failed\n");
		return ret;
	}

	return 0;
}
