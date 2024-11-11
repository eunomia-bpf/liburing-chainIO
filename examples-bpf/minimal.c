// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <sys/time.h>

#include "liburing.h"
#include "minimal.skel.h"
#include "/usr/include/asm-generic/unistd.h"
#include "../src/syscall.h"

enum {
	RUN_LINK,
	RUN_BPF,

	__RUN_TYPE_MAX,
};

static const char *type_names[] = {
	"2-LINK", "BPF",
};

struct ctx {
	int run_type;
	unsigned long reqs_to_run;
	struct io_uring ring;
	struct minimal_bpf *skel;
};

static unsigned long gettimeofday_ms(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void install_bpf_prog(struct ctx *ctx)
{
	struct minimal_bpf *skel;
	int err, prog_fd;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = minimal_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		exit(1);
	}

	skel->bss->reqs_to_run = ctx->reqs_to_run;

	/* Load & verify BPF programs */
	err = minimal_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	prog_fd = bpf_program__fd(skel->progs.run_test);

	err = io_uring_register_bpf(&ctx->ring, prog_fd);
	if (err) {
		fprintf(stderr, "io_uring_register_bpf failed %i\n", err);
		goto cleanup;
	}

	ctx->skel = skel;
	return;
cleanup:
	minimal_bpf__destroy(skel);
	exit(1);
}

static void setup_ctx(struct ctx *ctx)
{
	int ret;

	ret = io_uring_queue_init(32, &ctx->ring,
				IORING_SETUP_SINGLE_ISSUER |
				IORING_SETUP_DEFER_TASKRUN |
				IORING_SETUP_NO_SQARRAY);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		exit(1);
	}

	if (ctx->run_type == RUN_BPF)
		install_bpf_prog(ctx);
}

static void cleanup_ctx(struct ctx *ctx)
{
	if (ctx->skel)
		minimal_bpf__destroy(ctx->skel);
	io_uring_queue_exit(&ctx->ring);
}

static void run_bpf_test(struct ctx *ctx)
{
	int ret;

	ret = __sys_io_uring_enter(ctx->ring.ring_fd, 0, 1,
				   IORING_ENTER_GETEVENTS, NULL);
}

static void run_link_test(struct ctx *ctx)
{
	const int nr_per_link = 2;
	// struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	unsigned long nr_reqs = 0;
	int ret;


	while (nr_reqs < ctx->reqs_to_run) {
		for (int i = 0; i < nr_per_link; i++) {
			sqe = io_uring_get_sqe(&ctx->ring);
			io_uring_prep_nop(sqe);
			if (i != nr_per_link - 1)
				sqe->flags |= IOSQE_IO_LINK;
		}

		ret = io_uring_submit_and_wait(&ctx->ring, nr_per_link);
		if (ret != nr_per_link) {
			fprintf(stderr, "submit and wait failed %i\n", ret);
			exit(1);
		}

		io_uring_cq_advance(&ctx->ring, nr_per_link);
		nr_reqs += nr_per_link;
	}
}

int main(int argc, char **argv)
{
	struct ctx ctx = {};
	unsigned long t_start, t_stop, dt;
	unsigned type;
	unsigned requests;

	if (argc != 3) {
		fprintf(stderr, "run type parameter missing\n");
		return 1;
	}

	type = strtoul(argv[1], NULL, 0);
	if (type >= __RUN_TYPE_MAX) {
		fprintf(stderr, "invalid run type\n");
		return 1;
	}

	requests = strtoul(argv[2], NULL, 0);
	printf("type %s, requests to run %u\n", type_names[type], requests);

	ctx.run_type = type;
	ctx.reqs_to_run = requests;

	setup_ctx(&ctx);

	t_start = gettimeofday_ms();
	switch (ctx.run_type) {
	case RUN_BPF:
		run_bpf_test(&ctx);
		break;
	case RUN_LINK:
		run_link_test(&ctx);
		break;
	}
	t_stop = gettimeofday_ms();

	dt = t_stop - t_start;
	printf("sec %lu, total (ms) %lu\n", dt / 1000, dt);
	cleanup_ctx(&ctx);
	return 0;
}


