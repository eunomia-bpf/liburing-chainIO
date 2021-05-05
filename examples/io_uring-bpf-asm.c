/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stddef.h>
#include "liburing.h"
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <sys/mman.h>

#include "bpf-helpers.h"
#include "../src/syscall.h"

#define IORING_OP_EBPF (IORING_OP_UNLINKAT + 1)

char bpf_log_buf[BPF_LOG_BUF_SIZE];

static int bpf_example()
{
	struct bpf_load_program_attr load_attr;
	struct io_uring_params p;
	struct io_uring ring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;
	int map_fd;
	int key;
	long long value = 0;
	__u32 cq_sizes[2] = {128, 128};

	memset(&p, 0, sizeof(p));
	p.nr_cq = 1;
	p.cq_sizes = (__u64)(unsigned long)cq_sizes;
	ret = io_uring_queue_init_params(8, &ring, &p);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return 1;
	}

	map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value),	256, 0);
	if (map_fd < 0) {
		fprintf(stderr, "failed to create map '%s'\n", strerror(errno));
		exit(1);
	}

	struct bpf_insn prog[] = {
		BPF_MOV64_REG(BPF_REG_6, BPF_REG_1), // 6 -- ctx

		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -16),
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -24),
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -40),
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -48),
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -56),
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -64),


		BPF_MOV64_IMM(BPF_REG_0, 244), // invalid opcode
		BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_0, -64),
		BPF_MOV64_IMM(BPF_REG_0, 1), // invalid opcode
		// BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_0, -16),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),


		BPF_MOV64_REG(BPF_REG_1, BPF_REG_6), // ctx
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -64),
		BPF_MOV64_IMM(BPF_REG_3, 64),
		BPF_MOV64_IMM(BPF_REG_0, 60),
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -32), // user_data
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, MY_BPF_FUNC_iouring_queue_sqe),

		BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = fp - 4 */
		BPF_LD_MAP_FD(BPF_REG_1, map_fd),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_7),
		BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 0),

		BPF_MOV64_IMM(BPF_REG_0, 0), /* r0 = 0 */
		BPF_EXIT_INSN(),
	};

	memset(&load_attr, 0, sizeof(struct bpf_load_program_attr));
	load_attr.prog_type = (int)BPF_PROG_TYPE2_IOURING;
	load_attr.expected_attach_type = 0;
	load_attr.name = NULL;
	load_attr.insns = prog;
	load_attr.insns_cnt = sizeof(prog) / sizeof(struct bpf_insn);
	load_attr.license = "GPL";
	load_attr.kern_version = 0;
	load_attr.prog_flags = BPF_F_SLEEPABLE;

	int prog_fd = bpf_load_program_xattr(&load_attr, bpf_log_buf, BPF_LOG_BUF_SIZE);
	if (prog_fd < 0) {
		bpf_log_buf[BPF_LOG_BUF_SIZE - 1] = 0;
		fprintf(stderr, "%s\n", bpf_log_buf);
	}
	assert(prog_fd >= 0);

	int prog_fds[] = {prog_fd, prog_fd, prog_fd};
	ret = __sys_io_uring_register(ring.ring_fd, IORING_REGISTER_BPF,
					prog_fds, 3);
	assert(ret >= 0);

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_nop(sqe);
	sqe->off = 1;
	sqe->opcode = IORING_OP_EBPF;
	sqe->user_data = 13;
	sqe->flags = 0;

	ret = io_uring_submit(&ring);
	if (ret <= 0) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		goto err;
	}
	for (int i = 0; i < 1; ++i) {
		ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "wait completion %d\n", ret);
			goto err;
		}
		fprintf(stderr, "compl ud %i | res %i\n",
			(int)cqe->user_data,
			(int)cqe->res);
		io_uring_cqe_seen(&ring, cqe);
	}

	for (int i = 0; i < 10; i++) {
		long long cnt;
		key = i;
		assert(bpf_map_lookup_elem(map_fd, &key, &cnt) == 0);
		fprintf(stderr, "%i ", (int)cnt);
	}
	fprintf(stderr, "\n");
	return 0;
err:
	return 1;
}

int main(int argc, char *argv[])
{
	int ret;

	ret = bpf_example();
	if (ret) {
		fprintf(stderr, "failed\n");
		return ret;
	}
	return 0;
}
