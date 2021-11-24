/* SPDX-License-Identifier: MIT */
/* based on linux-kernel/tools/testing/selftests/net/msg_zerocopy.c */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <error.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include <arpa/inet.h>
#include <linux/errqueue.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "helpers.h"
#include "liburing.h"
#include "../src/syscall.h"

#ifndef SO_ZEROCOPY
#define SO_ZEROCOPY	60
#endif
#define ZC_TAG 1366

static bool fixed_files;
static bool zc;
static bool flush;
static int nr_reqs;
static bool fixed_buf;

static int  cfg_family		= PF_UNSPEC;
static int  cfg_payload_len;
static int  cfg_port		= 8000;
static int  cfg_runtime_ms	= 4200;

static socklen_t cfg_alen;
static struct sockaddr_storage cfg_dst_addr;

static char payload[IP_MAXPACKET] __attribute__((aligned(4096)));

static unsigned long gettimeofday_ms(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

static void do_setsockopt(int fd, int level, int optname, int val)
{
	if (setsockopt(fd, level, optname, &val, sizeof(val)))
		error(1, errno, "setsockopt %d.%d: %d", level, optname, val);
}

static void setup_sockaddr(int domain, const char *str_addr,
			   struct sockaddr_storage *sockaddr)
{
	struct sockaddr_in6 *addr6 = (void *) sockaddr;
	struct sockaddr_in *addr4 = (void *) sockaddr;

	switch (domain) {
	case PF_INET:
		memset(addr4, 0, sizeof(*addr4));
		addr4->sin_family = AF_INET;
		addr4->sin_port = htons(cfg_port);
		if (str_addr &&
		    inet_pton(AF_INET, str_addr, &(addr4->sin_addr)) != 1)
			error(1, 0, "ipv4 parse error: %s", str_addr);
		break;
	case PF_INET6:
		memset(addr6, 0, sizeof(*addr6));
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = htons(cfg_port);
		if (str_addr &&
		    inet_pton(AF_INET6, str_addr, &(addr6->sin6_addr)) != 1)
			error(1, 0, "ipv6 parse error: %s", str_addr);
		break;
	default:
		error(1, 0, "illegal domain");
	}
}

static int do_setup_tx(int domain, int type, int protocol)
{
	int fd;

	fd = socket(domain, type, protocol);
	if (fd == -1)
		error(1, errno, "socket t");

	do_setsockopt(fd, SOL_SOCKET, SO_SNDBUF, 1 << 21);
	do_setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, 1);

	if (connect(fd, (void *) &cfg_dst_addr, cfg_alen))
		error(1, errno, "connect");
	return fd;
}

static inline struct io_uring_cqe *wait_cqe_fast(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	unsigned head;
	int ret;

	io_uring_for_each_cqe(ring, head, cqe)
		return cqe;

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret)
		error(1, ret, "wait cqe");
	return cqe;
}

static void do_tx(int domain, int type, int protocol)
{
	unsigned long seq = 0, eagain_reqs = 0, packets = 0, bytes = 0;
	struct io_uring ring;
	struct iovec iov;
	uint64_t tstop;
	int i, fd, ret;

	fd = do_setup_tx(domain, type, protocol);

	ret = io_uring_queue_init(512, &ring, 0);
	if (ret)
		error(1, ret, "io_uring: queue init");

	struct io_uring_tx_ctx_register r = { .tag = ZC_TAG, };
	ret = ____sys_io_uring_register(ring.ring_fd, IORING_REGISTER_TX_CTX, (void *)&r, 1);
	if (ret)
		error(1, ret, "io_uring: tx ctx registration");

	ret = io_uring_register_files(&ring, &fd, 1);
	if (ret < 0)
		error(1, ret, "io_uring: files registration");

	iov.iov_base = payload;
	iov.iov_len = cfg_payload_len;
	ret = t_register_buffers(&ring, &iov, 1);
	if (ret != T_SETUP_OK)
		error(1, ret, "io_uring: buffer registration");

	tstop = gettimeofday_ms() + cfg_runtime_ms;
	do {
		struct io_uring_sqe *sqe;
		struct io_uring_cqe *cqe;
		int nr_cqes = flush ? nr_reqs * 2 : nr_reqs;

		for (i = 0; i < nr_reqs; i++) {
			sqe = io_uring_get_sqe(&ring);
			io_uring_prep_send(sqe, fd, payload, cfg_payload_len, MSG_DONTWAIT);
			sqe->user_data = 1;
			if (fixed_files) {
				sqe->fd = 0;
				sqe->flags = IOSQE_FIXED_FILE;
			}

			if (zc) {
				sqe->opcode = IORING_OP_SENDZC;
				sqe->tx_ctx_idx = 0;
				sqe->ioprio = 0;
				sqe->off = 0;
				sqe->__pad2[0] = 0;

				if (flush)
					sqe->ioprio |= IORING_SENDZC_FLUSH;
				if (fixed_buf) {
					sqe->ioprio |= IORING_SENDZC_FIXED_BUF;
					sqe->buf_index = 0;
				}
			}
		}

		ret = io_uring_submit(&ring);
		if (ret != nr_reqs)
			error(1, ret, "submit");

		for (i = 0; i < nr_cqes; i++) {
			cqe = wait_cqe_fast(&ring);

			if (cqe->user_data == ZC_TAG) {
				if (seq != cqe->res)
					error(1, -EINVAL, "sequences don't match %u!=%u",
						(int)seq, cqe->res);
				seq++;
			} else if (cqe->user_data == 1) {
				if (cqe->res > 0) {
					packets++;
					bytes += cqe->res;
				} else if (cqe->res == -EAGAIN) {
					if (flush)
						nr_cqes--;
					eagain_reqs++;
				} else {
					error(1, cqe->res, "send ret");
				}
			} else {
				error(1, cqe->user_data, "user_data");
			}

			io_uring_cqe_seen(&ring, cqe);
		}
	} while (gettimeofday_ms() < tstop);

	if (close(fd))
		error(1, errno, "close");

	fprintf(stderr, "tx=%lu (%lu MB) txc=%lu, nr EAGAIN=%lu\n",
		packets, bytes >> 20, seq, eagain_reqs);

	io_uring_queue_exit(&ring);
}

static void do_test(int domain, int type, int protocol)
{
	int i;

	for (i = 0; i < IP_MAXPACKET; i++)
		payload[i] = 'a' + (i % 26);

	do_tx(domain, type, protocol);
}

static void usage(const char *filepath)
{
	error(1, 0, "Usage: %s [options] <test>", filepath);
}

static void parse_opts(int argc, char **argv)
{
	const int max_payload_len = sizeof(payload) -
				    sizeof(struct ipv6hdr) -
				    sizeof(struct tcphdr) -
				    40 /* max tcp options */;
	int c;
	char *daddr = NULL;

	cfg_payload_len = max_payload_len;

	fixed_files = 1;
	zc = 1;
	flush = 0 && zc;
	nr_reqs = 8;
	fixed_buf = 1 && zc;

	while ((c = getopt(argc, argv, "46D:i:p:s:t:n:r:f")) != -1) {
		switch (c) {
		case '4':
			if (cfg_family != PF_UNSPEC)
				error(1, 0, "Pass one of -4 or -6");
			cfg_family = PF_INET;
			cfg_alen = sizeof(struct sockaddr_in);
			break;
		case '6':
			if (cfg_family != PF_UNSPEC)
				error(1, 0, "Pass one of -4 or -6");
			cfg_family = PF_INET6;
			cfg_alen = sizeof(struct sockaddr_in6);
			break;
		case 'D':
			daddr = optarg;
			break;
		case 'p':
			cfg_port = strtoul(optarg, NULL, 0);
			break;
		case 's':
			cfg_payload_len = strtoul(optarg, NULL, 0);
			break;
		case 't':
			cfg_runtime_ms = 200 + strtoul(optarg, NULL, 10) * 1000;
			break;
		case 'n':
		case 'r':
			nr_reqs = strtoul(optarg, NULL, 0);
			break;
		case 'f':
			flush = 1;
			break;
		}
	}

	if (cfg_family == PF_INET6 && zc)
		error(1, 0, "zc IPv6 is not supported");
	if (flush && !zc)
		error(1, 0, "Flush should be used with zc only");

	setup_sockaddr(cfg_family, daddr, &cfg_dst_addr);

	if (cfg_payload_len > max_payload_len)
		error(1, 0, "-s: payload exceeds max (%d)", max_payload_len);

	if (optind != argc - 1)
		usage(argv[0]);
}

int main(int argc, char **argv)
{
	const char *cfg_test;

	parse_opts(argc, argv);

	cfg_test = argv[argc - 1];

	if (!strcmp(cfg_test, "raw"))
		do_test(cfg_family, SOCK_RAW, IPPROTO_EGP);
	else if (!strcmp(cfg_test, "tcp"))
		do_test(cfg_family, SOCK_STREAM, 0);
	else if (!strcmp(cfg_test, "udp"))
		do_test(cfg_family, SOCK_DGRAM, 0);
	else
		error(1, 0, "unknown cfg_test %s", cfg_test);

	return 0;
}
