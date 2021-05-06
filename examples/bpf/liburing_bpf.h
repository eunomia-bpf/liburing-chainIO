#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

typedef size_t socklen_t;
typedef unsigned short mode_t;

#ifndef ARRAY_SIZE
	#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#endif

#ifndef uring_unlikely
#  define uring_unlikely(cond)      __builtin_expect(!!(cond), 0)
#endif

#ifndef uring_likely
#  define uring_likely(cond)        __builtin_expect(!!(cond), 1)
#endif

/*
 * sqe->flags
 */
/* use fixed fileset */
#define IOSQE_FIXED_FILE	(1U << IOSQE_FIXED_FILE_BIT)
/* issue after inflight IO */
#define IOSQE_IO_DRAIN		(1U << IOSQE_IO_DRAIN_BIT)
/* links next sqe */
#define IOSQE_IO_LINK		(1U << IOSQE_IO_LINK_BIT)
/* like LINK, but stronger */
#define IOSQE_IO_HARDLINK	(1U << IOSQE_IO_HARDLINK_BIT)
/* always go async */
#define IOSQE_ASYNC		(1U << IOSQE_ASYNC_BIT)
/* select buffer from sqe->buf_group */
#define IOSQE_BUFFER_SELECT	(1U << IOSQE_BUFFER_SELECT_BIT)

/*
 * io_uring_setup() flags
 */
#define IORING_SETUP_IOPOLL	(1U << 0)	/* io_context is polled */
#define IORING_SETUP_SQPOLL	(1U << 1)	/* SQ poll thread */
#define IORING_SETUP_SQ_AFF	(1U << 2)	/* sq_thread_cpu is valid */
#define IORING_SETUP_CQSIZE	(1U << 3)	/* app defines CQ size */
#define IORING_SETUP_CLAMP	(1U << 4)	/* clamp SQ/CQ ring sizes */
#define IORING_SETUP_ATTACH_WQ	(1U << 5)	/* attach to existing wq */
#define IORING_SETUP_R_DISABLED	(1U << 6)	/* start with ring disabled */

/*
 * sqe->fsync_flags
 */
#define IORING_FSYNC_DATASYNC	(1U << 0)

/*
 * sqe->timeout_flags
 */
#define IORING_TIMEOUT_ABS		(1U << 0)
#define IORING_TIMEOUT_UPDATE		(1U << 1)
#define IORING_TIMEOUT_BOOTTIME		(1U << 2)
#define IORING_TIMEOUT_REALTIME		(1U << 3)
#define IORING_LINK_TIMEOUT_UPDATE	(1U << 4)
#define IORING_TIMEOUT_CLOCK_MASK	(IORING_TIMEOUT_BOOTTIME | IORING_TIMEOUT_REALTIME)
#define IORING_TIMEOUT_UPDATE_MASK	(IORING_TIMEOUT_UPDATE | IORING_LINK_TIMEOUT_UPDATE)
/*
 * sqe->splice_flags
 * extends splice(2) flags
 */
#define SPLICE_F_FD_IN_FIXED	(1U << 31) /* the last bit of __u32 */

/*
 * POLL_ADD flags. Note that since sqe->poll_events is the flag space, the
 * command flags for POLL_ADD are stored in sqe->len.
 *
 * IORING_POLL_ADD_MULTI	Multishot poll. Sets IORING_CQE_F_MORE if
 *				the poll handler will continue to report
 *				CQEs on behalf of the same SQE.
 *
 * IORING_POLL_UPDATE		Update existing poll request, matching
 *				sqe->addr as the old user_data field.
 */
#define IORING_POLL_ADD_MULTI	(1U << 0)
#define IORING_POLL_UPDATE_EVENTS	(1U << 1)
#define IORING_POLL_UPDATE_USER_DATA	(1U << 2)

/*
 * cqe->flags
 *
 * IORING_CQE_F_BUFFER	If set, the upper 16 bits are the buffer ID
 * IORING_CQE_F_MORE	If set, parent SQE will generate more CQE entries
 */
#define IORING_CQE_F_BUFFER		(1U << 0)
#define IORING_CQE_F_MORE		(1U << 1)

/*
 * Magic offsets for the application to mmap the data it needs
 */
#define IORING_OFF_SQ_RING		0ULL
#define IORING_OFF_CQ_RING		0x8000000ULL
#define IORING_OFF_SQES			0x10000000ULL
#define IORING_OFF_CQ_RING_EXTRA	0x1200000ULL
#define IORING_STRIDE_CQ_RING		0x0100000ULL

/*
 * sq_ring->flags
 */
#define IORING_SQ_NEED_WAKEUP	(1U << 0) /* needs io_uring_enter wakeup */
#define IORING_SQ_CQ_OVERFLOW	(1U << 1) /* CQ ring is overflown */

/*
 * cq_ring->flags
 */

/* disable eventfd notifications */
#define IORING_CQ_EVENTFD_DISABLED	(1U << 0)

/*
 * io_uring_enter(2) flags
 */
#define IORING_ENTER_GETEVENTS	(1U << 0)
#define IORING_ENTER_SQ_WAKEUP	(1U << 1)
#define IORING_ENTER_SQ_WAIT	(1U << 2)
#define IORING_ENTER_EXT_ARG	(1U << 3)

/*
 * io_uring_params->features flags
 */
#define IORING_FEAT_SINGLE_MMAP		(1U << 0)
#define IORING_FEAT_NODROP		(1U << 1)
#define IORING_FEAT_SUBMIT_STABLE	(1U << 2)
#define IORING_FEAT_RW_CUR_POS		(1U << 3)
#define IORING_FEAT_CUR_PERSONALITY	(1U << 4)
#define IORING_FEAT_FAST_POLL		(1U << 5)
#define IORING_FEAT_POLL_32BITS 	(1U << 6)
#define IORING_FEAT_SQPOLL_NONFIXED	(1U << 7)
#define IORING_FEAT_EXT_ARG		(1U << 8)
#define IORING_FEAT_NATIVE_WORKERS	(1U << 9)
#define IORING_FEAT_RSRC_TAGS		(1U << 10)

/* Skip updating fd indexes set to this value in the fd table */
#define IORING_REGISTER_FILES_SKIP	(-2)

#define IO_URING_OP_SUPPORTED	(1U << 0)

/*
 * Command prep helpers
 */
static inline void io_uring_sqe_set_data(struct io_uring_sqe *sqe, void *data)
{
	sqe->user_data = (unsigned long) data;
}

static inline void *io_uring_cqe_get_data(const struct io_uring_cqe *cqe)
{
	return (void *) (uintptr_t) cqe->user_data;
}

static inline void io_uring_sqe_set_flags(struct io_uring_sqe *sqe,
					  unsigned flags)
{
	sqe->flags = (__u8) flags;
}

static inline void __io_uring_set_target_fixed_file(struct io_uring_sqe *sqe,
						    unsigned int file_index)
{
	/* 0 means no fixed files, indexes should be encoded as "index + 1" */
	sqe->file_index = file_index + 1;
}

static inline void io_uring_prep_rw(int op, struct io_uring_sqe *sqe, int fd,
				    const void *addr, unsigned len,
				    __u64 offset)
{
	sqe->opcode = (__u8) op;
	sqe->flags = 0;
	sqe->ioprio = 0;
	sqe->fd = fd;
	sqe->off = offset;
	sqe->addr = (unsigned long) addr;
	sqe->len = len;
	sqe->rw_flags = 0;
	sqe->user_data = 0;
	sqe->buf_index = 0;
	sqe->personality = 0;
	sqe->file_index = 0;
	sqe->cq_idx = 0;
	sqe->__pad1 = 0;
	sqe->__pad2 = 0;
	sqe->__pad3 = 0;
}

/**
 * @pre Either fd_in or fd_out must be a pipe.
 * @param off_in If fd_in refers to a pipe, off_in must be (int64_t) -1;
 *               If fd_in does not refer to a pipe and off_in is (int64_t) -1, then bytes are read
 *               from fd_in starting from the file offset and it is adjust appropriately;
 *               If fd_in does not refer to a pipe and off_in is not (int64_t) -1, then the
 *               starting offset of fd_in will be off_in.
 * @param off_out The description of off_in also applied to off_out.
 * @param splice_flags see man splice(2) for description of flags.
 *
 * This splice operation can be used to implement sendfile by splicing to an intermediate pipe
 * first, then splice to the final destination.
 * In fact, the implementation of sendfile in kernel uses splice internally.
 *
 * NOTE that even if fd_in or fd_out refers to a pipe, the splice operation can still failed with
 * EINVAL if one of the fd doesn't explicitly support splice operation, e.g. reading from terminal
 * is unsupported from kernel 5.7 to 5.11.
 * Check issue #291 for more information.
 */
static inline void io_uring_prep_splice(struct io_uring_sqe *sqe,
					int fd_in, int64_t off_in,
					int fd_out, int64_t off_out,
					unsigned int nbytes,
					unsigned int splice_flags)
{
	io_uring_prep_rw(IORING_OP_SPLICE, sqe, fd_out, NULL, nbytes,
				(__u64) off_out);
	sqe->splice_off_in = (__u64) off_in;
	sqe->splice_fd_in = fd_in;
	sqe->splice_flags = splice_flags;
}

static inline void io_uring_prep_tee(struct io_uring_sqe *sqe,
				     int fd_in, int fd_out,
				     unsigned int nbytes,
				     unsigned int splice_flags)
{
	io_uring_prep_rw(IORING_OP_TEE, sqe, fd_out, NULL, nbytes, 0);
	sqe->splice_off_in = 0;
	sqe->splice_fd_in = fd_in;
	sqe->splice_flags = splice_flags;
}

static inline void io_uring_prep_readv(struct io_uring_sqe *sqe, int fd,
				       const struct iovec *iovecs,
				       unsigned nr_vecs, __u64 offset)
{
	io_uring_prep_rw(IORING_OP_READV, sqe, fd, iovecs, nr_vecs, offset);
}

static inline void io_uring_prep_read_fixed(struct io_uring_sqe *sqe, int fd,
					    void *buf, unsigned nbytes,
					    __u64 offset, int buf_index)
{
	io_uring_prep_rw(IORING_OP_READ_FIXED, sqe, fd, buf, nbytes, offset);
	sqe->buf_index = (__u16) buf_index;
}

static inline void io_uring_prep_writev(struct io_uring_sqe *sqe, int fd,
					const struct iovec *iovecs,
					unsigned nr_vecs, __u64 offset)
{
	io_uring_prep_rw(IORING_OP_WRITEV, sqe, fd, iovecs, nr_vecs, offset);
}

static inline void io_uring_prep_write_fixed(struct io_uring_sqe *sqe, int fd,
					     const void *buf, unsigned nbytes,
					     __u64 offset, int buf_index)
{
	io_uring_prep_rw(IORING_OP_WRITE_FIXED, sqe, fd, buf, nbytes, offset);
	sqe->buf_index = (__u16) buf_index;
}

static inline void io_uring_prep_recvmsg(struct io_uring_sqe *sqe, int fd,
					 struct msghdr *msg, unsigned flags)
{
	io_uring_prep_rw(IORING_OP_RECVMSG, sqe, fd, msg, 1, 0);
	sqe->msg_flags = flags;
}

static inline void io_uring_prep_sendmsg(struct io_uring_sqe *sqe, int fd,
					 const struct msghdr *msg, unsigned flags)
{
	io_uring_prep_rw(IORING_OP_SENDMSG, sqe, fd, msg, 1, 0);
	sqe->msg_flags = flags;
}

static inline unsigned __io_uring_prep_poll_mask(unsigned poll_mask)
{
#if __BYTE_ORDER == __BIG_ENDIAN
	poll_mask = __swahw32(poll_mask);
#endif
	return poll_mask;
}

static inline void io_uring_prep_poll_add(struct io_uring_sqe *sqe, int fd,
					  unsigned poll_mask)
{
	io_uring_prep_rw(IORING_OP_POLL_ADD, sqe, fd, NULL, 0, 0);
	sqe->poll32_events = __io_uring_prep_poll_mask(poll_mask);
}

static inline void io_uring_prep_poll_multishot(struct io_uring_sqe *sqe,
						int fd, unsigned poll_mask)
{
	io_uring_prep_poll_add(sqe, fd, poll_mask);
	sqe->len = IORING_POLL_ADD_MULTI;
}

static inline void io_uring_prep_poll_remove(struct io_uring_sqe *sqe,
					     void *user_data)
{
	io_uring_prep_rw(IORING_OP_POLL_REMOVE, sqe, -1, user_data, 0, 0);
}

static inline void io_uring_prep_poll_update(struct io_uring_sqe *sqe,
					     void *old_user_data,
					     void *new_user_data,
					     unsigned poll_mask, unsigned flags)
{
	io_uring_prep_rw(IORING_OP_POLL_REMOVE, sqe, -1, old_user_data, flags,
			 (__u64)(uintptr_t)new_user_data);
	sqe->poll32_events = __io_uring_prep_poll_mask(poll_mask);
}

static inline void io_uring_prep_fsync(struct io_uring_sqe *sqe, int fd,
				       unsigned fsync_flags)
{
	io_uring_prep_rw(IORING_OP_FSYNC, sqe, fd, NULL, 0, 0);
	sqe->fsync_flags = fsync_flags;
}

static inline void io_uring_prep_nop(struct io_uring_sqe *sqe)
{
	io_uring_prep_rw(IORING_OP_NOP, sqe, -1, NULL, 0, 0);
}

static inline void io_uring_prep_timeout(struct io_uring_sqe *sqe,
					 struct __kernel_timespec *ts,
					 unsigned count, unsigned flags)
{
	io_uring_prep_rw(IORING_OP_TIMEOUT, sqe, -1, ts, 1, count);
	sqe->timeout_flags = flags;
}

static inline void io_uring_prep_timeout_remove(struct io_uring_sqe *sqe,
						__u64 user_data, unsigned flags)
{
	io_uring_prep_rw(IORING_OP_TIMEOUT_REMOVE, sqe, -1,
				(void *)(unsigned long)user_data, 0, 0);
	sqe->timeout_flags = flags;
}

static inline void io_uring_prep_timeout_update(struct io_uring_sqe *sqe,
						struct __kernel_timespec *ts,
						__u64 user_data, unsigned flags)
{
	io_uring_prep_rw(IORING_OP_TIMEOUT_REMOVE, sqe, -1,
				(void *)(unsigned long)user_data, 0,
				(uintptr_t)ts);
	sqe->timeout_flags = flags | IORING_TIMEOUT_UPDATE;
}

static inline void io_uring_prep_accept(struct io_uring_sqe *sqe, int fd,
					struct sockaddr *addr,
					socklen_t *addrlen, int flags)
{
	io_uring_prep_rw(IORING_OP_ACCEPT, sqe, fd, addr, 0,
				(__u64) (unsigned long) addrlen);
	sqe->accept_flags = (__u32) flags;
}

/* accept directly into the fixed file table */
static inline void io_uring_prep_accept_direct(struct io_uring_sqe *sqe, int fd,
					       struct sockaddr *addr,
					       socklen_t *addrlen, int flags,
					       unsigned int file_index)
{
	io_uring_prep_accept(sqe, fd, addr, addrlen, flags);
	__io_uring_set_target_fixed_file(sqe, file_index);
}

static inline void io_uring_prep_cancel(struct io_uring_sqe *sqe, void *user_data,
					int flags)
{
	io_uring_prep_rw(IORING_OP_ASYNC_CANCEL, sqe, -1, user_data, 0, 0);
	sqe->cancel_flags = (__u32) flags;
}

static inline void io_uring_prep_link_timeout(struct io_uring_sqe *sqe,
					      struct __kernel_timespec *ts,
					      unsigned flags)
{
	io_uring_prep_rw(IORING_OP_LINK_TIMEOUT, sqe, -1, ts, 1, 0);
	sqe->timeout_flags = flags;
}

static inline void io_uring_prep_connect(struct io_uring_sqe *sqe, int fd,
					 const struct sockaddr *addr,
					 socklen_t addrlen)
{
	io_uring_prep_rw(IORING_OP_CONNECT, sqe, fd, addr, 0, addrlen);
}

static inline void io_uring_prep_files_update(struct io_uring_sqe *sqe,
					      int *fds, unsigned nr_fds,
					      int offset)
{
	io_uring_prep_rw(IORING_OP_FILES_UPDATE, sqe, -1, fds, nr_fds,
				(__u64) offset);
}

static inline void io_uring_prep_fallocate(struct io_uring_sqe *sqe, int fd,
					   int mode, off_t offset, off_t len)
{

	io_uring_prep_rw(IORING_OP_FALLOCATE, sqe, fd,
			(const uintptr_t *) (unsigned long) len,
			(unsigned int) mode, (__u64) offset);
}

static inline void io_uring_prep_openat(struct io_uring_sqe *sqe, int dfd,
					const char *path, int flags, mode_t mode)
{
	io_uring_prep_rw(IORING_OP_OPENAT, sqe, dfd, path, mode, 0);
	sqe->open_flags = (__u32) flags;
}

/* open directly into the fixed file table */
static inline void io_uring_prep_openat_direct(struct io_uring_sqe *sqe,
					       int dfd, const char *path,
					       int flags, mode_t mode,
					       unsigned file_index)
{
	io_uring_prep_openat(sqe, dfd, path, flags, mode);
	__io_uring_set_target_fixed_file(sqe, file_index);
}


static inline void io_uring_prep_close(struct io_uring_sqe *sqe, int fd)
{
	io_uring_prep_rw(IORING_OP_CLOSE, sqe, fd, NULL, 0, 0);
}

static inline void io_uring_prep_read(struct io_uring_sqe *sqe, int fd,
				      void *buf, unsigned nbytes, __u64 offset)
{
	io_uring_prep_rw(IORING_OP_READ, sqe, fd, buf, nbytes, offset);
}

static inline void io_uring_prep_write(struct io_uring_sqe *sqe, int fd,
				       const void *buf, unsigned nbytes, __u64 offset)
{
	io_uring_prep_rw(IORING_OP_WRITE, sqe, fd, buf, nbytes, offset);
}

struct statx;
static inline void io_uring_prep_statx(struct io_uring_sqe *sqe, int dfd,
				const char *path, int flags, unsigned mask,
				struct statx *statxbuf)
{
	io_uring_prep_rw(IORING_OP_STATX, sqe, dfd, path, mask,
				(__u64) (unsigned long) statxbuf);
	sqe->statx_flags = (__u32) flags;
}

static inline void io_uring_prep_fadvise(struct io_uring_sqe *sqe, int fd,
					 __u64 offset, off_t len, int advice)
{
	io_uring_prep_rw(IORING_OP_FADVISE, sqe, fd, NULL, (__u32) len, offset);
	sqe->fadvise_advice = (__u32) advice;
}

static inline void io_uring_prep_madvise(struct io_uring_sqe *sqe, void *addr,
					 off_t length, int advice)
{
	io_uring_prep_rw(IORING_OP_MADVISE, sqe, -1, addr, (__u32) length, 0);
	sqe->fadvise_advice = (__u32) advice;
}

static inline void io_uring_prep_send(struct io_uring_sqe *sqe, int sockfd,
				      const void *buf, size_t len, int flags)
{
	io_uring_prep_rw(IORING_OP_SEND, sqe, sockfd, buf, (__u32) len, 0);
	sqe->msg_flags = (__u32) flags;
}

static inline void io_uring_prep_recv(struct io_uring_sqe *sqe, int sockfd,
				      void *buf, size_t len, int flags)
{
	io_uring_prep_rw(IORING_OP_RECV, sqe, sockfd, buf, (__u32) len, 0);
	sqe->msg_flags = (__u32) flags;
}

static inline void io_uring_prep_openat2(struct io_uring_sqe *sqe, int dfd,
					const char *path, struct open_how *how)
{
	io_uring_prep_rw(IORING_OP_OPENAT2, sqe, dfd, path, sizeof(*how),
				(uint64_t) (uintptr_t) how);
}

/* open directly into the fixed file table */
static inline void io_uring_prep_openat2_direct(struct io_uring_sqe *sqe,
						int dfd, const char *path,
						struct open_how *how,
						unsigned file_index)
{
	io_uring_prep_openat2(sqe, dfd, path, how);
	__io_uring_set_target_fixed_file(sqe, file_index);
}

struct epoll_event;
static inline void io_uring_prep_epoll_ctl(struct io_uring_sqe *sqe, int epfd,
					   int fd, int op,
					   struct epoll_event *ev)
{
	io_uring_prep_rw(IORING_OP_EPOLL_CTL, sqe, epfd, ev,
				(__u32) op, (__u32) fd);
}

static inline void io_uring_prep_provide_buffers(struct io_uring_sqe *sqe,
						 void *addr, int len, int nr,
						 int bgid, int bid)
{
	io_uring_prep_rw(IORING_OP_PROVIDE_BUFFERS, sqe, nr, addr, (__u32) len,
				(__u64) bid);
	sqe->buf_group = (__u16) bgid;
}

static inline void io_uring_prep_remove_buffers(struct io_uring_sqe *sqe,
						int nr, int bgid)
{
	io_uring_prep_rw(IORING_OP_REMOVE_BUFFERS, sqe, nr, NULL, 0, 0);
	sqe->buf_group = (__u16) bgid;
}

static inline void io_uring_prep_shutdown(struct io_uring_sqe *sqe, int fd,
					  int how)
{
	io_uring_prep_rw(IORING_OP_SHUTDOWN, sqe, fd, NULL, (__u32) how, 0);
}

static inline void io_uring_prep_unlinkat(struct io_uring_sqe *sqe, int dfd,
					  const char *path, int flags)
{
	io_uring_prep_rw(IORING_OP_UNLINKAT, sqe, dfd, path, 0, 0);
	sqe->unlink_flags = (__u32) flags;
}

static inline void io_uring_prep_renameat(struct io_uring_sqe *sqe, int olddfd,
					  const char *oldpath, int newdfd,
					  const char *newpath, int flags)
{
	io_uring_prep_rw(IORING_OP_RENAMEAT, sqe, olddfd, oldpath, (__u32) newdfd,
				(uint64_t) (uintptr_t) newpath);
	sqe->rename_flags = (__u32) flags;
}

static inline void io_uring_prep_sync_file_range(struct io_uring_sqe *sqe,
						 int fd, unsigned len,
						 __u64 offset, int flags)
{
	io_uring_prep_rw(IORING_OP_SYNC_FILE_RANGE, sqe, fd, NULL, len, offset);
	sqe->sync_range_flags = (__u32) flags;
}
