#include <arpa/inet.h> // debugging
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <liburing.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>

// TODO: use fixed buffers? https://unixism.net/loti/tutorial/fixed_buffers.html

typedef struct io_uring go_uring;
typedef struct msghdr go_msghdr;
typedef struct iovec go_iovec;
typedef struct sockaddr_in go_sockaddr_in;
typedef struct io_uring_params go_io_uring_params;

static int initialize(struct io_uring *ring, int fd) {
	struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    // POLL
    // params.flags |= IORING_SETUP_SQPOLL;
    // params.sq_thread_idle = 1000; // 1s
    int ret;
    ret = io_uring_queue_init_params(16, ring, &params); // 16: size of ring
    if (ret < 0) {
        return ret;
    }
    ret = io_uring_register_files(ring, &fd, 1);
    // TODO: Do we need to unregister files on close, or is Closing the uring enough?
    perror("io_uring_queue_init");
    if (ret < 0) {
        return ret;
    }
    return 0;
}

// packNIdx packs a returned n (usually number of bytes) and a index into a request array into a 63-bit uint64.
static uint64_t packNIdx(int n, size_t idx) {
    uint64_t idx64 = idx & 0xFFFFFFFF; // truncate to 32 bits, just to be careful (should never be larger than 8)
    uint64_t n64 = n & 0x7FFFFFFF; // truncate to 31 bits, just to be careful (should never be larger than 65544, max UDP write + IP header)
    return (n64 << 32) | idx64;
}

// Wait for a completion to be available, fetch the data
static uint64_t receive_into_udp(struct io_uring *ring) {
    struct io_uring_cqe *cqe;
again:;

    int ret = io_uring_wait_cqe(ring, &cqe);
    if (ret == -EINTR) {
        goto again;
    }
    // TODO: Delete perror, fprintf, etc.
    // Encode in return value or similar.
    if (ret < 0) {
        perror("io_uring_wait_cqe");
        return ret;
    }
    int n = cqe->res;
    if (n < 0) {
        // TODO: this leaks a buffer!!!!
        fprintf(stderr, "recvmsg failed: %d.\n", n);
        return n;
    }
    size_t idx = (size_t)io_uring_cqe_get_data(cqe);
    uint64_t nidx = packNIdx(n, idx);
    io_uring_cqe_seen(ring, cqe);
    return nidx;
}

static uint32_t ip(struct sockaddr_in *sa) {
    return ntohl(sa->sin_addr.s_addr);
}

static uint16_t port(struct sockaddr_in *sa) {
    return ntohs(sa->sin_port);
}

// submit a recvmsg request via liburing
// TODO: What recvfrom support arrives, maybe use that instead?
static int submit_recvmsg_request(struct io_uring *ring, struct msghdr *mhdr, struct iovec *iov, struct sockaddr_in *sender, char *buf, int buflen, size_t idx) {
    iov->iov_base = buf;
    iov->iov_len = buflen;

    mhdr->msg_iov = iov;
    mhdr->msg_iovlen = 1;

    mhdr->msg_name = sender;
    mhdr->msg_namelen = sizeof(struct sockaddr_in);

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_recvmsg(sqe, 0, mhdr, 0); // use the 0th file in the list of registered fds
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    io_uring_sqe_set_data(sqe, (void *)(idx));
    io_uring_submit(ring);
    return 0;
}

static void submit_nop_request(struct io_uring *ring) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	io_uring_prep_nop(sqe);
    io_uring_sqe_set_data(sqe, (void *)(-1));
    io_uring_submit(ring);
}

// Wait for a completion to be available, fetch the data
// TODO: unify with receive_into_udp
static uint64_t get_file_completion(struct io_uring *ring) {
    struct io_uring_cqe *cqe;
again:;

    int ret = io_uring_wait_cqe(ring, &cqe);
    if (ret == -EINTR) {
        goto again;
    }
    // TODO: Delete perror, fprintf, etc.
    // Encode in return value or similar.
    if (ret < 0) {
        perror("get_file_completion io_uring_wait_cqe");
        return ret;
    }
    int n = cqe->res;
    if (n < 0) {
        // TODO: This leaks a buffer!!!
        fprintf(stderr, "get_file_completion write failed: %d.\n", n);
        return n;
    }
    size_t idx = (size_t)io_uring_cqe_get_data(cqe);
    uint64_t nidx = packNIdx(n, idx);
    io_uring_cqe_seen(ring, cqe);
    return nidx;
}

// submit a write request via liburing
static int submit_write_request(struct io_uring *ring, char *buf, int buflen, size_t idx, struct iovec *iov) {
    // fprintf(stderr, "submit_write_request to fd %d buf %p %s buflen %d idx %lu\n", fd, buf, buf, buflen, idx);
    // errno= 0;
    // perror("before bonus write");
    // int x = write(fd, buf, buflen);
    // fprintf(stderr, "plain write returned %d\n", x);
    // perror("submit_write_request bonus write");
    iov->iov_base = buf;
    iov->iov_len = buflen;

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_writev(sqe, 0, iov, 1, 0); // use the 0th file in the list of registered fds
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    io_uring_sqe_set_data(sqe, (void *)(idx));
    int submitted = io_uring_submit(ring);
    // fprintf(stderr, "submitted %d sqes\n", submitted);
    return 0;
}

// TODO: unify with get_file_completion
static uint64_t peek_file_completion(struct io_uring *ring) {
    struct io_uring_cqe *cqe;
    int ret = io_uring_peek_cqe(ring, &cqe);
    // perror("on entry, peek_file_completion io_uring_wait_cqe");
    if ((-ret == EAGAIN) || (-ret == EINTR)) {
        return ret;
    }
    // TODO: Delete perror, fprintf, etc.
    // Encode in return value or similar.
    if (ret < 0) {
        perror("on failure, peek_file_completion io_uring_wait_cqe");
        return ret;
    }
    errno = 0;
    int n = cqe->res;
    if (n < 0) {
        // TODO: This leaks a buffer!!!
        fprintf(stderr, "peek_file_completion write failed: %d.\n", n);
        return n;
    }
    size_t idx = (size_t)io_uring_cqe_get_data(cqe);
    uint64_t nidx = packNIdx(n, idx);
    io_uring_cqe_seen(ring, cqe);
    return nidx;
}
