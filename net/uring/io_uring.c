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
    int ret = io_uring_queue_init(16, ring, 0); // 16: size of ring
    if (ret < 0) {
        return ret;
    }
    ret = io_uring_register_files(ring, &fd, 1);
    // TODO: Do we need to unregister files on close, or is Closing the uring enough?
    if (ret < 0) {
        perror("io_uring_queue_init");
        return ret;
    }
    return 0;
}

struct req {
    struct msghdr hdr;
	struct iovec iov;
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    char *buf;
};

typedef struct req goreq;

static struct req *initializeReq(size_t sz, int ipVersion) {
    struct req *r = malloc(sizeof(struct req));
    memset(r, 0, sizeof(*r));
    r->buf = malloc(sz);
    memset(r->buf, 0, sz);
    r->iov.iov_base = r->buf;
    r->iov.iov_len = sz;
    r->hdr.msg_iov = &r->iov;
    r->hdr.msg_iovlen = 1;
    switch(ipVersion) {
        case 4:
            r->hdr.msg_name = &r->sa;
            r->hdr.msg_namelen = sizeof(r->sa);
            break;
        case 6:
            r->hdr.msg_name = &r->sa6;
            r->hdr.msg_namelen = sizeof(r->sa6);
            break;
    }
    return r;
}

static void freeReq(struct req *r) {
    free(r->buf);
    free(r);
}

// packNIdx packs a returned n (usually number of bytes) and a index into a request array into a 63-bit uint64.
static uint64_t packNIdx(int n, size_t idx) {
    uint64_t idx64 = idx & 0xFFFFFFFF; // truncate to 32 bits, just to be careful (should never be larger than 8)
    uint64_t n64 = n & 0x7FFFFFFF; // truncate to 31 bits, just to be careful (should never be larger than 65544, max UDP write + IP header)
    return (n64 << 32) | idx64;
}

// submit a recvmsg request via liburing
// TODO: What recvfrom support arrives, maybe use that instead?
static int submit_recvmsg_request(struct io_uring *ring, struct req *r, size_t idx) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_recvmsg(sqe, 0, &r->hdr, 0); // use the 0th file in the list of registered fds
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    io_uring_sqe_set_data(sqe, (void *)(idx));
    io_uring_submit(ring);
    return 0;
}

// submit a recvmsg request via liburing
// TODO: What recvfrom support arrives, maybe use that instead?
static int submit_sendmsg_request(struct io_uring *ring, struct req *r, int buflen, size_t idx) {
    r->iov.iov_len = buflen;
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_sendmsg(sqe, 0, &r->hdr, 0); // use the 0th file in the list of registered fds
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
static uint64_t wait_completion(struct io_uring *ring) {
    struct io_uring_cqe *cqe;
again:;

    int ret = io_uring_wait_cqe(ring, &cqe);
    if (ret == -EINTR) {
        goto again;
    }
    // TODO: Delete perror, fprintf, etc.
    // Encode in return value or similar.
    if (ret < 0) {
        perror("wait_completion io_uring_wait_cqe");
        return ret;
    }
    int n = cqe->res;
    if (n < 0) {
        // TODO: This leaks a buffer!!!
        fprintf(stderr, "wait_completion failed: %d.\n", n);
        return n;
    }
    size_t idx = (size_t)io_uring_cqe_get_data(cqe);
    uint64_t nidx = packNIdx(n, idx);
    io_uring_cqe_seen(ring, cqe);
    return nidx;
}

// submit a writev request via liburing
static int submit_writev_request(struct io_uring *ring, struct req *r, int buflen, size_t idx) {
    r->iov.iov_len = buflen;
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_writev(sqe, 0, &r->iov, 1, 0); // use the 0th file in the list of registered fds
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    io_uring_sqe_set_data(sqe, (void *)(idx));
    int submitted = io_uring_submit(ring);
    return 0;
}

// submit a readv request via liburing
static int submit_readv_request(struct io_uring *ring, struct req *r, size_t idx) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_readv(sqe, 0, &r->iov, 1, 0); // use the 0th file in the list of registered fds
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    io_uring_sqe_set_data(sqe, (void *)(idx));
    int submitted = io_uring_submit(ring);
    return 0;
}

static uint64_t peek_completion(struct io_uring *ring) {
    struct io_uring_cqe *cqe;
    int ret = io_uring_peek_cqe(ring, &cqe);
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
