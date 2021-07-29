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
    // in_kernel indicates (by being non-zero) whether this request is sitting in the kernel
    // It is accessed atomically.
    int32_t in_kernel; 
    char *buf;
    size_t idx;
};

typedef struct req goreq;

static struct req *initializeReq(size_t sz, size_t idx, int ipLen) {
    struct req *r = malloc(sizeof(struct req));
    memset(r, 0, sizeof(*r));
    r->buf = malloc(sz);
    memset(r->buf, 0, sz);
    r->iov.iov_base = r->buf;
    r->iov.iov_len = sz;
    r->hdr.msg_iov = &r->iov;
    r->hdr.msg_iovlen = 1;
    r->idx = idx;
    switch(ipLen) {
        case 4:
            r->hdr.msg_name = &r->sa;
            r->hdr.msg_namelen = sizeof(r->sa);
            break;
        case 16:
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

// submit a recvmsg request via liburing
// TODO: What recvfrom support arrives, maybe use that instead?
static int submit_recvmsg_request(struct io_uring *ring, struct req *r) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_recvmsg(sqe, 0, &r->hdr, 0); // use the 0th file in the list of registered fds
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    io_uring_sqe_set_data(sqe, (void *)(r->idx));
    io_uring_submit(ring);
    return 0;
}

// submit a recvmsg request via liburing
// TODO: What recvfrom support arrives, maybe use that instead?
static int submit_sendmsg_request(struct io_uring *ring, struct req *r, int buflen) {
    r->iov.iov_len = buflen;
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_sendmsg(sqe, 0, &r->hdr, 0); // use the 0th file in the list of registered fds
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    io_uring_sqe_set_data(sqe, (void *)(r->idx));
    io_uring_submit(ring);
    return 0;
}

static void submit_cancel_request(struct io_uring *ring, size_t idx) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	io_uring_prep_cancel(sqe, (void *)(idx), 0);
    io_uring_submit(ring);
}

// submit a writev request via liburing
static int submit_writev_request(struct io_uring *ring, struct req *r, int buflen) {
    r->iov.iov_len = buflen;
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_writev(sqe, 0, &r->iov, 1, 0); // use the 0th file in the list of registered fds
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    io_uring_sqe_set_data(sqe, (void *)(r->idx));
    int submitted = io_uring_submit(ring);
    return 0;
}

// submit a readv request via liburing
static int submit_readv_request(struct io_uring *ring, struct req *r) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_readv(sqe, 0, &r->iov, 1, 0); // use the 0th file in the list of registered fds
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    io_uring_sqe_set_data(sqe, (void *)(r->idx));
    int submitted = io_uring_submit(ring);
    return 0;
}


struct completion_result {
    int err;
    int n;
    size_t idx;
};

typedef struct completion_result go_completion_result;

static go_completion_result completion(struct io_uring *ring, int block) {
    struct io_uring_cqe *cqe;
    struct completion_result res;
    res.err = 0;
    res.n = 0;
    res.idx = 0;
    if (block) {
        res.err = io_uring_wait_cqe(ring, &cqe);
    } else {
        res.err = io_uring_peek_cqe(ring, &cqe);
    }
    if (res.err < 0) {
        return res;
    }
    res.idx = (size_t)io_uring_cqe_get_data(cqe);
    res.n = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    return res;
}
