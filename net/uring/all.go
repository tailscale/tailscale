package uring

import (
	"errors"
	"flag"
	"runtime"
)

// This file contains code shared across all platforms.

// Available reports whether io_uring is available on this machine.
// If Available reports false, no other package uring APIs should be called.
func Available() bool {
	return runtime.GOOS == "linux" && *useIOURing
}

var useIOURing = flag.Bool("use-io-uring", true, "attempt to use io_uring if available")

// NotSupportedError indicates an operation was attempted when io_uring is not supported.
var NotSupportedError = errors.New("io_uring not supported")

// DisabledError indicates that io_uring was explicitly disabled.
var DisabledError = errors.New("io_uring disabled")

type IORingOp = int

//https://unixism.net/loti/tutorial/probe_liburing.html
const (
	IORING_OP_NOP IORingOp = iota
	IORING_OP_READV
	IORING_OP_WRITEV
	IORING_OP_FSYNC
	IORING_OP_READ_FIXED
	IORING_OP_WRITE_FIXED
	IORING_OP_POLL_ADD
	IORING_OP_POLL_REMOVE
	IORING_OP_SYNC_FILE_RANGE
	IORING_OP_SENDMSG
	IORING_OP_RECVMSG
	IORING_OP_TIMEOUT
	IORING_OP_TIMEOUT_REMOVE
	IORING_OP_ACCEPT
	IORING_OP_ASYNC_CANCEL
	IORING_OP_LINK_TIMEOUT
	IORING_OP_CONNECT
	IORING_OP_FALLOCATE
	IORING_OP_OPENAT
	IORING_OP_CLOSE
	IORING_OP_FILES_UPDATE
	IORING_OP_STATX
	IORING_OP_READ
	IORING_OP_WRITE
	IORING_OP_FADVISE
	IORING_OP_MADVISE
	IORING_OP_SEND
	IORING_OP_RECV
	IORING_OP_OPENAT2
	IORING_OP_EPOLL_CTL
	IORING_OP_SPLICE
	IORING_OP_PROVIDE_BUFFERS
	IORING_OP_REMOVE_BUFFERS
)
