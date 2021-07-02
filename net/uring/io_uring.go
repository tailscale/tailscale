package uring

import (
	"errors"
	"flag"
)

var useIOURing = flag.Bool("use-io-uring", true, "attempt to use io_uring if available")

// NotSupportedError indicates an operation was attempted when io_uring is not supported.
var NotSupportedError = errors.New("io_uring not supported")

// DisabledError indicates that io_uring was explicitly disabled.
var DisabledError = errors.New("io_uring disabled")
