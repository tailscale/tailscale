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
