// Copyright 2019 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build aix darwin dragonfly freebsd nacl netbsd openbsd solaris linux

package rand

import (
	"context"
	"fmt"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// urandomReader is a contextReader.
type urandomReader struct {
	once sync.Once

	// fd is expected to be non-blocking.
	fd int
}

func (r *urandomReader) init() error {
	var realErr error
	r.once.Do(func() {
		fd, err := unix.Open("/dev/urandom", unix.O_RDONLY, 0)
		if err != nil {
			realErr = fmt.Errorf("open(/dev/urandom): %v", err)
			return
		}
		r.fd = fd
	})
	return realErr
}

// ReadContext implements a cancelable read from /dev/urandom.
func (r *urandomReader) ReadContext(ctx context.Context, b []byte) (int, error) {
	if err := r.init(); err != nil {
		return 0, err
	}
	for {
		n, err := unix.Read(r.fd, b)
		if err == nil {
			return n, err
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()

		default:
			if err != nil && err != syscall.EAGAIN && err != syscall.EINTR {
				return n, err
			}
		}
	}
}
