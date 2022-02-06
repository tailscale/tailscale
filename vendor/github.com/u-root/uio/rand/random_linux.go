// Copyright 2019 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rand

import (
	"context"
	"log"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var defaultContextReader = &getrandomReader{}

var backupReader = &urandomReader{}

type getrandomReader struct {
	once   sync.Once
	backup bool
}

// ReadContext implements a cancelable read from /dev/urandom.
func (r *getrandomReader) ReadContext(ctx context.Context, b []byte) (int, error) {
	r.once.Do(func() {
		if os.Getenv("UROOT_NOHWRNG") != "" {
			r.backup = true
			return
		}
		if _, err := unix.Getrandom(b, unix.GRND_NONBLOCK); err == syscall.ENOSYS {
			r.backup = true
		}
	})
	if r.backup {
		return backupReader.ReadContext(ctx, b)
	}

	for {
		// getrandom(2) with GRND_NONBLOCK uses the urandom number
		// source, but only returns numbers if the crng has been
		// initialized.
		//
		// This is preferrable to /dev/urandom, as /dev/urandom will
		// make up fake random numbers until the crng has been
		// initialized.
		n, err := unix.Getrandom(b, unix.GRND_NONBLOCK)
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

// ReadContextWithSlowLogs logs a helpful message if it takes a significant
// amount of time (>2s) to produce random data.
func (r *getrandomReader) ReadContextWithSlowLogs(ctx context.Context, b []byte) (int, error) {
	d := 2 * time.Second
	t := time.AfterFunc(d, func() {
		log.Printf("getrandom is taking a long time (>%v). "+
			"If running on hardware, consider enabling Linux's CONFIG_RANDOM_TRUST_CPU=y. "+
			"If running in a VM/emulator, try setting up virtio-rng.", d)
	})
	defer t.Stop()
	return r.ReadContext(ctx, b)
}
