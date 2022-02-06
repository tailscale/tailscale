// Copyright 2020 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build plan9 windows

package rand

import (
	"context"
	"crypto/rand"
)

var defaultContextReader = &cryptoRandReader{}

type cryptoRandReader struct{}

// ReadContext implements a cancelable read.
func (r *cryptoRandReader) ReadContext(ctx context.Context, b []byte) (n int, err error) {
	ch := make(chan struct{})
	go func() {
		n, err = rand.Reader.Read(b)
		close(ch)
	}()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-ch:
		return n, err
	}
}
