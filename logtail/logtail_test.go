// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logtail

import (
	"context"
	"testing"
	"time"
)

func TestFastShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	l := Log(Config{
		BaseURL: "http://localhost:1234",
	})
	l.Shutdown(ctx)
}

var sink []byte

func TestLoggerEncodeTextAllocs(t *testing.T) {
	lg := &logger{timeNow: time.Now}
	inBuf := []byte("some text to encode")
	n := testing.AllocsPerRun(1000, func() {
		sink = lg.encodeText(inBuf, false)
	})
	if int(n) != 1 {
		t.Logf("allocs = %d; want 1", int(n))
	}
}
