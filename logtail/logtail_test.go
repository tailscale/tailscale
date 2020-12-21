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

	l := NewLogger(Config{
		BaseURL: "http://localhost:1234",
	}, t.Logf)
	l.Shutdown(ctx)
}

var sink []byte

func TestLoggerEncodeTextAllocs(t *testing.T) {
	lg := &Logger{timeNow: time.Now}
	inBuf := []byte("some text to encode")
	n := testing.AllocsPerRun(1000, func() {
		sink = lg.encodeText(inBuf, false)
	})
	if int(n) != 1 {
		t.Logf("allocs = %d; want 1", int(n))
	}
}

func TestLoggerWriteLength(t *testing.T) {
	lg := &Logger{
		timeNow: time.Now,
		buffer:  NewMemoryBuffer(1024),
	}
	inBuf := []byte("some text to encode")
	n, err := lg.Write(inBuf)
	if err != nil {
		t.Error(err)
	}
	if n != len(inBuf) {
		t.Errorf("logger.Write wrote %d bytes, expected %d", n, len(inBuf))
	}
}
