// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/tstun"
)

func TestNoteReceiveActivity(t *testing.T) {
	now := time.Unix(1, 0)
	tick := func(d time.Duration) { now = now.Add(d) }
	var logBuf bytes.Buffer

	confc := make(chan bool, 1)
	gotConf := func() bool {
		select {
		case <-confc:
			return true
		default:
			return false
		}
	}
	e := &userspaceEngine{
		timeNow:        func() time.Time { return now },
		recvActivityAt: map[tailcfg.DiscoKey]time.Time{},
		logf: func(format string, a ...interface{}) {
			fmt.Fprintf(&logBuf, format, a...)
		},
		tundev:                new(tstun.TUN),
		testMaybeReconfigHook: func() { confc <- true },
	}
	ra := e.recvActivityAt

	dk := tailcfg.DiscoKey(key.NewPrivate().Public())

	// Activity on an untracked key should do nothing.
	e.noteReceiveActivity(dk)
	if len(ra) != 0 {
		t.Fatalf("unexpected growth in map: now has %d keys; want 0", len(ra))
	}
	if logBuf.Len() != 0 {
		t.Fatalf("unexpected log write (and thus activity): %s", logBuf.Bytes())
	}

	// Now track it and expect updates.
	ra[dk] = time.Time{}
	e.noteReceiveActivity(dk)
	if len(ra) != 1 {
		t.Fatalf("unexpected growth in map: now has %d keys; want 1", len(ra))
	}
	if got := ra[dk]; got != now {
		t.Fatalf("time in map = %v; want %v", got, now)
	}
	if !gotConf() {
		t.Fatalf("didn't get expected reconfig")
	}

	// With updates 1 second apart, don't expect a reconfig.
	for i := 0; i < 300; i++ {
		tick(time.Second)
		e.noteReceiveActivity(dk)
		if len(ra) != 1 {
			t.Fatalf("map len = %d; want 1", len(ra))
		}
		if got := ra[dk]; got != now {
			t.Fatalf("time in map = %v; want %v", got, now)
		}
		if gotConf() {
			t.Fatalf("unexpected reconfig")
		}
	}

	// But if there's a big jump it should get an update.
	tick(3 * time.Minute)
	e.noteReceiveActivity(dk)
	if !gotConf() {
		t.Fatalf("expected config")
	}
}
