// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstime

import (
	"testing"
	"time"
)

type d struct {
	wall    time.Duration
	virtual time.Duration
}

type t struct {
	wall    time.Time
	virtual time.Time
}

func since(dt *Virtual, t t) d {
	return d{
		wall:    time.Since(t.wall),
		virtual: dt.Since(t.virtual),
	}
}

func now(d *Virtual) t {
	return t{
		wall:    time.Now(),
		virtual: d.Now(),
	}
}

func TestVirtual(t *testing.T) {
	d := &Virtual{
		Second: time.Millisecond,
	}
	start := now(d)
	d.Sleep(time.Second)
	took := since(d, start)
	t.Logf("Slept %s in %s", took.virtual, took.wall)
	if took.wall > 5*time.Millisecond { // generous margin to allow for loaded machine
		t.Errorf("virtual time ran too slow")
	}
	if took.virtual < time.Second {
		t.Errorf("virtual time didn't advance enough")
	}
}
