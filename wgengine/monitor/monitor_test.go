// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package monitor

import (
	"testing"
)

func TestMonitorStartClose(t *testing.T) {
	mon, err := New(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	mon.Start()
	if err := mon.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMonitorJustClose(t *testing.T) {
	mon, err := New(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if err := mon.Close(); err != nil {
		t.Fatal(err)
	}
}
