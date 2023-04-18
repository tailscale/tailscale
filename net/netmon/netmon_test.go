// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"flag"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/net/interfaces"
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

func TestMonitorInjectEvent(t *testing.T) {
	mon, err := New(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer mon.Close()
	got := make(chan bool, 1)
	mon.RegisterChangeCallback(func(changed bool, state *interfaces.State) {
		select {
		case got <- true:
		default:
		}
	})
	mon.Start()
	mon.InjectEvent()
	select {
	case <-got:
		// Pass.
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for callback")
	}
}

var (
	monitor         = flag.String("monitor", "", `go into monitor mode like 'route monitor'; test never terminates. Value can be either "raw" or "callback"`)
	monitorDuration = flag.Duration("monitor-duration", 0, "if non-zero, how long to run TestMonitorMode. Zero means forever.")
)

func TestMonitorMode(t *testing.T) {
	switch *monitor {
	case "":
		t.Skip("skipping non-test without --monitor")
	case "raw", "callback":
	default:
		t.Skipf(`invalid --monitor value: must be "raw" or "callback"`)
	}
	mon, err := New(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	switch *monitor {
	case "raw":
		var closed atomic.Bool
		if *monitorDuration != 0 {
			t := time.AfterFunc(*monitorDuration, func() {
				closed.Store(true)
				mon.Close()
			})
			defer t.Stop()
		}
		for {
			msg, err := mon.om.Receive()
			if closed.Load() {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("msg: %#v", msg)
		}
	case "callback":
		var done <-chan time.Time
		if *monitorDuration != 0 {
			t := time.NewTimer(*monitorDuration)
			defer t.Stop()
			done = t.C
		}
		n := 0
		mon.RegisterChangeCallback(func(changed bool, st *interfaces.State) {
			n++
			t.Logf("cb: changed=%v, ifSt=%v", changed, st)
		})
		mon.Start()
		<-done
		t.Logf("%v callbacks", n)
	}
}
