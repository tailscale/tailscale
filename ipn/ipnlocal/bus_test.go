// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"tailscale.com/drive"
	"tailscale.com/ipn"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
)

func TestIsNotableNotify(t *testing.T) {
	tests := []struct {
		name   string
		notify *ipn.Notify
		want   bool
	}{
		{"nil", nil, false},
		{"empty", &ipn.Notify{}, false},
		{"version", &ipn.Notify{Version: "foo"}, false},
		{"netmap", &ipn.Notify{NetMap: new(netmap.NetworkMap)}, false},
		{"engine", &ipn.Notify{Engine: new(ipn.EngineStatus)}, false},
	}

	// Then for all other fields, assume they're notable.
	// We use reflect to catch fields that might be added in the future without
	// remembering to update the [isNotableNotify] function.
	rt := reflect.TypeFor[ipn.Notify]()
	for i := range rt.NumField() {
		n := &ipn.Notify{}
		sf := rt.Field(i)
		switch sf.Name {
		case "_", "NetMap", "Engine", "Version":
			// Already covered above or not applicable.
			continue
		case "DriveShares":
			n.DriveShares = views.SliceOfViews[*drive.Share, drive.ShareView](make([]*drive.Share, 1))
		default:
			rf := reflect.ValueOf(n).Elem().Field(i)
			switch rf.Kind() {
			case reflect.Pointer:
				rf.Set(reflect.New(rf.Type().Elem()))
			case reflect.String:
				rf.SetString("foo")
			case reflect.Slice:
				rf.Set(reflect.MakeSlice(rf.Type(), 1, 1))
			default:
				t.Errorf("unhandled field kind %v for %q", rf.Kind(), sf.Name)
			}
		}

		tests = append(tests, struct {
			name   string
			notify *ipn.Notify
			want   bool
		}{
			name:   "field-" + rt.Field(i).Name,
			notify: n,
			want:   true,
		})
	}

	for _, tt := range tests {
		if got := isNotableNotify(tt.notify); got != tt.want {
			t.Errorf("%v: got %v; want %v", tt.name, got, tt.want)
		}
	}
}

type rateLimitingBusSenderTester struct {
	tb    testing.TB
	got   []*ipn.Notify
	clock *tstest.Clock
	s     *rateLimitingBusSender
}

func (st *rateLimitingBusSenderTester) init() {
	if st.s != nil {
		return
	}
	st.clock = tstest.NewClock(tstest.ClockOpts{
		Start: time.Unix(1731777537, 0), // time I wrote this test :)
	})
	st.s = &rateLimitingBusSender{
		clock: tstime.DefaultClock{Clock: st.clock},
		fn: func(n *ipn.Notify) bool {
			st.got = append(st.got, n)
			return true
		},
	}
}

func (st *rateLimitingBusSenderTester) send(n *ipn.Notify) {
	st.tb.Helper()
	st.init()
	if !st.s.send(n) {
		st.tb.Fatal("unexpected send failed")
	}
}

func (st *rateLimitingBusSenderTester) advance(d time.Duration) {
	st.tb.Helper()
	st.clock.Advance(d)
	select {
	case <-st.s.flushChan():
		if !st.s.flush() {
			st.tb.Fatal("unexpected flush failed")
		}
	default:
	}
}

func TestRateLimitingBusSender(t *testing.T) {
	nm1 := &ipn.Notify{NetMap: new(netmap.NetworkMap)}
	nm2 := &ipn.Notify{NetMap: new(netmap.NetworkMap)}
	eng1 := &ipn.Notify{Engine: new(ipn.EngineStatus)}
	eng2 := &ipn.Notify{Engine: new(ipn.EngineStatus)}

	t.Run("unbuffered", func(t *testing.T) {
		st := &rateLimitingBusSenderTester{tb: t}
		st.send(nm1)
		st.send(nm2)
		st.send(eng1)
		st.send(eng2)
		if !slices.Equal(st.got, []*ipn.Notify{nm1, nm2, eng1, eng2}) {
			t.Errorf("got %d items; want 4 specific ones, unmodified", len(st.got))
		}
	})

	t.Run("buffered", func(t *testing.T) {
		st := &rateLimitingBusSenderTester{tb: t}
		st.init()
		st.s.interval = 1 * time.Second
		st.send(&ipn.Notify{Version: "initial"})
		if len(st.got) != 1 {
			t.Fatalf("got %d items; expected 1 (first to flush immediately)", len(st.got))
		}
		st.send(nm1)
		st.send(nm2)
		st.send(eng1)
		st.send(eng2)
		if len(st.got) != 1 {
			if len(st.got) != 1 {
				t.Fatalf("got %d items; expected still just that first 1", len(st.got))
			}
		}

		// But moving the clock should flush the rest, collasced into one new one.
		st.advance(5 * time.Second)
		if len(st.got) != 2 {
			t.Fatalf("got %d items; want 2", len(st.got))
		}
		gotn := st.got[1]
		if gotn.NetMap != nm2.NetMap {
			t.Errorf("got wrong NetMap; got %p", gotn.NetMap)
		}
		if gotn.Engine != eng2.Engine {
			t.Errorf("got wrong Engine; got %p", gotn.Engine)
		}
		if t.Failed() {
			t.Logf("failed Notify was: %v", logger.AsJSON(gotn))
		}
	})

	// Test the Run method
	t.Run("run", func(t *testing.T) {
		st := &rateLimitingBusSenderTester{tb: t}
		st.init()
		st.s.interval = 1 * time.Second
		st.s.lastFlush = st.clock.Now() // pretend we just flushed

		flushc := make(chan *ipn.Notify, 1)
		st.s.fn = func(n *ipn.Notify) bool {
			flushc <- n
			return true
		}
		didSend := make(chan bool, 2)
		st.s.didSendTestHook = func() { didSend <- true }
		waitSend := func() {
			select {
			case <-didSend:
			case <-time.After(5 * time.Second):
				t.Error("timeout waiting for call to send")
			}
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		incoming := make(chan *ipn.Notify, 2)
		go func() {
			incoming <- nm1
			waitSend()
			incoming <- nm2
			waitSend()
			st.advance(5 * time.Second)
			select {
			case n := <-flushc:
				if n.NetMap != nm2.NetMap {
					t.Errorf("got wrong NetMap; got %p", n.NetMap)
				}
			case <-time.After(10 * time.Second):
				t.Error("timeout")
			}
			cancel()
		}()

		st.s.Run(ctx, incoming)
	})
}
