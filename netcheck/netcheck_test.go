// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netcheck

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"tailscale.com/derp/derpmap"
	"tailscale.com/stun"
	"tailscale.com/stun/stuntest"
)

func TestHairpinSTUN(t *testing.T) {
	c := &Client{
		hairTX:      stun.NewTxID(),
		gotHairSTUN: make(chan *net.UDPAddr, 1),
	}
	req := stun.Request(c.hairTX)
	if !stun.Is(req) {
		t.Fatal("expected STUN message")
	}
	if !c.handleHairSTUN(req, nil) {
		t.Fatal("expected true")
	}
	select {
	case <-c.gotHairSTUN:
	default:
		t.Fatal("expected value")
	}
}

func TestBasic(t *testing.T) {
	stunAddr, cleanup := stuntest.Serve(t)
	defer cleanup()

	c := &Client{
		DERP: derpmap.NewTestWorld(stunAddr),
		Logf: t.Logf,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	r, err := c.GetReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !r.UDP {
		t.Error("want UDP")
	}
	if len(r.DERPLatency) != 1 {
		t.Errorf("expected 1 key in DERPLatency; got %+v", r.DERPLatency)
	}
	if _, ok := r.DERPLatency[stunAddr]; !ok {
		t.Errorf("expected key %q in DERPLatency; got %+v", stunAddr, r.DERPLatency)
	}
	if r.GlobalV4 == "" {
		t.Error("expected GlobalV4 set")
	}
	if r.PreferredDERP != 1 {
		t.Errorf("PreferredDERP = %v; want 1", r.PreferredDERP)
	}
}

func TestWorksWhenUDPBlocked(t *testing.T) {
	blackhole, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to open blackhole STUN listener: %v", err)
	}
	defer blackhole.Close()

	stunAddr := blackhole.LocalAddr().String()

	c := &Client{
		DERP: derpmap.NewTestWorld(stunAddr),
		Logf: t.Logf,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	r, err := c.GetReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := &Report{
		DERPLatency: map[string]time.Duration{},
	}

	if !reflect.DeepEqual(r, want) {
		t.Errorf("mismatch\n got: %+v\nwant: %+v\n", r, want)
	}
}

func TestAddReportHistoryAndSetPreferredDERP(t *testing.T) {
	derps := derpmap.NewTestWorldWith(
		&derpmap.Server{
			ID:    1,
			STUN4: "d1",
		},
		&derpmap.Server{
			ID:    2,
			STUN4: "d2",
		},
		&derpmap.Server{
			ID:    3,
			STUN4: "d3",
		},
	)
	// report returns a *Report from (DERP host, time.Duration)+ pairs.
	report := func(a ...interface{}) *Report {
		r := &Report{DERPLatency: map[string]time.Duration{}}
		for i := 0; i < len(a); i += 2 {
			k := a[i].(string)
			switch v := a[i+1].(type) {
			case time.Duration:
				r.DERPLatency[k] = v
			case int:
				r.DERPLatency[k] = time.Second * time.Duration(v)
			default:
				panic(fmt.Sprintf("unexpected type %T", v))
			}
		}
		return r
	}
	type step struct {
		after time.Duration
		r     *Report
	}
	tests := []struct {
		name        string
		steps       []step
		wantDERP    int // want PreferredDERP on final step
		wantPrevLen int // wanted len(c.prev)
	}{
		{
			name: "first_reading",
			steps: []step{
				{0, report("d1", 2, "d2", 3)},
			},
			wantPrevLen: 1,
			wantDERP:    1,
		},
		{
			name: "with_two",
			steps: []step{
				{0, report("d1", 2, "d2", 3)},
				{1 * time.Second, report("d1", 4, "d2", 3)},
			},
			wantPrevLen: 2,
			wantDERP:    1, // t0's d1 of 2 is still best
		},
		{
			name: "but_now_d1_gone",
			steps: []step{
				{0, report("d1", 2, "d2", 3)},
				{1 * time.Second, report("d1", 4, "d2", 3)},
				{2 * time.Second, report("d2", 3)},
			},
			wantPrevLen: 3,
			wantDERP:    2, // only option
		},
		{
			name: "d1_is_back",
			steps: []step{
				{0, report("d1", 2, "d2", 3)},
				{1 * time.Second, report("d1", 4, "d2", 3)},
				{2 * time.Second, report("d2", 3)},
				{3 * time.Second, report("d1", 4, "d2", 3)}, // same as 2 seconds ago
			},
			wantPrevLen: 4,
			wantDERP:    1, // t0's d1 of 2 is still best
		},
		{
			name: "things_clean_up",
			steps: []step{
				{0, report("d1", 1, "d2", 2)},
				{1 * time.Second, report("d1", 1, "d2", 2)},
				{2 * time.Second, report("d1", 1, "d2", 2)},
				{3 * time.Second, report("d1", 1, "d2", 2)},
				{10 * time.Minute, report("d3", 3)},
			},
			wantPrevLen: 1, // t=[0123]s all gone. (too old, older than 10 min)
			wantDERP:    3, // only option
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeTime := time.Unix(123, 0)
			c := &Client{
				DERP:    derps,
				TimeNow: func() time.Time { return fakeTime },
			}
			for _, s := range tt.steps {
				fakeTime = fakeTime.Add(s.after)
				c.addReportHistoryAndSetPreferredDERP(s.r)
			}
			lastReport := tt.steps[len(tt.steps)-1].r
			if got, want := len(c.prev), tt.wantPrevLen; got != want {
				t.Errorf("len(prev) = %v; want %v", got, want)
			}
			if got, want := lastReport.PreferredDERP, tt.wantDERP; got != want {
				t.Errorf("PreferredDERP = %v; want %v", got, want)
			}
		})
	}
}
