// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"errors"
	"reflect"
	"testing"

	"tailscale.com/tstest"
)

func TestNewStaticInterfaceDiscoveryFailure(t *testing.T) {
	tstest.Replace(t, &altNetInterfaces, func() ([]Interface, error) {
		return nil, errors.New("interface enumeration unavailable")
	})
	mon := NewStatic()
	if got := mon.InterfaceState(); !reflect.DeepEqual(got, &State{}) {
		t.Fatalf("InterfaceState = %#v, want non-nil empty state", got)
	}
	mon.Start()
	if err := mon.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLinkChangeLogLimiterStatic(t *testing.T) {
	mon := NewStatic()
	calls := 0
	logf := LinkChangeLogLimiter(t.Context(), func(string, ...any) { calls++ }, mon)
	logf("first format")
	logf("first format")
	logf("second format")
	if calls != 2 {
		t.Fatalf("logged %d messages, want 2", calls)
	}
}
