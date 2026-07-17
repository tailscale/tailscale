// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlknobs

import (
	"reflect"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

func TestAsDebugJSON(t *testing.T) {
	var nilPtr *Knobs
	if got := nilPtr.AsDebugJSON(); got != nil {
		t.Errorf("AsDebugJSON(nil) = %v; want nil", got)
	}
	k := new(Knobs)
	got := k.AsDebugJSON()
	if want := reflect.TypeFor[Knobs]().NumField(); len(got) != want {
		t.Errorf("AsDebugJSON map has %d fields; want %v", len(got), want)
	}
	t.Logf("Got: %v", logger.AsJSON(got))
}

func TestPathHealthMode(t *testing.T) {
	var nilKnobs *Knobs
	if got := nilKnobs.PathHealthMode(); got != PathHealthOff {
		t.Fatalf("nil PathHealthMode = %v; want off", got)
	}

	tests := []struct {
		name string
		caps tailcfg.NodeCapMap
		want PathHealthMode
	}{
		{name: "off", want: PathHealthOff},
		{
			name: "shadow",
			caps: tailcfg.NodeCapMap{tailcfg.NodeAttrMagicsockPathHealthShadow: nil},
			want: PathHealthShadow,
		},
		{
			name: "enforce",
			caps: tailcfg.NodeCapMap{tailcfg.NodeAttrMagicsockPathHealthEnforce: nil},
			want: PathHealthEnforce,
		},
		{
			name: "enforce-wins",
			caps: tailcfg.NodeCapMap{
				tailcfg.NodeAttrMagicsockPathHealthShadow:  nil,
				tailcfg.NodeAttrMagicsockPathHealthEnforce: nil,
			},
			want: PathHealthEnforce,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := new(Knobs)
			k.UpdateFromNodeAttributes(tt.caps)
			if got := k.PathHealthMode(); got != tt.want {
				t.Fatalf("PathHealthMode = %v; want %v", got, tt.want)
			}
			if got := k.AsDebugJSON()["MagicsockPathHealthMode"]; got != uint32(tt.want) {
				t.Fatalf("debug mode = %v; want %v", got, tt.want)
			}
		})
	}

	k := new(Knobs)
	k.UpdateFromNodeAttributes(tailcfg.NodeCapMap{tailcfg.NodeAttrMagicsockPathHealthEnforce: nil})
	k.UpdateFromNodeAttributes(nil)
	if got := k.PathHealthMode(); got != PathHealthOff {
		t.Fatalf("mode after capability removal = %v; want off", got)
	}
}

func TestPathHealthStatePublishesModeAndEpochAtomically(t *testing.T) {
	k := new(Knobs)
	const iterations = 10000
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range iterations {
			k.UpdateFromNodeAttributes(tailcfg.NodeCapMap{tailcfg.NodeAttrMagicsockPathHealthEnforce: nil})
			k.UpdateFromNodeAttributes(nil)
		}
	}()
	var lastEpoch uint64
	for {
		mode, epoch := k.PathHealthState()
		if epoch < lastEpoch {
			t.Fatalf("epoch moved backwards: %d -> %d", lastEpoch, epoch)
		}
		lastEpoch = epoch
		if mode != PathHealthOff && mode != PathHealthEnforce {
			t.Fatalf("observed invalid packed mode %v at epoch %d", mode, epoch)
		}
		select {
		case <-done:
			return
		default:
		}
	}
}
