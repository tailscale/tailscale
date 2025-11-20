// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package packet

import (
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/types/ptr"
)

func TestGeneveHeader(t *testing.T) {
	in := GeneveHeader{
		Version:  3,
		Protocol: GeneveProtocolDisco,
		Control:  true,
	}
	in.VNI.Set(1<<24 - 1)
	b := make([]byte, GeneveFixedHeaderLength)
	err := in.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	out := GeneveHeader{}
	err = out.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(out, in, cmpopts.EquateComparable(VirtualNetworkID{})); diff != "" {
		t.Fatalf("wrong results (-got +want)\n%s", diff)
	}
}

func TestVirtualNetworkID(t *testing.T) {
	tests := []struct {
		name string
		set  *uint32
		want uint32
	}{
		{
			"don't Set",
			nil,
			0,
		},
		{
			"Set 0",
			ptr.To(uint32(0)),
			0,
		},
		{
			"Set 1",
			ptr.To(uint32(1)),
			1,
		},
		{
			"Set math.MaxUint32",
			ptr.To(uint32(math.MaxUint32)),
			1<<24 - 1,
		},
		{
			"Set max 3-byte value",
			ptr.To(uint32(1<<24 - 1)),
			1<<24 - 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := VirtualNetworkID{}
			if tt.set != nil {
				v.Set(*tt.set)
			}
			if v.IsSet() != (tt.set != nil) {
				t.Fatalf("IsSet: %v != wantIsSet: %v", v.IsSet(), tt.set != nil)
			}
			if v.Get() != tt.want {
				t.Fatalf("Get(): %v != want: %v", v.Get(), tt.want)
			}
		})
	}
}
