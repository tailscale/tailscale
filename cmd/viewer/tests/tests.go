// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tests serves a list of tests for tailscale.com/cmd/viewer.
package tests

import (
	"fmt"

	"inet.af/netaddr"
)

//go:generate go run tailscale.com/cmd/viewer --type=StructWithPtrs,StructWithoutPtrs,Map,StructWithSlices

type StructWithoutPtrs struct {
	Int int
	Pfx netaddr.IPPrefix
}

type Map struct {
	M map[string]int
}

type StructWithPtrs struct {
	Value *StructWithoutPtrs
	Int   *int

	NoCloneValue *StructWithoutPtrs `codegen:"noclone"`
}

func (v *StructWithPtrs) String() string { return fmt.Sprintf("%v", v.Int) }

func (v *StructWithPtrs) Equal(v2 *StructWithPtrs) bool {
	return v.Value == v2.Value
}

type StructWithSlices struct {
	Values         []StructWithoutPtrs
	ValuePointers  []*StructWithoutPtrs
	StructPointers []*StructWithPtrs
	Structs        []StructWithPtrs
	Ints           []*int

	Slice    []string
	Prefixes []netaddr.IPPrefix
	Data     []byte
}
