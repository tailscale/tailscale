// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package packet

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGeneveHeader(t *testing.T) {
	in := GeneveHeader{
		Version:  3,
		Protocol: GeneveProtocolDisco,
		VNI:      1<<24 - 1,
		Control:  true,
	}
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
	if diff := cmp.Diff(out, in); diff != "" {
		t.Fatalf("wrong results (-got +want)\n%s", diff)
	}
}
