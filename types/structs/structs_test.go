// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package structs

import "testing"

func TestContainsPointers(t *testing.T) {
	type hasPtr struct {
		p *int
	}
	if !ContainsPointers[hasPtr]() {
		t.Error("ContainsPointers for struct with pointer returned false")
	}
	
	type noPtr struct {
		i int
	}
	if ContainsPointers[noPtr]() {
		t.Error("ContainsPointers for struct without pointer returned true")
	}
}
