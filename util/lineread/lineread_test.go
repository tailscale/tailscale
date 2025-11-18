// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package lineread

import (
	"strings"
	"testing"
)

func TestReader(t *testing.T) {
	r := strings.NewReader("line1\nline2\nline3\n")
	var lines []string
	if err := Reader(r, func(line []byte) error {
		lines = append(lines, string(line))
		return nil
	}); err != nil {
		t.Fatalf("Reader() failed: %v", err)
	}
	
	if len(lines) != 3 {
		t.Errorf("got %d lines, want 3", len(lines))
	}
}
