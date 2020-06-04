// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package version

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func xcode(short, long string) string {
	return fmt.Sprintf("VERSION_NAME = %s\nVERSION_ID = %s", short, long)
}

func mkversion(t *testing.T, mode, in string) string {
	t.Helper()
	bs, err := exec.Command("./mkversion.sh", mode, in).CombinedOutput()
	if err != nil {
		t.Logf("mkversion.sh output: %s", string(bs))
		t.Fatalf("mkversion.sh %s %s: %v", mode, in, err)
	}
	return strings.TrimSpace(string(bs))
}

func TestMkversion(t *testing.T) {
	tests := []struct {
		in    string
		long  string
		short string
		xcode string
	}{
		{"v0.98-abcdef", "0.98.0-0-abcdef", "0.98.0-0", xcode("0.98.0", "100.98.0")},
		{"v0.98-123-abcdef", "0.98.0-123-abcdef", "0.98.0-123", xcode("0.98.123", "100.98.123")},
		{"v0.99.5-123-abcdef", "0.99.5-123-abcdef", "0.99.5-123", xcode("0.99.50123", "100.99.50123")},
		{"v0.99.5-123-abcdef", "0.99.5-123-abcdef", "0.99.5-123", xcode("0.99.50123", "100.99.50123")},
		{"v2.3-0-abcdef", "2.3.0-0-abcdef", "2.3.0-0", xcode("2.3.0", "102.3.0")},
		{"1.2.3-4-abcdef", "1.2.3-4-abcdef", "1.2.3-4", xcode("1.2.30004", "101.2.30004")},
	}

	for _, test := range tests {
		gotlong := mkversion(t, "long", test.in)
		gotshort := mkversion(t, "short", test.in)
		gotxcode := mkversion(t, "xcode", test.in)
		if gotlong != test.long {
			t.Errorf("mkversion.sh long %q: got %q, want %q", test.in, gotlong, test.long)
		}
		if gotshort != test.short {
			t.Errorf("mkversion.sh short %q: got %q, want %q", test.in, gotshort, test.short)
		}
		if gotxcode != test.xcode {
			t.Errorf("mkversion.sh xcode %q: got %q, want %q", test.in, gotxcode, test.xcode)
		}
	}
}
