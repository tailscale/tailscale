// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package version

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func xcode(short, long string) string {
	return fmt.Sprintf("VERSION_NAME = %s\nVERSION_ID = %s", short, long)
}

func mkversion(t *testing.T, mode, describe, other string) (string, bool) {
	t.Helper()
	bs, err := exec.Command("./mkversion.sh", mode, describe, other).CombinedOutput()
	if err != nil {
		t.Logf("mkversion.sh output: %s", string(bs))
		return "", false
	}
	return strings.TrimSpace(string(bs)), true
}

func TestMkversion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip test on Windows, because there is no shell to execute mkversion.sh.")
	}
	tests := []struct {
		describe string
		other    string
		ok       bool
		long     string
		short    string
		xcode    string
	}{
		{"v0.98-gabcdef", "", true, "0.98.0-tabcdef", "0.98.0", xcode("0.98.0", "100.98.0")},
		{"v0.98.1-gabcdef", "", true, "0.98.1-tabcdef", "0.98.1", xcode("0.98.1", "100.98.1")},
		{"v1.1.0-37-gabcdef", "", true, "1.1.1037-tabcdef", "1.1.1037", xcode("1.1.1037", "101.1.1037")},
		{"v1.2.9-gabcdef", "", true, "1.2.9-tabcdef", "1.2.9", xcode("1.2.9", "101.2.9")},
		{"v1.2.9-0-gabcdef", "", true, "1.2.9-tabcdef", "1.2.9", xcode("1.2.9", "101.2.9")},
		{"v1.15.0-129-gabcdef", "", true, "1.15.129-tabcdef", "1.15.129", xcode("1.15.129", "101.15.129")},

		{"v0.98-123-gabcdef", "", true, "0.0.0-tabcdef", "0.0.0", xcode("0.0.0", "100.0.0")},
		{"v1.0.0-37-gabcdef", "", true, "0.0.0-tabcdef", "0.0.0", xcode("0.0.0", "100.0.0")},
		{"v1.1.0-129-gabcdef", "0123456789abcdef0123456789abcdef", true, "1.1.1129-tabcdef-g012345678", "1.1.1129", xcode("1.1.1129", "101.1.1129")},
		{"v0.99.5-0-gabcdef", "", false, "", "", ""},   // unstable, patch not allowed
		{"v0.99.5-123-gabcdef", "", false, "", "", ""}, // unstable, patch not allowed
		{"v1-gabcdef", "", false, "", "", ""},          // bad semver
		{"v1.0", "", false, "", "", ""},                // missing suffix
	}

	for _, test := range tests {
		gotlong, longOK := mkversion(t, "long", test.describe, test.other)
		if longOK != test.ok {
			t.Errorf("mkversion.sh long %q ok=%v, want %v", test.describe, longOK, test.ok)
		}
		gotshort, shortOK := mkversion(t, "short", test.describe, test.other)
		if shortOK != test.ok {
			t.Errorf("mkversion.sh short %q ok=%v, want %v", test.describe, shortOK, test.ok)
		}
		gotxcode, xcodeOK := mkversion(t, "xcode", test.describe, test.other)
		if xcodeOK != test.ok {
			t.Errorf("mkversion.sh xcode %q ok=%v, want %v", test.describe, xcodeOK, test.ok)
		}
		if longOK && gotlong != test.long {
			t.Errorf("mkversion.sh long %q: got %q, want %q", test.describe, gotlong, test.long)
		}
		if shortOK && gotshort != test.short {
			t.Errorf("mkversion.sh short %q: got %q, want %q", test.describe, gotshort, test.short)
		}
		if xcodeOK && gotxcode != test.xcode {
			t.Errorf("mkversion.sh xcode %q: got %q, want %q", test.describe, gotxcode, test.xcode)
		}
	}
}
