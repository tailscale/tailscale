// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package version

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func mkversion(t *testing.T, gitHash, otherHash string, major, minor, patch, changeCount int) (string, bool) {
	t.Helper()
	bs, err := exec.Command("./version.sh", gitHash, otherHash, strconv.Itoa(major), strconv.Itoa(minor), strconv.Itoa(patch), strconv.Itoa(changeCount)).CombinedOutput()
	out := strings.TrimSpace(string(bs))
	if err != nil {
		return out, false
	}
	return out, true
}

func TestMkversion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip test on Windows, because there is no shell to execute mkversion.sh.")
	}
	tests := []struct {
		gitHash, otherHash               string
		major, minor, patch, changeCount int
		want                             string
	}{
		{"abcdef", "", 0, 98, 0, 0, `
           VERSION_SHORT="0.98.0"
           VERSION_LONG="0.98.0-tabcdef"
           VERSION_GIT_HASH="abcdef"
           VERSION_EXTRA_HASH=""
           VERSION_XCODE="100.98.0"
           VERSION_WINRES="0,98,0,0"`},
		{"abcdef", "", 0, 98, 1, 0, `
           VERSION_SHORT="0.98.1"
           VERSION_LONG="0.98.1-tabcdef"
           VERSION_GIT_HASH="abcdef"
           VERSION_EXTRA_HASH=""
           VERSION_XCODE="100.98.1"
           VERSION_WINRES="0,98,1,0"`},
		{"abcdef", "", 1, 1, 0, 37, `
           VERSION_SHORT="1.1.1037"
           VERSION_LONG="1.1.1037-tabcdef"
           VERSION_GIT_HASH="abcdef"
           VERSION_EXTRA_HASH=""
           VERSION_XCODE="101.1.1037"
           VERSION_WINRES="1,1,1037,0"`},
		{"abcdef", "", 1, 2, 9, 0, `
           VERSION_SHORT="1.2.9"
           VERSION_LONG="1.2.9-tabcdef"
           VERSION_GIT_HASH="abcdef"
           VERSION_EXTRA_HASH=""
           VERSION_XCODE="101.2.9"
           VERSION_WINRES="1,2,9,0"`},
		{"abcdef", "", 1, 15, 0, 129, `
           VERSION_SHORT="1.15.129"
           VERSION_LONG="1.15.129-tabcdef"
           VERSION_GIT_HASH="abcdef"
           VERSION_EXTRA_HASH=""
           VERSION_XCODE="101.15.129"
           VERSION_WINRES="1,15,129,0"`},
		{"abcdef", "", 1, 2, 0, 17, `
           VERSION_SHORT="0.0.0"
           VERSION_LONG="0.0.0-tabcdef"
           VERSION_GIT_HASH="abcdef"
           VERSION_EXTRA_HASH=""
           VERSION_XCODE="100.0.0"
           VERSION_WINRES="0,0,0,0"`},
		{"abcdef", "defghi", 1, 15, 0, 129, `
           VERSION_SHORT="1.15.129"
           VERSION_LONG="1.15.129-tabcdef-gdefghi"
           VERSION_GIT_HASH="abcdef"
           VERSION_EXTRA_HASH="defghi"
           VERSION_XCODE="101.15.129"
           VERSION_WINRES="1,15,129,0"`},
		{"abcdef", "", 0, 99, 5, 0, ""},   // unstable, patch number not allowed
		{"abcdef", "", 0, 99, 5, 123, ""}, // unstable, patch number not allowed
	}

	for _, test := range tests {
		want := strings.ReplaceAll(strings.TrimSpace(test.want), " ", "")
		got, ok := mkversion(t, test.gitHash, test.otherHash, test.major, test.minor, test.patch, test.changeCount)
		invoc := fmt.Sprintf("version.sh %s %s %d %d %d %d", test.gitHash, test.otherHash, test.major, test.minor, test.patch, test.changeCount)
		if want == "" && ok {
			t.Errorf("%s ok=true, want false", invoc)
			continue
		}
		if diff := cmp.Diff(got, want); want != "" && diff != "" {
			t.Errorf("%s wrong output (-got+want):\n%s", invoc, diff)
		}
	}
}
