// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package mkversion

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func mkInfo(gitHash, otherHash, otherDate string, major, minor, patch, changeCount int) verInfo {
	return verInfo{
		major:       major,
		minor:       minor,
		patch:       patch,
		changeCount: changeCount,
		hash:        gitHash,
		otherHash:   otherHash,
		otherDate:   otherDate,
	}
}

func TestMkversion(t *testing.T) {
	otherDate := fmt.Sprintf("%d", time.Date(2023, time.January, 27, 1, 2, 3, 4, time.UTC).Unix())

	tests := []struct {
		in   verInfo
		want string
	}{
		{mkInfo("abcdef", "", otherDate, 0, 98, 0, 0), `
           VERSION_MAJOR=0
           VERSION_MINOR=98
           VERSION_PATCH=0
           VERSION_SHORT="0.98.0"
           VERSION_LONG="0.98.0-tabcdef"
           VERSION_GIT_HASH="abcdef"
           VERSION_TRACK="stable"`},
		{mkInfo("abcdef", "", otherDate, 0, 98, 1, 0), `
           VERSION_MAJOR=0
           VERSION_MINOR=98
           VERSION_PATCH=1
           VERSION_SHORT="0.98.1"
           VERSION_LONG="0.98.1-tabcdef"
           VERSION_GIT_HASH="abcdef"
           VERSION_TRACK="stable"`},
		{mkInfo("abcdef", "", otherDate, 1, 2, 9, 0), `
           VERSION_MAJOR=1
           VERSION_MINOR=2
           VERSION_PATCH=9
           VERSION_SHORT="1.2.9"
           VERSION_LONG="1.2.9-tabcdef"
           VERSION_GIT_HASH="abcdef"
           VERSION_TRACK="stable"`},
		{mkInfo("abcdef", "", otherDate, 1, 15, 0, 129), `
           VERSION_MAJOR=1
           VERSION_MINOR=15
           VERSION_PATCH=129
           VERSION_SHORT="1.15.129"
           VERSION_LONG="1.15.129-tabcdef"
           VERSION_GIT_HASH="abcdef"
           VERSION_TRACK="unstable"`},
		{mkInfo("abcdef", "", otherDate, 1, 2, 0, 17), `
           VERSION_MAJOR=1
           VERSION_MINOR=2
           VERSION_PATCH=0
           VERSION_SHORT="1.2.0"
           VERSION_LONG="1.2.0-17-tabcdef"
           VERSION_GIT_HASH="abcdef"
           VERSION_TRACK="stable"`},
		{mkInfo("abcdef", "defghi", otherDate, 1, 15, 0, 129), `
           VERSION_MAJOR=1
           VERSION_MINOR=15
           VERSION_PATCH=129
           VERSION_SHORT="1.15.129"
           VERSION_LONG="1.15.129-tabcdef-gdefghi"
           VERSION_GIT_HASH="abcdef"
           VERSION_TRACK="unstable"
           VERSION_EXTRA_HASH="defghi"
           VERSION_XCODE="101.15.129"
           VERSION_XCODE_MACOS="274.27.3723"
           VERSION_WINRES="1,15,129,0"
           VERSION_MSIPRODUCT_AMD64="89C96952-1FB8-5A4D-B02E-16A8060C56AA"
           VERSION_MSIPRODUCT_ARM64="DB1A2E86-66C4-5CEC-8F4C-7DB805370F3A"
           VERSION_MSIPRODUCT_X86="DC57C0C3-5164-5C92-86B3-2800CEFF0540"`},
		{mkInfo("abcdef", "", otherDate, 1, 2, 0, 17), `
           VERSION_MAJOR=1
           VERSION_MINOR=2
           VERSION_PATCH=0
           VERSION_SHORT="1.2.0"
           VERSION_LONG="1.2.0-17-tabcdef"
           VERSION_GIT_HASH="abcdef"
           VERSION_TRACK="stable"`},
		{mkInfo("abcdef", "defghi", otherDate, 1, 15, 0, 129), `
           VERSION_MAJOR=1
           VERSION_MINOR=15
           VERSION_PATCH=129
           VERSION_SHORT="1.15.129"
           VERSION_LONG="1.15.129-tabcdef-gdefghi"
           VERSION_GIT_HASH="abcdef"
           VERSION_TRACK="unstable"
           VERSION_EXTRA_HASH="defghi"
           VERSION_XCODE="101.15.129"
           VERSION_XCODE_MACOS="274.27.3723"
           VERSION_WINRES="1,15,129,0"
           VERSION_MSIPRODUCT_AMD64="89C96952-1FB8-5A4D-B02E-16A8060C56AA"
           VERSION_MSIPRODUCT_ARM64="DB1A2E86-66C4-5CEC-8F4C-7DB805370F3A"
           VERSION_MSIPRODUCT_X86="DC57C0C3-5164-5C92-86B3-2800CEFF0540"`},
		{mkInfo("abcdef", "", otherDate, 0, 99, 5, 0), ""},   // unstable, patch number not allowed
		{mkInfo("abcdef", "", otherDate, 0, 99, 5, 123), ""}, // unstable, patch number not allowed
		{mkInfo("abcdef", "defghi", "", 1, 15, 0, 129), ""},  // missing otherDate
	}

	for _, test := range tests {
		want := strings.ReplaceAll(strings.TrimSpace(test.want), " ", "")
		info, err := mkOutput(test.in)
		if err != nil {
			if test.want != "" {
				t.Errorf("%#v got unexpected error %v", test.in, err)
			}
			continue
		}
		got := strings.TrimSpace(info.String())
		if diff := cmp.Diff(got, want); want != "" && diff != "" {
			t.Errorf("%#v wrong output (-got+want):\n%s", test.in, diff)
		}
	}
}
