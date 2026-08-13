// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android && !ts_package_container

package hostinfo

import (
	"errors"
	"testing"
)

func TestQnap(t *testing.T) {
	version_info := `commit 2910d3a594b068024ed01a64a0fe4168cb001a12
Date:   2022-05-30 16:08:45 +0800
================================================
* QTSFW_5.0.0
remotes/origin/QTSFW_5.0.0`

	got := getQnapQtsVersion(version_info)
	want := "5.0.0"
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}

	got = getQnapQtsVersion("")
	want = ""
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}

	got = getQnapQtsVersion("just a bunch of junk")
	want = ""
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestPackageTypeNotContainer(t *testing.T) {
	var got string
	if packageType != nil {
		got = packageType()
	}
	if got == "container" {
		t.Fatal("packageType = container; should only happen if build tag ts_package_container is set")
	}
}

type fakeLogindRunner struct {
	sessions     []byte
	sessionErr   error
	sessionTypes map[string]string
}

func (f *fakeLogindRunner) listSessions() ([]byte, error) {
	return f.sessions, f.sessionErr
}

func (f *fakeLogindRunner) getSessionType(session string) (string, error) {
	return f.sessionTypes[session], nil
}

func TestSystemdLogindFindDesktop(t *testing.T) {
	tests := []struct {
		name   string
		runner *fakeLogindRunner
		want   bool
	}{
		{
			name: "listSessions-error",
			runner: &fakeLogindRunner{
				sessionErr: errors.New("loginctl not found"),
			},
			want: false,
		},
		{
			name: "invalid-json",
			runner: &fakeLogindRunner{
				sessions: []byte(`not json`),
			},
			want: false,
		},
		{
			name: "empty",
			runner: &fakeLogindRunner{
				sessions: []byte(`[]`),
			},
			want: false,
		},
		{
			name: "x11",
			runner: &fakeLogindRunner{
				sessions:     []byte(`[{"session":"1"}]`),
				sessionTypes: map[string]string{"1": "x11"},
			},
			want: true,
		},
		{
			name: "wayland",
			runner: &fakeLogindRunner{
				sessions:     []byte(`[{"session":"2"}]`),
				sessionTypes: map[string]string{"2": "wayland"},
			},
			want: true,
		},
		{
			name: "mir",
			runner: &fakeLogindRunner{
				sessions:     []byte(`[{"session":"3"}]`),
				sessionTypes: map[string]string{"3": "mir"},
			},
			want: true,
		},
		{
			name: "tty",
			runner: &fakeLogindRunner{
				sessions:     []byte(`[{"session":"4"}]`),
				sessionTypes: map[string]string{"4": "tty"},
			},
			want: false,
		},
		{
			name: "unspecified",
			runner: &fakeLogindRunner{
				sessions:     []byte(`[{"session":"5"}]`),
				sessionTypes: map[string]string{"5": "unspecified"},
			},
			want: false,
		},
		{
			name: "downcase",
			runner: &fakeLogindRunner{
				sessions:     []byte(`[{"session":"6"}]`),
				sessionTypes: map[string]string{"6": "WaYlAnD"},
			},
			want: true,
		},
		{
			name: "malformed",
			runner: &fakeLogindRunner{
				sessions:     []byte(`[{"session":"7"}]`),
				sessionTypes: map[string]string{"7": "TypeWayland"},
			},
			want: false,
		},
		{
			name: "multiple-no-desktop",
			runner: &fakeLogindRunner{
				sessions: []byte(`[{"session":"8"},{"session":"9"}]`),
				sessionTypes: map[string]string{
					"8": "tty",
					"9": "unspecified",
				},
			},
			want: false,
		},
		{
			name: "multiple-desktop",
			runner: &fakeLogindRunner{
				sessions: []byte(`[{"session":"10"},{"session":"11"}]`),
				sessionTypes: map[string]string{
					"10": "tty",
					"11": "wayland",
				},
			},
			want: true,
		},
		{
			name: "alpha-session",
			runner: &fakeLogindRunner{
				sessions:     []byte(`[{"session":"someSession"}]`),
				sessionTypes: map[string]string{"someSession": "wayland"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := systemdLogindFindDesktop(tt.runner); got != tt.want {
				t.Errorf("systemdLogindFindDesktop() = %v; want %v", got, tt.want)
			}
		})
	}
}
