// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package hostinfo

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	hi := New()
	if hi == nil {
		t.Fatal("no Hostinfo")
	}
	j, err := json.MarshalIndent(hi, "  ", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Got: %s", j)
}

func TestOSVersion(t *testing.T) {
	if osVersion == nil {
		t.Skip("not available for OS")
	}
	t.Logf("Got: %#q", osVersion())
}

func TestEtcAptSourceFileIsDisabled(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"normal", "deb foo\n", false},
		{"normal-commented", "# deb foo\n", false},
		{"normal-disabled-by-ubuntu", "# deb foo # disabled on upgrade to dingus\n", true},
		{"normal-disabled-then-uncommented", "deb foo # disabled on upgrade to dingus\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := etcAptSourceFileIsDisabled(strings.NewReader(tt.in))
			if got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestCustomHostnameFunc(t *testing.T) {
	want := "custom-hostname"
	SetHostnameFn(func() (string, error) {
		return want, nil
	})

	got, err := Hostname()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	SetHostnameFn(os.Hostname)
	got, err = Hostname()
	want, _ = os.Hostname()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEnvironWithoutSystemdServiceVars(t *testing.T) {
	got := EnvironWithoutSystemdServiceVars([]string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"NOTIFY_SOCKET=/run/systemd/notify",
		"HOME=/home/user",
		"WATCHDOG_PID=1234",
		"WATCHDOG_USEC=60000000",
		"LISTEN_FDS=2",
		"LISTEN_PID=1",
		"LISTEN_FDNAMES=tailscaled.socket",
		"INVOCATION_ID=57fad4dc31874d3882b8907c50d167a2",
		"JOURNAL_STREAM=9:1234567",
		"USER=ubuntu",
	})
	want := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/home/user",
		"USER=ubuntu",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}

	// A nil env means the current environment.
	t.Setenv("NOTIFY_SOCKET", "/fake/systemd/notify")
	got = EnvironWithoutSystemdServiceVars(nil)
	for _, kv := range got {
		if strings.HasPrefix(kv, "NOTIFY_SOCKET=") {
			t.Errorf("current-environment form leaked %q", kv)
		}
	}
	found := false
	for _, kv := range os.Environ() {
		if kv == "NOTIFY_SOCKET=/fake/systemd/notify" {
			found = true
		}
	}
	if !found {
		t.Errorf("test setup: NOTIFY_SOCKET not in os.Environ()")
	}
}
