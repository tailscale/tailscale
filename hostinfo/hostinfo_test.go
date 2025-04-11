// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package hostinfo

import (
	"encoding/json"
	"os"
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
