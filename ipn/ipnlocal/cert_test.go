// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"errors"
	"testing"

	"tailscale.com/tailcfg"
)

func TestCertStatus(t *testing.T) {
	b := &LocalBackend{}

	if _, err := b.CertStatus("node.example.ts.net"); !errors.Is(err, errNoCerts) {
		t.Fatalf("CertStatus without ACME support: err = %v, want %v", err, errNoCerts)
	}

	want := &tailcfg.C2NTLSCertInfo{Missing: true, Error: "no certificate"}
	var gotDomain string
	t.Cleanup(HookCertStatus.SetForTest(func(hb *LocalBackend, domain string) (*tailcfg.C2NTLSCertInfo, error) {
		if hb != b {
			t.Errorf("hook called with a different LocalBackend")
		}
		gotDomain = domain
		return want, nil
	}))
	got, err := b.CertStatus("node.example.ts.net")
	if err != nil {
		t.Fatalf("CertStatus: %v", err)
	}
	if got != want {
		t.Errorf("CertStatus = %+v, want %+v", got, want)
	}
	if gotDomain != "node.example.ts.net" {
		t.Errorf("hook got domain %q, want %q", gotDomain, "node.example.ts.net")
	}
}
