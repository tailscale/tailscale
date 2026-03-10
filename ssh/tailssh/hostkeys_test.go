// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || (darwin && !ios)

package tailssh

import (
	"reflect"
	"testing"
)

func TestSSHKeyGen(t *testing.T) {
	dir := t.TempDir()
	keys, err := getTailscaleHostKeys(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, k := range keys {
		got[k.PublicKey().Type()] = true
	}
	want := map[string]bool{
		"ssh-rsa":             true,
		"ecdsa-sha2-nistp256": true,
		"ssh-ed25519":         true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("keys = %v; want %v", got, want)
	}

	keys2, err := getTailscaleHostKeys(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(keys, keys2) {
		t.Errorf("got different keys on second call")
	}
}
