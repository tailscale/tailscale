// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || (darwin && !ios)

package tailssh

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSSHKeyGen(t *testing.T) {
	dir := t.TempDir()
	keys, err := getTailscaleHostKeys(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Private host keys must be readable by the owner only: 0600, not 0700,
	// which would allow the key directory to be walked into by others.
	for _, typ := range keyTypes {
		fi, err := os.Stat(filepath.Join(dir, "ssh", "ssh_host_"+typ+"_key"))
		if err != nil {
			t.Fatalf("stat host key: %v", err)
		}
		if got := fi.Mode().Perm(); got != 0600 {
			t.Errorf("host key %s mode = %o; want 0600", typ, got)
		}
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
