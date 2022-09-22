// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || (darwin && !ios)
// +build linux darwin,!ios

package ipnlocal

import (
	"encoding/json"
	"reflect"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/util/must"
)

func TestSSHKeyGen(t *testing.T) {
	dir := t.TempDir()
	lb := &LocalBackend{varRoot: dir}
	keys, err := lb.getTailscaleSSH_HostKeys(nil)
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

	keys2, err := lb.getTailscaleSSH_HostKeys(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(keys, keys2) {
		t.Errorf("got different keys on second call")
	}
}

type fakeSSHServer struct {
	SSHServer
}

func TestGetSSHUsernames(t *testing.T) {
	b := new(LocalBackend)
	b.sshServer = fakeSSHServer{}
	res, err := b.getSSHUsernames(new(tailcfg.C2NSSHUsernamesRequest))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Got: %s", must.Get(json.Marshal(res)))
}
