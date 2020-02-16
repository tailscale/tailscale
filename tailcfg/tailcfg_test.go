// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tailcfg

import (
	"reflect"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/wgcfg"
)

func fieldsOf(t reflect.Type) (fields []string) {
	for i := 0; i < t.NumField(); i++ {
		fields = append(fields, t.Field(i).Name)
	}
	return
}

func TestNodeEqual(t *testing.T) {
	nodeHandles := []string{"ID", "Name", "User", "Key", "KeyExpiry", "Machine", "Addresses", "AllowedIPs", "Endpoints", "Hostinfo", "Created", "LastSeen", "MachineAuthorized"}
	if have := fieldsOf(reflect.TypeOf(Node{})); !reflect.DeepEqual(have, nodeHandles) {
		t.Errorf("Node.Equal check might be out of sync\nfields: %q\nhandled: %q\n",
			have, nodeHandles)
	}

	newPublicKey := func(t *testing.T) wgcfg.Key {
		t.Helper()
		k, err := wgcfg.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		return k.Public()
	}
	n1 := newPublicKey(t)
	now := time.Now()

	tests := []struct {
		a, b *Node
		want bool
	}{
		{
			&Node{},
			nil,
			false,
		},
		{
			nil,
			&Node{},
			false,
		},
		{
			&Node{},
			&Node{},
			true,
		},
		{
			&Node{User: 0},
			&Node{User: 1},
			false,
		},
		{
			&Node{User: 1},
			&Node{User: 1},
			true,
		},
		{
			&Node{Key: NodeKey(n1)},
			&Node{Key: NodeKey(newPublicKey(t))},
			false,
		},
		{
			&Node{Key: NodeKey(n1)},
			&Node{Key: NodeKey(n1)},
			true,
		},
		{
			&Node{KeyExpiry: now},
			&Node{KeyExpiry: now.Add(60 * time.Second)},
			false,
		},
		{
			&Node{KeyExpiry: now},
			&Node{KeyExpiry: now},
			true,
		},
		{
			&Node{Machine: MachineKey(n1)},
			&Node{Machine: MachineKey(newPublicKey(t))},
			false,
		},
		{
			&Node{Machine: MachineKey(n1)},
			&Node{Machine: MachineKey(n1)},
			true,
		},
		{
			&Node{Addresses: []wgcfg.CIDR{}},
			&Node{Addresses: nil},
			false,
		},
		{
			&Node{Addresses: []wgcfg.CIDR{}},
			&Node{Addresses: []wgcfg.CIDR{}},
			true,
		},
		{
			&Node{AllowedIPs: []wgcfg.CIDR{}},
			&Node{AllowedIPs: nil},
			false,
		},
		{
			&Node{Addresses: []wgcfg.CIDR{}},
			&Node{Addresses: []wgcfg.CIDR{}},
			true,
		},
		{
			&Node{Endpoints: []string{}},
			&Node{Endpoints: nil},
			false,
		},
		{
			&Node{Endpoints: []string{}},
			&Node{Endpoints: []string{}},
			true,
		},
		{
			&Node{Hostinfo: Hostinfo{Hostname: "alice"}},
			&Node{Hostinfo: Hostinfo{Hostname: "bob"}},
			false,
		},
		{
			&Node{Hostinfo: Hostinfo{}},
			&Node{Hostinfo: Hostinfo{}},
			true,
		},
		{
			&Node{Created: now},
			&Node{Created: now.Add(60 * time.Second)},
			false,
		},
		{
			&Node{Created: now},
			&Node{Created: now},
			true,
		},
		{
			&Node{LastSeen: &now},
			&Node{LastSeen: nil},
			false,
		},
		{
			&Node{LastSeen: &now},
			&Node{LastSeen: &now},
			true,
		},
	}
	for i, tt := range tests {
		got := tt.a.Equal(tt.b)
		if got != tt.want {
			t.Errorf("%d. Equal = %v; want %v", i, got, tt.want)
		}
	}
}
