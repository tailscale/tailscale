// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"reflect"
	"testing"

	"github.com/tailscale/wireguard-go/wgcfg"
)

func TestPersistEqual(t *testing.T) {
	persistHandles := []string{"LegacyFrontendPrivateMachineKey", "PrivateNodeKey", "OldPrivateNodeKey", "Provider", "LoginName"}
	if have := fieldsOf(reflect.TypeOf(Persist{})); !reflect.DeepEqual(have, persistHandles) {
		t.Errorf("Persist.Equal check might be out of sync\nfields: %q\nhandled: %q\n",
			have, persistHandles)
	}

	newPrivate := func() wgcfg.PrivateKey {
		k, err := wgcfg.NewPrivateKey()
		if err != nil {
			panic(err)
		}
		return k
	}
	k1 := newPrivate()
	tests := []struct {
		a, b *Persist
		want bool
	}{
		{nil, nil, true},
		{nil, &Persist{}, false},
		{&Persist{}, nil, false},
		{&Persist{}, &Persist{}, true},

		{
			&Persist{LegacyFrontendPrivateMachineKey: k1},
			&Persist{LegacyFrontendPrivateMachineKey: newPrivate()},
			false,
		},
		{
			&Persist{LegacyFrontendPrivateMachineKey: k1},
			&Persist{LegacyFrontendPrivateMachineKey: k1},
			true,
		},

		{
			&Persist{PrivateNodeKey: k1},
			&Persist{PrivateNodeKey: newPrivate()},
			false,
		},
		{
			&Persist{PrivateNodeKey: k1},
			&Persist{PrivateNodeKey: k1},
			true,
		},

		{
			&Persist{OldPrivateNodeKey: k1},
			&Persist{OldPrivateNodeKey: newPrivate()},
			false,
		},
		{
			&Persist{OldPrivateNodeKey: k1},
			&Persist{OldPrivateNodeKey: k1},
			true,
		},

		{
			&Persist{Provider: "google"},
			&Persist{Provider: "o365"},
			false,
		},
		{
			&Persist{Provider: "google"},
			&Persist{Provider: "google"},
			true,
		},

		{
			&Persist{LoginName: "foo@tailscale.com"},
			&Persist{LoginName: "bar@tailscale.com"},
			false,
		},
		{
			&Persist{LoginName: "foo@tailscale.com"},
			&Persist{LoginName: "foo@tailscale.com"},
			true,
		},
	}
	for i, test := range tests {
		if got := test.a.Equals(test.b); got != test.want {
			t.Errorf("%d. Equals = %v; want %v", i, got, test.want)
		}
	}
}
