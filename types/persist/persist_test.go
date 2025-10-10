// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package persist

import (
	"reflect"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func fieldsOf(t reflect.Type) (fields []string) {
	for i := range t.NumField() {
		if name := t.Field(i).Name; name != "_" {
			fields = append(fields, name)
		}
	}
	return
}

func TestPersistEqual(t *testing.T) {
	persistHandles := []string{"PrivateNodeKey", "OldPrivateNodeKey", "UserProfile", "NetworkLockKey", "NodeID", "AttestationKey", "DisallowedTKAStateIDs"}
	if have := fieldsOf(reflect.TypeFor[Persist]()); !reflect.DeepEqual(have, persistHandles) {
		t.Errorf("Persist.Equal check might be out of sync\nfields: %q\nhandled: %q\n",
			have, persistHandles)
	}

	k1 := key.NewNode()
	nl1 := key.NewNLPrivate()
	tests := []struct {
		a, b *Persist
		want bool
	}{
		{nil, nil, true},
		{nil, &Persist{}, false},
		{&Persist{}, nil, false},
		{&Persist{}, &Persist{}, true},

		{
			&Persist{PrivateNodeKey: k1},
			&Persist{PrivateNodeKey: key.NewNode()},
			false,
		},
		{
			&Persist{PrivateNodeKey: k1},
			&Persist{PrivateNodeKey: k1},
			true,
		},

		{
			&Persist{OldPrivateNodeKey: k1},
			&Persist{OldPrivateNodeKey: key.NewNode()},
			false,
		},
		{
			&Persist{OldPrivateNodeKey: k1},
			&Persist{OldPrivateNodeKey: k1},
			true,
		},

		{
			&Persist{UserProfile: tailcfg.UserProfile{
				ID: tailcfg.UserID(3),
			}},
			&Persist{UserProfile: tailcfg.UserProfile{
				ID: tailcfg.UserID(3),
			}},
			true,
		},
		{
			&Persist{UserProfile: tailcfg.UserProfile{
				ID: tailcfg.UserID(3),
			}},
			&Persist{UserProfile: tailcfg.UserProfile{
				ID:          tailcfg.UserID(3),
				DisplayName: "foo",
			}},
			false,
		},
		{
			&Persist{NetworkLockKey: nl1},
			&Persist{NetworkLockKey: nl1},
			true,
		},
		{
			&Persist{NetworkLockKey: nl1},
			&Persist{NetworkLockKey: key.NewNLPrivate()},
			false,
		},
		{
			&Persist{NodeID: "abc"},
			&Persist{NodeID: "abc"},
			true,
		},
		{
			&Persist{NodeID: ""},
			&Persist{NodeID: "abc"},
			false,
		},
		{
			&Persist{DisallowedTKAStateIDs: nil},
			&Persist{DisallowedTKAStateIDs: []string{"0:0"}},
			false,
		},
		{
			&Persist{DisallowedTKAStateIDs: []string{"0:1"}},
			&Persist{DisallowedTKAStateIDs: []string{"0:1"}},
			true,
		},
		{
			&Persist{DisallowedTKAStateIDs: []string{}},
			&Persist{DisallowedTKAStateIDs: nil},
			true,
		},
	}
	for i, test := range tests {
		if got := test.a.Equals(test.b); got != test.want {
			t.Errorf("%d. Equals = %v; want %v", i, got, test.want)
		}
	}
}
