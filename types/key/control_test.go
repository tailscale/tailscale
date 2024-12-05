// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"encoding/json"
	"testing"
)

func TestControlKey(t *testing.T) {
	serialized := `{"PrivateKey":[36,132,249,6,73,141,249,49,9,96,49,60,240,217,253,57,3,69,248,64,178,62,121,73,121,88,115,218,130,145,68,254]}`
	want := ControlPrivate{
		MachinePrivate{
			k: [32]byte{36, 132, 249, 6, 73, 141, 249, 49, 9, 96, 49, 60, 240, 217, 253, 57, 3, 69, 248, 64, 178, 62, 121, 73, 121, 88, 115, 218, 130, 145, 68, 254},
		},
	}

	var got struct {
		PrivateKey ControlPrivate
	}
	if err := json.Unmarshal([]byte(serialized), &got); err != nil {
		t.Fatalf("decoding serialized ControlPrivate: %v", err)
	}

	if !got.PrivateKey.mkey.Equal(want.mkey) {
		t.Fatalf("Serialized ControlPrivate didn't deserialize as expected, got %v want %v", got.PrivateKey, want)
	}

	bs, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json reserialization of ControlPrivate failed: %v", err)
	}

	if got, want := string(bs), serialized; got != want {
		t.Fatalf("ControlPrivate didn't round-trip, got %q want %q", got, want)
	}
}
