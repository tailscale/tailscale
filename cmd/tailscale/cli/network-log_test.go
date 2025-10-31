// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/cmd/tailscale/cli/jsonoutput"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tka"
	"tailscale.com/types/tkatype"
)

func TestNetworkLockLogOutput(t *testing.T) {
	aum1 := tka.AUM{
		MessageKind: tka.AUMCheckpoint,
		State: &tka.State{
			Keys: []tka.Key{
				{
					Kind:   tka.Key25519,
					Votes:  1,
					Public: []byte{1, 1},
				},
			},
			DisablementSecrets: [][]byte{
				{1, 2, 3},
				{4, 5, 6},
				{7, 8, 9},
			},
		},
	}
	h1 := aum1.Hash()
	aum2 := tka.AUM{
		MessageKind: tka.AUMAddKey,
		Key: &tka.Key{
			Kind:   tka.Key25519,
			Votes:  1,
			Public: []byte{2, 2},
		},
		PrevAUMHash: h1[:],
		State:       &tka.State{},
	}
	h2 := aum2.Hash()
	aum3 := tka.AUM{
		MessageKind: tka.AUMRemoveKey,
		KeyID:       []byte{3, 3},
		PrevAUMHash: h2[:],
		State:       &tka.State{},
		Signatures: []tkatype.Signature{
			{
				KeyID:     []byte{3, 4},
				Signature: []byte{4, 5},
			},
		},
	}

	updates := []ipnstate.NetworkLockUpdate{
		{
			Hash:   aum3.Hash(),
			Change: aum3.MessageKind.String(),
			Raw:    aum3.Serialize(),
		},
		{
			Hash:   aum2.Hash(),
			Change: aum2.MessageKind.String(),
			Raw:    aum2.Serialize(),
		},
		{
			Hash:   aum1.Hash(),
			Change: aum1.MessageKind.String(),
			Raw:    aum1.Serialize(),
		},
	}

	t.Run("human-readable", func(t *testing.T) {
		t.Parallel()

		var outBuf bytes.Buffer
		json := jsonoutput.JSONSchemaVersion{}
		useColor := false

		printNetworkLockLog(updates, &outBuf, &json, useColor)

		want := `update D3FLVPFAB5MAVOY572IFTRAWHSYLJEKHQ33MWWICFNHS3UEDRJTA (remove-key)
KeyID: tlpub:0303

update YWWMHTE7L7WNIBXQFNUIEPOO4VMQ5SG4GDCUKFBG4ISTUHTF6GNQ (add-key)
Type: 25519
KeyID: tlpub:0202

update C4CRI2FP246RDASCLR6QIX6WTXKW7G64HXN6LZVLQNWU6EKSOPBA (checkpoint)
Disablement values:
 - 010203
 - 040506
 - 070809
Keys:
  Type: 25519
  KeyID: tlpub:0101

`

		if diff := cmp.Diff(outBuf.String(), want); diff != "" {
			t.Fatalf("wrong output (-got, +want):\n%s", diff)
		}
	})

	jsonV1 := `{
  "SchemaVersion": "1",
  "Messages": [
    {
      "Hash": "D3FLVPFAB5MAVOY572IFTRAWHSYLJEKHQ33MWWICFNHS3UEDRJTA",
      "AUM": {
        "MessageKind": "remove-key",
        "PrevAUMHash": "YWWMHTE7L7WNIBXQFNUIEPOO4VMQ5SG4GDCUKFBG4ISTUHTF6GNQ",
        "Key": null,
        "KeyID": "tlpub:0303",
        "State": {
          "LastAUMHash": null,
          "DisablementSecrets": null,
          "Keys": null,
          "StateID1": 0,
          "StateID2": 0
        },
        "Votes": null,
        "Meta": null,
        "Signatures": [
          {
            "KeyID": "tlpub:0304",
            "Signature": "BAU="
          }
        ]
      },
      "Raw": "pQECAlggxazDzJ9f7NQG8Ctogj3O5VkOyNwwxUUUJuIlOh5l8ZsEQgMDBaMB9gL2A_YXgaIBQgMEAkIEBQ=="
    },
    {
      "Hash": "YWWMHTE7L7WNIBXQFNUIEPOO4VMQ5SG4GDCUKFBG4ISTUHTF6GNQ",
      "AUM": {
        "MessageKind": "add-key",
        "PrevAUMHash": "C4CRI2FP246RDASCLR6QIX6WTXKW7G64HXN6LZVLQNWU6EKSOPBA",
        "Key": {
          "Kind": "25519",
          "Votes": 1,
          "Public": "tlpub:0202",
          "Meta": null
        },
        "KeyID": null,
        "State": {
          "LastAUMHash": null,
          "DisablementSecrets": null,
          "Keys": null,
          "StateID1": 0,
          "StateID2": 0
        },
        "Votes": null,
        "Meta": null,
        "Signatures": null
      },
      "Raw": "pAEBAlggFwUUaK_XPRGCQlx9BF_WndVvm9w92-Xmq4NtTxFSc8IDowEBAgEDQgICBaMB9gL2A_Y="
    },
    {
      "Hash": "C4CRI2FP246RDASCLR6QIX6WTXKW7G64HXN6LZVLQNWU6EKSOPBA",
      "AUM": {
        "MessageKind": "checkpoint",
        "PrevAUMHash": null,
        "Key": null,
        "KeyID": null,
        "State": {
          "LastAUMHash": null,
          "DisablementSecrets": [
            "AQID",
            "BAUG",
            "BwgJ"
          ],
          "Keys": [
            {
              "Kind": "25519",
              "Votes": 1,
              "Public": "tlpub:0101",
              "Meta": null
            }
          ],
          "StateID1": 0,
          "StateID2": 0
        },
        "Votes": null,
        "Meta": null,
        "Signatures": null
      },
      "Raw": "owEFAvYFowH2AoNDAQIDQwQFBkMHCAkDgaMBAQIBA0IBAQ=="
    }
  ]
}
`

	t.Run("json-1", func(t *testing.T) {
		t.Parallel()

		var outBuf bytes.Buffer
		json := jsonoutput.JSONSchemaVersion{
			IsSet: true,
			Value: 1,
		}
		useColor := false

		printNetworkLockLog(updates, &outBuf, &json, useColor)

		want := jsonV1

		if diff := cmp.Diff(outBuf.String(), want); diff != "" {
			t.Fatalf("wrong output (-got, +want):\n%s", diff)
		}
	})
}
