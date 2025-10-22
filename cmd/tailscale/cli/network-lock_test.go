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
	votes := uint(1)
	aum1 := tka.AUM{
		MessageKind: tka.AUMAddKey,
		Key: &tka.Key{
			Kind:   tka.Key25519,
			Votes:  1,
			Public: []byte{2, 2},
		},
	}
	h1 := aum1.Hash()
	aum2 := tka.AUM{
		MessageKind: tka.AUMRemoveKey,
		KeyID:       []byte{3, 3},
		PrevAUMHash: h1[:],
		Signatures: []tkatype.Signature{
			{
				KeyID:     []byte{3, 4},
				Signature: []byte{4, 5},
			},
		},
		Meta: map[string]string{"en": "three", "de": "drei", "es": "tres"},
	}
	h2 := aum2.Hash()
	aum3 := tka.AUM{
		MessageKind: tka.AUMCheckpoint,
		PrevAUMHash: h2[:],
		State: &tka.State{
			Keys: []tka.Key{
				{
					Kind:   tka.Key25519,
					Votes:  1,
					Public: []byte{1, 1},
					Meta:   map[string]string{"en": "one", "de": "eins", "es": "uno"},
				},
			},
			DisablementSecrets: [][]byte{
				{1, 2, 3},
				{4, 5, 6},
				{7, 8, 9},
			},
		},
		Votes: &votes,
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

		printNetworkLockLog(updates, &outBuf, json, useColor)

		t.Logf("%s", outBuf.String())

		want := `update 4M4Q3IXBARPQMFVXHJBDCYQMWU5H5FBKD7MFF75HE4O5JMIWR2UA (checkpoint)
Disablement values:
 - 010203
 - 040506
 - 070809
Keys:
  Type: 25519
  KeyID: tlpub:0101
  Metadata: map[de:eins en:one es:uno]

update BKVVXHOVBW7Y7YXYTLVVLMNSYG6DS5GVRVSYZLASNU3AQKA732XQ (remove-key)
KeyID: tlpub:0303

update UKJIKFHILQ62AEN7MQIFHXJ6SFVDGQCQA3OHVI3LWVPM736EMSAA (add-key)
Type: 25519
KeyID: tlpub:0202

`

		if diff := cmp.Diff(outBuf.String(), want); diff != "" {
			t.Fatalf("wrong output (-got, +want):\n%s", diff)
		}
	})

	jsonV1 := `{
  "SchemaVersion": "1",
  "Messages": [
    {
      "Hash": "4M4Q3IXBARPQMFVXHJBDCYQMWU5H5FBKD7MFF75HE4O5JMIWR2UA",
      "AUM": {
        "MessageKind": "checkpoint",
        "PrevAUMHash": "BKVVXHOVBW7Y7YXYTLVVLMNSYG6DS5GVRVSYZLASNU3AQKA732XQ",
        "State": {
          "DisablementSecrets": [
            "010203",
            "040506",
            "070809"
          ],
          "Keys": [
            {
              "Kind": "25519",
              "Votes": 1,
              "Public": "tlpub:0101",
              "Meta": {
                "de": "eins",
                "en": "one",
                "es": "uno"
              }
            }
          ],
          "StateID1": 0,
          "StateID2": 0
        },
        "Votes": 1
      },
      "Raw": "pAEFAlggCqtbndUNv4_i-JrrVbGywbw5dNWNZYysEm02CCgf3q8FowH2AoNDAQIDQwQFBkMHCAkDgaQBAQIBA0IBAQyjYmRlZGVpbnNiZW5jb25lYmVzY3VubwYB"
    },
    {
      "Hash": "BKVVXHOVBW7Y7YXYTLVVLMNSYG6DS5GVRVSYZLASNU3AQKA732XQ",
      "AUM": {
        "MessageKind": "remove-key",
        "PrevAUMHash": "UKJIKFHILQ62AEN7MQIFHXJ6SFVDGQCQA3OHVI3LWVPM736EMSAA",
        "KeyID": "tlpub:0303",
        "Meta": {
          "de": "drei",
          "en": "three",
          "es": "tres"
        },
        "Signatures": [
          {
            "KeyID": "tlpub:0304",
            "Signature": "BAU="
          }
        ]
      },
      "Raw": "pQECAlggopKFFOhcPaARv2QQU90-kWozQFAG3Hqja7Vez-_EZIAEQgMDB6NiZGVkZHJlaWJlbmV0aHJlZWJlc2R0cmVzF4GiAUIDBAJCBAU="
    },
    {
      "Hash": "UKJIKFHILQ62AEN7MQIFHXJ6SFVDGQCQA3OHVI3LWVPM736EMSAA",
      "AUM": {
        "MessageKind": "add-key",
        "Key": {
          "Kind": "25519",
          "Votes": 1,
          "Public": "tlpub:0202"
        }
      },
      "Raw": "owEBAvYDowEBAgEDQgIC"
    }
  ]
}
`

	t.Run("json-1", func(t *testing.T) {
		t.Parallel()
		t.Logf("BOOM")

		var outBuf bytes.Buffer
		json := jsonoutput.JSONSchemaVersion{
			IsSet: true,
			Value: 1,
		}
		useColor := false

		printNetworkLockLog(updates, &outBuf, json, useColor)

		want := jsonV1
		t.Logf("%s", outBuf.String())

		if diff := cmp.Diff(outBuf.String(), want); diff != "" {
			t.Fatalf("wrong output (-got, +want):\n%s", diff)
		}
	})
}
