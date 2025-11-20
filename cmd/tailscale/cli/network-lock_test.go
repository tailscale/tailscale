// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go4.org/mem"
	"tailscale.com/cmd/tailscale/cli/jsonoutput"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
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

		var outBuf bytes.Buffer
		json := jsonoutput.JSONSchemaVersion{
			IsSet: true,
			Value: 1,
		}
		useColor := false

		printNetworkLockLog(updates, &outBuf, json, useColor)

		want := jsonV1

		if diff := cmp.Diff(outBuf.String(), want); diff != "" {
			t.Fatalf("wrong output (-got, +want):\n%s", diff)
		}
	})
}

func TestNetworkLockStatusOutput(t *testing.T) {
	aum := tka.AUM{
		MessageKind: tka.AUMNoOp,
	}
	h := aum.Hash()
	head := [32]byte(h[:])

	nodeKey1 := key.NodePublicFromRaw32(mem.B(bytes.Repeat([]byte{1}, 32)))
	nodeKey2 := key.NodePublicFromRaw32(mem.B(bytes.Repeat([]byte{2}, 32)))
	nodeKey3 := key.NodePublicFromRaw32(mem.B(bytes.Repeat([]byte{3}, 32)))

	nlPub := key.NLPublicFromEd25519Unsafe(bytes.Repeat([]byte{4}, 32))

	trustedNlPub := key.NLPublicFromEd25519Unsafe(bytes.Repeat([]byte{5}, 32))

	tailnetIPv4_A, tailnetIPv6_A := netip.MustParseAddr("100.99.99.99"), netip.MustParseAddr("fd7a:115c:a1e0::701:b62a")
	tailnetIPv4_B, tailnetIPv6_B := netip.MustParseAddr("100.88.88.88"), netip.MustParseAddr("fd7a:115c:a1e0::4101:512f")

	t.Run("json-1", func(t *testing.T) {
		for _, tt := range []struct {
			Name   string
			Status ipnstate.NetworkLockStatus
			Want   string
		}{
			{
				Name:   "tailnet-lock-disabled",
				Status: ipnstate.NetworkLockStatus{Enabled: false},
				Want: `{
  "SchemaVersion": "1",
  "Enabled": false
}
`,
			},
			{
				Name: "tailnet-lock-disabled-with-keys",
				Status: ipnstate.NetworkLockStatus{
					Enabled:   false,
					NodeKey:   &nodeKey1,
					PublicKey: trustedNlPub,
				},
				Want: `{
  "SchemaVersion": "1",
  "Enabled": false,
  "PublicKey": "tlpub:0505050505050505050505050505050505050505050505050505050505050505",
  "NodeKey": "nodekey:0101010101010101010101010101010101010101010101010101010101010101"
}
`,
			},
			{
				Name: "tailnet-lock-enabled",
				Status: ipnstate.NetworkLockStatus{
					Enabled:          true,
					Head:             &head,
					PublicKey:        nlPub,
					NodeKey:          &nodeKey1,
					NodeKeySigned:    false,
					NodeKeySignature: nil,
					TrustedKeys: []ipnstate.TKAKey{
						{
							Kind:     tka.Key25519.String(),
							Votes:    1,
							Key:      trustedNlPub,
							Metadata: map[string]string{"en": "one", "de": "eins", "es": "uno"},
						},
					},
					VisiblePeers: []*ipnstate.TKAPeer{
						{
							Name:         "authentic-associate",
							ID:           tailcfg.NodeID(1234),
							StableID:     tailcfg.StableNodeID("1234_AAAA_TEST"),
							TailscaleIPs: []netip.Addr{tailnetIPv4_A, tailnetIPv6_A},
							NodeKey:      nodeKey2,
							NodeKeySignature: tka.NodeKeySignature{
								SigKind:        tka.SigDirect,
								Pubkey:         []byte("22222222222222222222222222222222"),
								KeyID:          []byte("44444444444444444444444444444444"),
								Signature:      []byte("1234567890"),
								WrappingPubkey: []byte("0987654321"),
							},
						},
					},
					FilteredPeers: []*ipnstate.TKAPeer{
						{
							Name:         "bogus-bandit",
							ID:           tailcfg.NodeID(5678),
							StableID:     tailcfg.StableNodeID("5678_BBBB_TEST"),
							TailscaleIPs: []netip.Addr{tailnetIPv4_B, tailnetIPv6_B},
							NodeKey:      nodeKey3,
						},
					},
					StateID: 98989898,
				},
				Want: `{
  "SchemaVersion": "1",
  "Enabled": true,
  "PublicKey": "tlpub:0404040404040404040404040404040404040404040404040404040404040404",
  "NodeKey": "nodekey:0101010101010101010101010101010101010101010101010101010101010101",
  "Head": "WYIVHDR7JUIXBWAJT5UPSCAILEXB7OMINDFEFEPOPNTUCNXMY2KA",
  "NodeKeySigned": false,
  "NodeKeySignature": null,
  "TrustedKeys": [
    {
      "Kind": "25519",
      "Votes": 1,
      "Public": "tlpub:0505050505050505050505050505050505050505050505050505050505050505",
      "Meta": {
        "de": "eins",
        "en": "one",
        "es": "uno"
      }
    }
  ],
  "VisiblePeers": [
    {
      "ID": "1234_AAAA_TEST",
      "DNSName": "authentic-associate",
      "TailscaleIPs": [
        "100.99.99.99",
        "fd7a:115c:a1e0::701:b62a"
      ],
      "NodeKey": "nodekey:0202020202020202020202020202020202020202020202020202020202020202",
      "NodeKeySignature": {
        "SigKind": "direct",
        "PublicKey": "tlpub:3232323232323232323232323232323232323232323232323232323232323232",
        "KeyID": "tlpub:3434343434343434343434343434343434343434343434343434343434343434",
        "Signature": "MTIzNDU2Nzg5MA==",
        "WrappingPublicKey": "tlpub:30393837363534333231"
      }
    }
  ],
  "FilteredPeers": [
    {
      "ID": "5678_BBBB_TEST",
      "DNSName": "bogus-bandit",
      "TailscaleIPs": [
        "100.88.88.88",
        "fd7a:115c:a1e0::4101:512f"
      ],
      "NodeKey": "nodekey:0303030303030303030303030303030303030303030303030303030303030303"
    }
  ],
  "State": 98989898
}
`,
			},
		} {
			t.Run(tt.Name, func(t *testing.T) {
				t.Parallel()

				var outBuf bytes.Buffer
				err := jsonoutput.PrintNetworkLockStatusJSONV1(&outBuf, &tt.Status)
				if err != nil {
					t.Fatalf("PrintNetworkLockStatusJSONV1: %v", err)
				}

				if diff := cmp.Diff(outBuf.String(), tt.Want); diff != "" {
					t.Fatalf("wrong output (-got, +want):\n%s", diff)
				}
			})
		}
	})
}
