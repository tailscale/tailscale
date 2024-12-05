// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tka

import (
	"testing"
)

func TestGenerateDeeplink(t *testing.T) {
	pub, _ := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}
	c := newTestchain(t, `
        G1 -> L1

        G1.template = genesis
    `,
		optTemplate("genesis", AUM{MessageKind: AUMCheckpoint, State: &State{
			Keys:               []Key{key},
			DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
		}}),
	)
	a, _ := Open(c.Chonk())

	nodeKey := "nodekey:1234567890"
	tlPub := "tlpub:1234567890"
	deviceName := "Example Device"
	osName := "iOS"
	loginName := "insecure@example.com"

	deeplink, err := a.NewDeeplink(NewDeeplinkParams{
		NodeKey:    nodeKey,
		TLPub:      tlPub,
		DeviceName: deviceName,
		OSName:     osName,
		LoginName:  loginName,
	})
	if err != nil {
		t.Errorf("deeplink generation failed: %v", err)
	}

	res := a.ValidateDeeplink(deeplink)
	if !res.IsValid {
		t.Errorf("deeplink validation failed: %s", res.Error)
	}
	if res.NodeKey != nodeKey {
		t.Errorf("node key mismatch: %s != %s", res.NodeKey, nodeKey)
	}
	if res.TLPub != tlPub {
		t.Errorf("tlpub mismatch: %s != %s", res.TLPub, tlPub)
	}
}
