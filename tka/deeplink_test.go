// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tka

import (
	"encoding/hex"
	"net/url"
	"testing"
)

func TestGenerateDeeplink(t *testing.T) {
	pub, _ := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}
	c := newTestchain(t, `
        G1 -> L1

        G1.template = genesis
    `, genesisTemplate(key),
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

func TestValidateDeeplinkMissingParam(t *testing.T) {
	pub, _ := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}
	c := newTestchain(t, `
        G1 -> L1

        G1.template = genesis
    `, genesisTemplate(key),
	)
	a, _ := Open(c.Chonk())

	tests := []struct {
		param   string
		clear   func(*NewDeeplinkParams)
		wantErr string
	}{
		{"nk", func(p *NewDeeplinkParams) { p.NodeKey = "" }, "missing nk (NodeKey) query parameter"},
		{"tp", func(p *NewDeeplinkParams) { p.TLPub = "" }, "missing tp (TLPub) query parameter"},
		{"dn", func(p *NewDeeplinkParams) { p.DeviceName = "" }, "missing dn (DeviceName) query parameter"},
		{"os", func(p *NewDeeplinkParams) { p.OSName = "" }, "missing os (OSName) query parameter"},
		{"em", func(p *NewDeeplinkParams) { p.LoginName = "" }, "missing em (EmailAddress) query parameter"},
	}
	for _, tt := range tests {
		t.Run(tt.param, func(t *testing.T) {
			params := NewDeeplinkParams{
				NodeKey:    "nodekey:1234567890",
				TLPub:      "tlpub:1234567890",
				DeviceName: "Example Device",
				OSName:     "iOS",
				LoginName:  "insecure@example.com",
			}
			tt.clear(&params)

			// Build the link by hand, since NewDeeplink refuses empty
			// fields. The HMAC covers the empty field, so only the
			// missing parameter check can reject the link.
			v := url.Values{}
			for k, val := range map[string]string{
				"nk": params.NodeKey,
				"tp": params.TLPub,
				"dn": params.DeviceName,
				"os": params.OSName,
				"em": params.LoginName,
			} {
				if val != "" {
					v.Set(k, val)
				}
			}
			v.Set("hm", hex.EncodeToString(a.generateHMAC(params)))
			u := url.URL{
				Scheme:   DeeplinkTailscaleURLScheme,
				Host:     DeeplinkCommandSign,
				Path:     "/v1/",
				RawQuery: v.Encode(),
			}

			res := a.ValidateDeeplink(u.String())
			if res.IsValid {
				t.Fatalf("deeplink without %q validated successfully", tt.param)
			}
			if res.Error != tt.wantErr {
				t.Errorf("error = %q; want %q", res.Error, tt.wantErr)
			}
		})
	}
}
