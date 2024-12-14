// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package keyfallback contains a fallback mechanism for starting up Tailscale
// when the control server cannot be reached to obtain the primary Noise key.
//
// The data is backed by a JSON file `control-key.json` that is updated by
// `update.go`:
//
//	(cd control/keyfallback; go run update.go)
package keyfallback

import (
	_ "embed"
	"encoding/json"

	"tailscale.com/tailcfg"
)

// Get returns the fallback control server public key that was baked into the
// binary at compile time. It is only valid for the main Tailscale control
// server instance.
func Get() (*tailcfg.OverTLSPublicKeyResponse, error) {
	out := &tailcfg.OverTLSPublicKeyResponse{}
	if err := json.Unmarshal(controlKeyJSON, out); err != nil {
		return nil, err
	}
	return out, nil
}

//go:embed control-key.json
var controlKeyJSON []byte
