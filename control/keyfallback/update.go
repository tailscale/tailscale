// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

func main() {
	keyURL := fmt.Sprintf("%v/key?v=%d", ipn.DefaultControlURL, tailcfg.CurrentCapabilityVersion)
	res, err := http.Get(keyURL)
	if err != nil {
		log.Fatalf("fetch control key: %v", err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		log.Fatalf("read control key: %v", err)
	}
	if res.StatusCode != 200 {
		log.Fatalf("fetch control key: bad status; got %v, want 200", res.Status)
	}

	// Unmarshal to make sure it's valid.
	var out tailcfg.OverTLSPublicKeyResponse
	if err := json.Unmarshal(b, &out); err != nil {
		log.Fatalf("unmarshal control key: %v", err)
	}
	if out.PublicKey.IsZero() {
		log.Fatalf("control key is zero")
	}

	if err := os.WriteFile("control-key.json", b, 0644); err != nil {
		log.Fatalf("write control key: %v", err)
	}
}
