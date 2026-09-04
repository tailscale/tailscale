// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// TestDialNodeUsingProxyRejectsInvalidHostname checks that a control-supplied
// DERP hostname containing CR/LF is rejected before it can be written into the
// proxy CONNECT request line. The guard fires before the proxy is dialed, so
// the bogus proxy address here is never contacted.
func TestDialNodeUsingProxyRejectsInvalidHostname(t *testing.T) {
	c := NewRegionClient(key.NewNode(), t.Logf, netmon.NewStatic(),
		func() *tailcfg.DERPRegion { return nil })
	defer c.Close()

	n := &tailcfg.DERPNode{
		HostName: "127.0.0.1\r\nX-Injected: 1",
		DERPPort: 443,
	}
	proxyURL := &url.URL{Scheme: "http", Host: "127.0.0.1:1"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := c.dialNodeUsingProxy(ctx, n, proxyURL)
	if err == nil {
		t.Fatal("dialNodeUsingProxy accepted a hostname containing CRLF")
	}
	if !strings.Contains(err.Error(), "invalid DERP node hostname") {
		t.Fatalf("got error %v, want an invalid-hostname error", err)
	}
}
