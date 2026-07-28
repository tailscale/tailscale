// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package testcontrol_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tailscale.com/control/ts2021"
	"tailscale.com/control/tsp"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/util/must"
)

// TestStreamingMapReqReadOnlyByVersion verifies that testcontrol matches
// production control's streaming-is-read-only semantics for clients at
// capability version >= 68. Per tailcfg.MapRequest.Stream docs, a streaming
// MapRequest from a cap>=68 client must be treated as read-only by the
// server (Endpoints/Hostinfo/DiscoKey are sent separately via a non-streaming
// /machine/map call), so the streaming MapRequest's zero-valued DiscoKey
// must not clobber the node's currently stored DiscoKey.
//
// For older (cap<68) clients, the streaming MapRequest is still a write and
// writes do happen, so DiscoKey=zero in the request does clobber.
func TestStreamingMapReqReadOnlyByVersion(t *testing.T) {
	tests := []struct {
		version     tailcfg.CapabilityVersion
		wantClobber bool
	}{
		{67, true},  // pre-cap-68: streaming is a write, DiscoKey=zero clobbers.
		{68, false}, // cap>=68: streaming is read-only, DiscoKey unchanged.
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("v%d", tt.version), func(t *testing.T) {
			ctrl := &testcontrol.Server{}
			ctrl.HTTPTestServer = httptest.NewUnstartedServer(ctrl)
			ctrl.HTTPTestServer.Start()
			t.Cleanup(ctrl.HTTPTestServer.Close)
			baseURL := ctrl.HTTPTestServer.URL

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			serverKey := must.Get(tsp.DiscoverServerKey(ctx, baseURL))

			// Register a node and push a known DiscoKey via SendMapUpdate
			// (a non-streaming, unambiguously-a-write request).
			nodeKey := key.NewNode()
			machineKey := key.NewMachine()
			wantDisco := key.NewDisco().Public()

			tc := must.Get(tsp.NewClient(tsp.ClientOpts{
				ServerURL:  baseURL,
				MachineKey: machineKey,
			}))
			defer tc.Close()
			tc.SetControlPublicKey(serverKey)
			must.Get(tc.Register(ctx, tsp.RegisterOpts{
				NodeKey:  nodeKey,
				Hostinfo: &tailcfg.Hostinfo{Hostname: "target"},
			}))
			if err := tc.SendMapUpdate(ctx, tsp.SendMapUpdateOpts{
				NodeKey:  nodeKey,
				DiscoKey: wantDisco,
				Hostinfo: &tailcfg.Hostinfo{Hostname: "target"},
			}); err != nil {
				t.Fatalf("SendMapUpdate: %v", err)
			}
			if n := ctrl.Node(nodeKey.Public()); n == nil || n.DiscoKey != wantDisco {
				t.Fatalf("pre: DiscoKey not set; node=%+v", n)
			}

			// Fire a streaming MapRequest with the chosen Version and a
			// zero DiscoKey. Use ts2021 directly because tsp.Map hardcodes
			// Version to tailcfg.CurrentCapabilityVersion.
			nc := must.Get(ts2021.NewClient(ts2021.ClientOpts{
				ServerURL:    baseURL,
				PrivKey:      machineKey,
				ServerPubKey: serverKey,
				Dialer:       tsdial.NewFromFuncForDebug(t.Logf, (&net.Dialer{}).DialContext),
			}))
			defer nc.Close()

			body := must.Get(json.Marshal(&tailcfg.MapRequest{
				Version: tt.version,
				NodeKey: nodeKey.Public(),
				Stream:  true,
				// DiscoKey intentionally zero.
			}))
			reqURL := strings.Replace(baseURL+"/machine/map", "http:", "https:", 1)
			reqCtx, reqCancel := context.WithCancel(ctx)
			defer reqCancel()
			req := must.Get(http.NewRequestWithContext(reqCtx, "POST", reqURL, bytes.NewReader(body)))
			ts2021.AddLBHeader(req, nodeKey.Public())

			// nc.Do returns once response headers arrive, which in
			// testcontrol's serveMap is AFTER the write branch has run
			// (or been skipped). So by the time this returns, any write
			// this request is going to do has already happened.
			res, err := nc.Do(req)
			if err != nil {
				t.Fatalf("nc.Do: %v", err)
			}
			res.Body.Close() // tears down the streaming session server-side

			got := ctrl.Node(nodeKey.Public())
			if got == nil {
				t.Fatal("node disappeared")
			}
			switch {
			case tt.wantClobber && !got.DiscoKey.IsZero():
				t.Errorf("v%d: expected DiscoKey clobbered to zero, got %v", tt.version, got.DiscoKey)
			case !tt.wantClobber && got.DiscoKey != wantDisco:
				t.Errorf("v%d: DiscoKey changed from %v to %v; should have been left alone",
					tt.version, wantDisco, got.DiscoKey)
			}
		})
	}
}
