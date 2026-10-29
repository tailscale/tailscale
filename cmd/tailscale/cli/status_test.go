// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
)

func TestStatusNoTraffic(t *testing.T) {
	for _, online := range []bool{true, false} {
		want := "offline"
		if online {
			want = "online"
		}
		t.Run(want, func(t *testing.T) {
			st := &ipnstate.Status{
				BackendState: "Running",
				Self: &ipnstate.PeerStatus{
					HostName:     "device",
					OS:           "linux",
					TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
					Online:       online,
				},
			}
			peer := *st.Self
			peer.HostName = "peer"
			peer.TailscaleIPs = []netip.Addr{netip.MustParseAddr("100.64.0.2")}
			st.Peer = map[key.NodePublic]*ipnstate.PeerStatus{key.NewNode().Public(): &peer}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/localapi/v0/serve-config" {
					io.WriteString(w, "null")
					return
				}
				if r.URL.Path != "/localapi/v0/status" {
					http.NotFound(w, r)
					return
				}
				if err := json.NewEncoder(w).Encode(st); err != nil {
					t.Error(err)
				}
			}))
			defer srv.Close()
			tstest.Replace(t, &localClient, local.Client{
				Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
				},
			})
			tstest.Replace(t, &statusArgs.self, true)
			tstest.Replace(t, &statusArgs.peers, true)
			var out bytes.Buffer
			tstest.Replace[io.Writer](t, &Stdout, &out)
			if err := runStatus(context.Background(), nil); err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSpace(out.String()), "\n")
			if len(lines) != 2 {
				t.Fatalf("status output = %q; want self and peer rows", out.String())
			}
			for _, line := range lines {
				fields := strings.Fields(line)
				if len(fields) != 5 || fields[4] != want {
					t.Errorf("status row = %q; want five columns ending in %q", line, want)
				}
			}
		})
	}
}
