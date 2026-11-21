// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn"
	"tailscale.com/ipn/conffile"
	"tailscale.com/tailcfg"
	"tailscale.com/util/must"
)

// TestServicesFileProxyBackendHTTP applies a 0.1.0 Services config file to a
// running node and sends requests through the Service's HTTPS listener. It
// checks which HTTP version the back-end sees, and that the node's serve
// config converts back to the file that was applied.
func TestServicesFileProxyBackendHTTP(t *testing.T) {
	if !buildfeatures.HasServe {
		t.Skip("requires Serve")
	}

	const (
		serviceName = tailcfg.ServiceName("svc:foo")
		serviceVIP  = "100.11.22.33"
	)

	tests := []struct {
		name      string
		httpField string // extra members of the "proxy" object
		wantProto int32  // HTTP major version that the back-end sees
		stream    bool   // whether to interleave request and response writes
	}{
		{
			name:      "unset",
			wantProto: 1,
		},
		{
			name:      "h2c",
			httpField: `, "http": "h2c"`,
			wantProto: 2,
			stream:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lt := setupTwoClientTest(t, false)
			host, client := lt.s2, lt.s1
			setUpServiceState(t, serviceName.String(), serviceVIP, host, client, lt.control, nil)

			// The back-end accepts HTTP/1.1 and h2c. It echoes each chunk of
			// the request body as soon as the chunk arrives.
			var gotProto atomic.Int32
			ln := must.Get(net.Listen("tcp", "127.0.0.1:0"))
			var protocols http.Protocols
			protocols.SetHTTP1(true)
			protocols.SetUnencryptedHTTP2(true)
			backend := &http.Server{
				Protocols: &protocols,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					gotProto.Store(int32(r.ProtoMajor))
					rc := http.NewResponseController(w)
					w.WriteHeader(http.StatusOK)
					rc.Flush()
					buf := make([]byte, 1024)
					for {
						n, err := r.Body.Read(buf)
						if n > 0 {
							w.Write(buf[:n])
							rc.Flush()
						}
						if err != nil {
							return
						}
					}
				}),
			}
			go backend.Serve(ln)
			t.Cleanup(func() { backend.Close() })

			filename := filepath.Join(t.TempDir(), "services.json")
			must.Do(os.WriteFile(filename, fmt.Appendf(nil, `{
				"version": "0.1.0",
				"services": {
					%q: {
						"listeners": {
							"443": {
								"protocol": "https",
								"routes": {
									"/": {"proxy": {"url": "http://%s"%s}}
								}
							}
						}
					}
				}
			}`, serviceName, ln.Addr(), tt.httpField), 0o644))
			file := must.Get(conffile.LoadServicesFile(filename, ""))
			svc := file.Services[serviceName]

			ctx := t.Context()
			st := must.Get(host.localClient.StatusWithoutPeers(ctx))
			suffix := st.CurrentTailnet.MagicDNSSuffix
			sc := must.Get(host.localClient.GetServeConfig(ctx))
			if sc == nil {
				sc = new(ipn.ServeConfig)
			}
			must.Do(svc.ApplyTo(sc, serviceName, suffix))
			must.Do(host.localClient.SetServeConfig(ctx, sc))
			must.Get(host.localClient.EditPrefs(ctx, &ipn.MaskedPrefs{
				AdvertiseServicesSet: true,
				Prefs:                ipn.Prefs{AdvertiseServices: []string{serviceName.String()}},
			}))

			stored := must.Get(host.localClient.GetServeConfig(ctx))
			exported := must.Get(conffile.ServiceFromServeConfig(serviceName, stored.Services[serviceName], suffix))
			if diff := cmp.Diff(svc, exported); diff != "" {
				t.Errorf("exported Service differs from the applied file (-applied +exported):\n%s", diff)
			}

			fqdn := serviceName.WithoutPrefix() + "." + suffix
			hc := &http.Client{
				Transport: &http.Transport{
					ForceAttemptHTTP2: true,
					DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						tcpConn, err := client.Dial(ctx, network, addr)
						if err != nil {
							return nil, err
						}
						tlsConn := tls.Client(tcpConn, &tls.Config{
							ServerName: fqdn,
							RootCAs:    testCertRoot.Pool(),
							NextProtos: []string{"h2", "http/1.1"},
						})
						if err := tlsConn.HandshakeContext(ctx); err != nil {
							tcpConn.Close()
							return nil, err
						}
						return tlsConn, nil
					},
				},
			}
			defer hc.CloseIdleConnections()

			// The content type is deliberately not a gRPC one. A gRPC content
			// type makes the proxy use h2c without any declaration.
			const contentType = "application/connect+json"
			url := "https://" + fqdn + "/"

			if !tt.stream {
				req := must.Get(http.NewRequestWithContext(ctx, "POST", url, http.NoBody))
				req.Header.Set("Content-Type", contentType)
				resp := must.Get(hc.Do(req))
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status = %v, want 200", resp.Status)
				}
				io.Copy(io.Discard, resp.Body)
			} else {
				pr, pw := io.Pipe()
				req := must.Get(http.NewRequestWithContext(ctx, "POST", url, pr))
				req.Header.Set("Content-Type", contentType)
				resp := must.Get(hc.Do(req))
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status = %v, want 200", resp.Status)
				}
				// Each message must come back before the next one is sent.
				for _, msg := range []string{"first", "second", "third"} {
					must.Get(io.WriteString(pw, msg))
					got := make([]byte, len(msg))
					if _, err := io.ReadFull(resp.Body, got); err != nil {
						t.Fatalf("reading echo of %q: %v", msg, err)
					}
					if string(got) != msg {
						t.Fatalf("echo = %q, want %q", got, msg)
					}
				}
				pw.Close()
				io.Copy(io.Discard, resp.Body)
			}

			if got := gotProto.Load(); got != tt.wantProto {
				t.Errorf("back-end saw HTTP/%d, want HTTP/%d", got, tt.wantProto)
			}
		})
	}
}
