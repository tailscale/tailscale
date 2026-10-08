// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derpserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/memnet"
	"tailscale.com/net/netmon"
	"tailscale.com/tstest"
	"tailscale.com/tstest/tlstest"
	"tailscale.com/types/key"
)

// TestHandlerUpgradeWriteTimeout verifies that a client that stops reading the
// HTTP upgrade response cannot leave the handler blocked indefinitely.
func TestHandlerUpgradeWriteTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs tstest.MemLogger
		logf := func(format string, args ...any) {
			t.Logf(format, args...)
			logs.Logf(format, args...)
		}
		s := New(key.NewNode(), logf)
		defer s.Close()
		ln := memnet.Listen("derp:80")
		ln.NewConn = func(_, addr string, _ int) (memnet.Conn, memnet.Conn) {
			return memnet.NewConn(addr, 1)
		}
		done := make(chan struct{})
		h := Handler(s)
		hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
			close(done)
		})}
		defer hs.Close()
		go hs.Serve(ln)
		c, err := ln.Dial(context.Background(), "tcp", "derp:80")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := io.WriteString(c, "GET /derp HTTP/1.1\r\nHost: derp\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		// A peer that stops consuming the upgrade response must still be
		// subject to the ten-second handshake write timeout.
		time.Sleep(11 * time.Second)
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Error("upgrade response is still blocked after the handshake timeout")
		}

		// The timed-out write must have taken the error path, which logs
		// and closes the connection rather than handing it off to Accept.
		if want := "writing upgrade response"; !strings.Contains(logs.String(), want) {
			t.Errorf("server log does not contain %q; got:\n%s", want, logs.String())
		}
		// After draining whatever partial response made it into the
		// buffer, the client should see EOF from the server's close, not
		// a still-open connection.
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.Copy(io.Discard, c); err != nil {
			t.Errorf("draining conn: %v; want EOF (server-side close)", err)
		}
	})
}

// TestHandlerTLSReaderSize verifies that ordinary and fast-start TLS connections
// use a small reader without disrupting packet delivery.
func TestHandlerTLSReaderSize(t *testing.T) {
	for _, fast := range []bool{false, true} {
		name := "ordinary"
		if fast {
			name = "fast_start"
		}
		t.Run(name, func(t *testing.T) {
			s := New(key.NewNode(), t.Logf)
			defer s.Close()
			h := Handler(s)
			fastHeader := make(chan string, 1)
			hs := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fastHeader <- r.Header.Get(derp.FastStartHeader)
				r.Header.Set(derp.IdealNodeHeader, "other-node")
				h.ServeHTTP(w, r)
			}))
			defer hs.Close()
			hs.TLS = tlstest.Derper.ServerTLSConfig()
			if fast {
				hs.TLS.Certificates[0].Certificate = append(hs.TLS.Certificates[0].Certificate, s.MetaCert())
			}
			hs.StartTLS()
			priv := key.NewNode()
			c, err := derphttp.NewClient(priv, "https://"+string(tlstest.Derper)+"/derp", t.Logf, netmon.NewStatic())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(tlstest.TestRootCA())
			c.TLSConfig = &tls.Config{RootCAs: roots}
			c.SetURLDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, hs.Listener.Addr().String())
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stop := context.AfterFunc(ctx, func() { c.Close() })
			defer stop()
			if err := c.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			if m, err := c.Recv(); err != nil {
				t.Fatal(err)
			} else if _, ok := m.(derp.ServerInfoMessage); !ok {
				t.Fatalf("first message is %T", m)
			}
			if got := <-fastHeader; (got == "1") != fast {
				t.Fatalf("fast-start header = %q, want fast=%v", got, fast)
			}
			cs, ok := s.clients.Load(priv.Public())
			if !ok {
				t.Fatal("client not registered")
			}
			sc := cs.activeClient.Load()
			if !sc.isNotIdealConn {
				t.Error("ideal-node header was lost")
			}
			payload := bytes.Repeat([]byte("x"), 4096)
			if err := c.Send(priv.Public(), payload); err != nil {
				t.Fatal(err)
			}
			m, err := c.Recv()
			if err != nil {
				t.Fatal(err)
			}
			if p, ok := m.(derp.ReceivedPacket); !ok || !bytes.Equal(p.Data, payload) {
				t.Fatalf("unexpected packet: %T", m)
			}
			if size := sc.br.Size(); size != 1024 {
				t.Errorf("standing reader size = %d, want 1024", size)
			}
		})
	}
}
