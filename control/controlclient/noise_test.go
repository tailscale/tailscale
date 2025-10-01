// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/control/ts2021"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/nettest"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus/eventbustest"
)

// maxAllowedNoiseVersion is the highest we expect the Tailscale
// capability version to ever get. It's a value close to 2^16, but
// with enough leeway that we get a very early warning that it's time
// to rework the wire protocol to allow larger versions, while still
// giving us headroom to bump this test and fix the build.
//
// Code elsewhere in the client will panic() if the tailcfg capability
// version exceeds 16 bits, so take a failure of this test seriously.
const maxAllowedNoiseVersion = math.MaxUint16 - 5000

func TestNoiseVersion(t *testing.T) {
	if tailcfg.CurrentCapabilityVersion > maxAllowedNoiseVersion {
		t.Fatalf("tailcfg.CurrentCapabilityVersion is %d, want <=%d", tailcfg.CurrentCapabilityVersion, maxAllowedNoiseVersion)
	}
}

type noiseClientTest struct {
	sendEarlyPayload bool
}

func TestNoiseClientHTTP2Upgrade(t *testing.T) {
	noiseClientTest{}.run(t)
}

func TestNoiseClientHTTP2Upgrade_earlyPayload(t *testing.T) {
	noiseClientTest{
		sendEarlyPayload: true,
	}.run(t)
}

func makeClientWithURL(t *testing.T, url string) *NoiseClient {
	nc, err := NewNoiseClient(NoiseOpts{
		Logf:      t.Logf,
		ServerURL: url,
	})
	if err != nil {
		t.Fatal(err)
	}
	return nc
}

func TestNoiseClientPortsAreSet(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantHTTPS string
		wantHTTP  string
	}{
		{
			name:      "https-url",
			url:       "https://example.com",
			wantHTTPS: "443",
			wantHTTP:  "80",
		},
		{
			name:      "http-url",
			url:       "http://example.com",
			wantHTTPS: "443", // TODO(bradfitz): questionable; change?
			wantHTTP:  "80",
		},
		{
			name:      "https-url-custom-port",
			url:       "https://example.com:123",
			wantHTTPS: "123",
			wantHTTP:  "",
		},
		{
			name:      "http-url-custom-port",
			url:       "http://example.com:123",
			wantHTTPS: "443", // TODO(bradfitz): questionable; change?
			wantHTTP:  "123",
		},
		{
			name:      "http-loopback-no-port",
			url:       "http://127.0.0.1",
			wantHTTPS: "",
			wantHTTP:  "80",
		},
		{
			name:      "http-loopback-custom-port",
			url:       "http://127.0.0.1:8080",
			wantHTTPS: "",
			wantHTTP:  "8080",
		},
		{
			name:      "http-localhost-no-port",
			url:       "http://localhost",
			wantHTTPS: "",
			wantHTTP:  "80",
		},
		{
			name:      "http-localhost-custom-port",
			url:       "http://localhost:8080",
			wantHTTPS: "",
			wantHTTP:  "8080",
		},
		{
			name:      "http-private-ip-no-port",
			url:       "http://192.168.2.3",
			wantHTTPS: "",
			wantHTTP:  "80",
		},
		{
			name:      "http-private-ip-custom-port",
			url:       "http://192.168.2.3:8080",
			wantHTTPS: "",
			wantHTTP:  "8080",
		},
		{
			name:      "http-public-ip",
			url:       "http://1.2.3.4",
			wantHTTPS: "443", // TODO(bradfitz): questionable; change?
			wantHTTP:  "80",
		},
		{
			name:      "http-public-ip-custom-port",
			url:       "http://1.2.3.4:8080",
			wantHTTPS: "443", // TODO(bradfitz): questionable; change?
			wantHTTP:  "8080",
		},
		{
			name:      "https-public-ip",
			url:       "https://1.2.3.4",
			wantHTTPS: "443",
			wantHTTP:  "80",
		},
		{
			name:      "https-public-ip-custom-port",
			url:       "https://1.2.3.4:8080",
			wantHTTPS: "8080",
			wantHTTP:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nc := makeClientWithURL(t, tt.url)
			if nc.httpsPort != tt.wantHTTPS {
				t.Errorf("nc.httpsPort = %q; want %q", nc.httpsPort, tt.wantHTTPS)
			}
			if nc.httpPort != tt.wantHTTP {
				t.Errorf("nc.httpPort = %q; want %q", nc.httpPort, tt.wantHTTP)
			}
		})
	}
}

func (tt noiseClientTest) run(t *testing.T) {
	serverPrivate := key.NewMachine()
	clientPrivate := key.NewMachine()
	chalPrivate := key.NewChallenge()
	bus := eventbustest.NewBus(t)

	const msg = "Hello, client"
	h2 := &http2.Server{}
	nw := nettest.GetNetwork(t)
	hs := nettest.NewHTTPServer(nw, &Upgrader{
		h2srv:            h2,
		noiseKeyPriv:     serverPrivate,
		sendEarlyPayload: tt.sendEarlyPayload,
		challenge:        chalPrivate,
		httpBaseConfig: &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				io.WriteString(w, msg)
			}),
		},
	})
	defer hs.Close()

	dialer := tsdial.NewDialer(netmon.NewStatic())
	dialer.SetBus(bus)
	if nettest.PreferMemNetwork() {
		dialer.SetSystemDialerForTest(nw.Dial)
	}

	nc, err := NewNoiseClient(NoiseOpts{
		PrivKey:      clientPrivate,
		ServerPubKey: serverPrivate.Public(),
		ServerURL:    hs.URL,
		Dialer:       dialer,
		Logf:         t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Get a conn and verify it read its early payload before the http/2
	// handshake.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := nc.getConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := c.GetEarlyPayload(ctx)
	if err != nil {
		t.Fatal("timed out waiting for didReadHeaderCh")
	}

	gotNonNil := payload != nil
	if gotNonNil != tt.sendEarlyPayload {
		t.Errorf("sendEarlyPayload = %v but got earlyPayload = %T", tt.sendEarlyPayload, payload)
	}
	if payload != nil {
		if payload.NodeKeyChallenge != chalPrivate.Public() {
			t.Errorf("earlyPayload.NodeKeyChallenge = %v; want %v", payload.NodeKeyChallenge, chalPrivate.Public())
		}
	}

	checkRes := func(t *testing.T, res *http.Response) {
		t.Helper()
		defer res.Body.Close()
		all, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(all) != msg {
			t.Errorf("got response %q; want %q", all, msg)
		}
	}

	// And verify we can do HTTP/2 against that conn.
	res, err := (&http.Client{Transport: c}).Get("https://unused.example/")
	if err != nil {
		t.Fatal(err)
	}
	checkRes(t, res)

	// And try using the high-level nc.post API as well.
	res, err = nc.post(context.Background(), "/", key.NodePublic{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkRes(t, res)
}

// Upgrader is an http.Handler that hijacks and upgrades POST-with-Upgrade
// request to a Tailscale 2021 connection, then hands the resulting
// controlbase.Conn off to h2srv.
type Upgrader struct {
	// h2srv is that will handle requests after the
	// connection has been upgraded to HTTP/2-over-noise.
	h2srv *http2.Server

	// httpBaseConfig is the http1 server config that h2srv is
	// associated with.
	httpBaseConfig *http.Server

	logf logger.Logf

	noiseKeyPriv key.MachinePrivate
	challenge    key.ChallengePrivate

	sendEarlyPayload bool
}

func (up *Upgrader) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if up == nil || up.h2srv == nil {
		http.Error(w, "invalid server config", http.StatusServiceUnavailable)
		return
	}
	if r.URL.Path != "/ts2021" {
		http.Error(w, "ts2021 upgrader installed at wrong path", http.StatusBadGateway)
		return
	}
	if up.noiseKeyPriv.IsZero() {
		http.Error(w, "keys not available", http.StatusServiceUnavailable)
		return
	}

	earlyWriteFn := func(protocolVersion int, w io.Writer) error {
		if !up.sendEarlyPayload {
			return nil
		}
		earlyJSON, err := json.Marshal(&tailcfg.EarlyNoise{
			NodeKeyChallenge: up.challenge.Public(),
		})
		if err != nil {
			return err
		}
		// 5 bytes that won't be mistaken for an HTTP/2 frame:
		// https://httpwg.org/specs/rfc7540.html#rfc.section.4.1 (Especially not
		// an HTTP/2 settings frame, which isn't of type 'T')
		var notH2Frame [5]byte
		copy(notH2Frame[:], ts2021.EarlyPayloadMagic)
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(earlyJSON)))
		// These writes are all buffered by caller, so fine to do them
		// separately:
		if _, err := w.Write(notH2Frame[:]); err != nil {
			return err
		}
		if _, err := w.Write(lenBuf[:]); err != nil {
			return err
		}
		if _, err := w.Write(earlyJSON[:]); err != nil {
			return err
		}
		return nil
	}

	cbConn, err := controlhttpserver.AcceptHTTP(r.Context(), w, r, up.noiseKeyPriv, earlyWriteFn)
	if err != nil {
		up.logf("controlhttp: Accept: %v", err)
		return
	}
	defer cbConn.Close()

	up.h2srv.ServeConn(cbConn, &http2.ServeConnOpts{
		BaseConfig: up.httpBaseConfig,
	})
}
