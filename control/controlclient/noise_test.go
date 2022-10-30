// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlhttp"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
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

func TestNoiseClientHTTP2Upgrade(t *testing.T) {
	serverPrivate := key.NewMachine()
	clientPrivate := key.NewMachine()

	const msg = "Hello, client"
	h2 := &http2.Server{}
	hs := httptest.NewServer(&Upgrader{
		h2srv:        h2,
		noiseKeyPriv: serverPrivate,
		httpBaseConfig: &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				io.WriteString(w, msg)
			}),
		},
	})
	defer hs.Close()

	dialer := new(tsdial.Dialer)
	nc, err := newNoiseClient(clientPrivate, serverPrivate.Public(), hs.URL, dialer, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := nc.post(context.Background(), "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	all, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(all) != msg {
		t.Errorf("got response %q; want %q", all, msg)
	}

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

	chalPub := key.NewChallenge()
	earlyWriteFn := func(protocolVersion int, w io.Writer) error {
		if !up.sendEarlyPayload {
			return nil
		}
		earlyJSON, err := json.Marshal(struct {
			NodeKeyOwnershipChallenge string
		}{chalPub.Public().String()})
		if err != nil {
			return err
		}
		// 5 bytes that won't be mistaken for an HTTP/2 frame:
		// https://httpwg.org/specs/rfc7540.html#rfc.section.4.1 (Especially not
		// an HTTP/2 settings frame, which isn't of type 'T')
		var notH2Frame = [5]byte{0xff, 0xff, 0xff, 'T', 'S'}
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

	cbConn, err := controlhttp.AcceptHTTP(r.Context(), w, r, up.noiseKeyPriv, earlyWriteFn)
	if err != nil {
		up.logf("controlhttp: Accept: %v", err)
		return
	}
	defer cbConn.Close()

	up.h2srv.ServeConn(cbConn, &http2.ServeConnOpts{
		BaseConfig: up.httpBaseConfig,
	})
}
