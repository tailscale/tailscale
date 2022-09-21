// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/control/controlclient"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
)

func fakeControlClient(t *testing.T, c *http.Client) *controlclient.Auto {
	hi := hostinfo.New()
	ni := tailcfg.NetInfo{LinkType: "wired"}
	hi.NetInfo = &ni

	k := key.NewMachine()
	opts := controlclient.Options{
		ServerURL: "https://example.com",
		Hostinfo:  hi,
		GetMachinePrivateKey: func() (key.MachinePrivate, error) {
			return k, nil
		},
		HTTPTestClient:  c,
		NoiseTestClient: c,
		Status:          func(controlclient.Status) {},
	}

	cc, err := controlclient.NewNoStart(opts)
	if err != nil {
		t.Fatal(err)
	}
	return cc
}

// NOTE: URLs must have a https scheme and example.com domain to work with the underlying
// httptest plumbing, despite the domain being unused in the actual noise request transport.
func fakeNoiseServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *http.Client) {
	ts := httptest.NewUnstartedServer(handler)
	ts.StartTLS()
	client := ts.Client()
	client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, ts.Listener.Addr().String())
	}
	return ts, client
}

func TestTKAEnablementFlow(t *testing.T) {
	networkLockAvailable = func() bool { return true } // Enable the feature flag
	nodePriv := key.NewNode()

	// Make a fake TKA authority, getting a usable genesis AUM which
	// our mock server can communicate.
	nlPriv := key.NewNLPrivate()
	key := tka.Key{Kind: tka.Key25519, Public: nlPriv.Public().Verifier(), Votes: 2}
	a1, genesisAUM, err := tka.Create(&tka.Mem{}, tka.State{
		Keys:               []tka.Key{key},
		DisablementSecrets: [][]byte{bytes.Repeat([]byte{0xa5}, 32)},
	}, nlPriv)
	if err != nil {
		t.Fatalf("tka.Create() failed: %v", err)
	}

	ts, client := fakeNoiseServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		switch r.URL.Path {
		case "/machine/tka/bootstrap":
			body := new(tailcfg.TKABootstrapRequest)
			if err := json.NewDecoder(r.Body).Decode(body); err != nil {
				t.Fatal(err)
			}
			if body.Version != tailcfg.CurrentCapabilityVersion {
				t.Errorf("bootstrap CapVer = %v, want %v", body.Version, tailcfg.CurrentCapabilityVersion)
			}
			if body.NodeKey != nodePriv.Public() {
				t.Errorf("bootstrap nodeKey=%v, want %v", body.NodeKey, nodePriv.Public())
			}
			if body.Head != "" {
				t.Errorf("bootstrap head=%s, want empty hash", body.Head)
			}

			w.WriteHeader(200)
			out := tailcfg.TKABootstrapResponse{
				GenesisAUM: genesisAUM.Serialize(),
			}
			if err := json.NewEncoder(w).Encode(out); err != nil {
				t.Fatal(err)
			}

		default:
			t.Errorf("unhandled endpoint path: %v", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()
	temp := t.TempDir()

	cc := fakeControlClient(t, client)
	b := LocalBackend{
		varRoot: temp,
		cc:      cc,
		ccAuto:  cc,
		logf:    t.Logf,
		prefs: &ipn.Prefs{
			Persist: &persist.Persist{PrivateNodeKey: nodePriv},
		},
	}

	b.mu.Lock()
	err = b.tkaSyncIfNeededLocked(&netmap.NetworkMap{
		TKAEnabled: true,
		TKAHead:    tka.AUMHash{},
	})
	b.mu.Unlock()
	if err != nil {
		t.Errorf("tkaSyncIfNeededLocked() failed: %v", err)
	}
	if b.tka == nil {
		t.Fatal("tka was not initialized")
	}
	if b.tka.authority.Head() != a1.Head() {
		t.Errorf("authority.Head() = %x, want %x", b.tka.authority.Head(), a1.Head())
	}
}

func TestTKADisablementFlow(t *testing.T) {
	networkLockAvailable = func() bool { return true } // Enable the feature flag
	temp := t.TempDir()
	os.Mkdir(filepath.Join(temp, "tka"), 0755)
	nodePriv := key.NewNode()

	// Make a fake TKA authority, to seed local state.
	disablementSecret := bytes.Repeat([]byte{0xa5}, 32)
	nlPriv := key.NewNLPrivate()
	key := tka.Key{Kind: tka.Key25519, Public: nlPriv.Public().Verifier(), Votes: 2}
	chonk, err := tka.ChonkDir(filepath.Join(temp, "tka"))
	if err != nil {
		t.Fatal(err)
	}
	authority, _, err := tka.Create(chonk, tka.State{
		Keys:               []tka.Key{key},
		DisablementSecrets: [][]byte{tka.DisablementKDF(disablementSecret)},
	}, nlPriv)
	if err != nil {
		t.Fatalf("tka.Create() failed: %v", err)
	}

	returnWrongSecret := false
	ts, client := fakeNoiseServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		switch r.URL.Path {
		case "/machine/tka/bootstrap":
			body := new(tailcfg.TKABootstrapRequest)
			if err := json.NewDecoder(r.Body).Decode(body); err != nil {
				t.Fatal(err)
			}
			if body.Version != tailcfg.CurrentCapabilityVersion {
				t.Errorf("bootstrap CapVer = %v, want %v", body.Version, tailcfg.CurrentCapabilityVersion)
			}
			if body.NodeKey != nodePriv.Public() {
				t.Errorf("nodeKey=%v, want %v", body.NodeKey, nodePriv.Public())
			}
			var head tka.AUMHash
			if err := head.UnmarshalText([]byte(body.Head)); err != nil {
				t.Fatalf("failed unmarshal of body.Head: %v", err)
			}
			if head != authority.Head() {
				t.Errorf("reported head = %x, want %x", head, authority.Head())
			}

			var disablement []byte
			if returnWrongSecret {
				disablement = bytes.Repeat([]byte{0x42}, 32) // wrong secret
			} else {
				disablement = disablementSecret
			}

			w.WriteHeader(200)
			out := tailcfg.TKABootstrapResponse{
				DisablementSecret: disablement,
			}
			if err := json.NewEncoder(w).Encode(out); err != nil {
				t.Fatal(err)
			}

		default:
			t.Errorf("unhandled endpoint path: %v", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()

	cc := fakeControlClient(t, client)
	b := LocalBackend{
		varRoot: temp,
		cc:      cc,
		ccAuto:  cc,
		logf:    t.Logf,
		tka: &tkaState{
			authority: authority,
			storage:   chonk,
		},
		prefs: &ipn.Prefs{
			Persist: &persist.Persist{PrivateNodeKey: nodePriv},
		},
	}

	// Test that the wrong disablement secret does not shut down the authority.
	returnWrongSecret = true
	b.mu.Lock()
	err = b.tkaSyncIfNeededLocked(&netmap.NetworkMap{
		TKAEnabled: false,
		TKAHead:    authority.Head(),
	})
	b.mu.Unlock()
	if err != nil {
		t.Errorf("tkaSyncIfNeededLocked() failed: %v", err)
	}
	if b.tka == nil {
		t.Error("TKA was disabled despite incorrect disablement secret")
	}

	// Test the correct disablement secret shuts down the authority.
	returnWrongSecret = false
	b.mu.Lock()
	err = b.tkaSyncIfNeededLocked(&netmap.NetworkMap{
		TKAEnabled: false,
		TKAHead:    authority.Head(),
	})
	b.mu.Unlock()
	if err != nil {
		t.Errorf("tkaSyncIfNeededLocked() failed: %v", err)
	}

	if b.tka != nil {
		t.Fatal("tka was not shut down")
	}
	if _, err := os.Stat(b.chonkPath()); err == nil || !os.IsNotExist(err) {
		t.Errorf("os.Stat(chonkDir) = %v, want ErrNotExist", err)
	}
}
