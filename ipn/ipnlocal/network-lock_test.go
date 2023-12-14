// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/control/controlclient"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/types/tkatype"
	"tailscale.com/util/must"
)

type observerFunc func(controlclient.Status)

func (f observerFunc) SetControlClientStatus(_ controlclient.Client, s controlclient.Status) {
	f(s)
}

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
		Observer:        observerFunc(func(controlclient.Status) {}),
	}

	cc, err := controlclient.NewNoStart(opts)
	if err != nil {
		t.Fatal(err)
	}
	return cc
}

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

		// Sync offer/send endpoints are hit even though the node is up-to-date,
		// so we implement enough of a fake that the client doesn't explode.
		case "/machine/tka/sync/offer":
			head, err := a1.Head().MarshalText()
			if err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(200)
			if err := json.NewEncoder(w).Encode(tailcfg.TKASyncOfferResponse{
				Head: string(head),
			}); err != nil {
				t.Fatal(err)
			}
		case "/machine/tka/sync/send":
			head, err := a1.Head().MarshalText()
			if err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(200)
			if err := json.NewEncoder(w).Encode(tailcfg.TKASyncSendResponse{
				Head: string(head),
			}); err != nil {
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
	pm := must.Get(newProfileManager(new(mem.Store), t.Logf))
	must.Do(pm.SetPrefs((&ipn.Prefs{
		Persist: &persist.Persist{
			PrivateNodeKey: nodePriv,
			NetworkLockKey: nlPriv,
		},
	}).View(), ipn.NetworkProfile{}))
	b := LocalBackend{
		capTailnetLock: true,
		varRoot:        temp,
		cc:             cc,
		ccAuto:         cc,
		logf:           t.Logf,
		pm:             pm,
		store:          pm.Store(),
	}

	err = b.tkaSyncIfNeeded(&netmap.NetworkMap{
		TKAEnabled: true,
		TKAHead:    a1.Head(),
	}, pm.CurrentPrefs())
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
	nodePriv := key.NewNode()

	// Make a fake TKA authority, to seed local state.
	disablementSecret := bytes.Repeat([]byte{0xa5}, 32)
	nlPriv := key.NewNLPrivate()
	key := tka.Key{Kind: tka.Key25519, Public: nlPriv.Public().Verifier(), Votes: 2}

	pm := must.Get(newProfileManager(new(mem.Store), t.Logf))
	must.Do(pm.SetPrefs((&ipn.Prefs{
		Persist: &persist.Persist{
			PrivateNodeKey: nodePriv,
			NetworkLockKey: nlPriv,
		},
	}).View(), ipn.NetworkProfile{}))

	temp := t.TempDir()
	tkaPath := filepath.Join(temp, "tka-profile", string(pm.CurrentProfile().ID))
	os.Mkdir(tkaPath, 0755)
	chonk, err := tka.ChonkDir(tkaPath)
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
		pm:    pm,
		store: pm.Store(),
	}

	// Test that the wrong disablement secret does not shut down the authority.
	returnWrongSecret = true
	err = b.tkaSyncIfNeeded(&netmap.NetworkMap{
		TKAEnabled: false,
		TKAHead:    authority.Head(),
	}, pm.CurrentPrefs())
	if err != nil {
		t.Errorf("tkaSyncIfNeededLocked() failed: %v", err)
	}
	if b.tka == nil {
		t.Error("TKA was disabled despite incorrect disablement secret")
	}

	// Test the correct disablement secret shuts down the authority.
	returnWrongSecret = false
	err = b.tkaSyncIfNeeded(&netmap.NetworkMap{
		TKAEnabled: false,
		TKAHead:    authority.Head(),
	}, pm.CurrentPrefs())
	if err != nil {
		t.Errorf("tkaSyncIfNeededLocked() failed: %v", err)
	}

	if b.tka != nil {
		t.Fatal("tka was not shut down")
	}
	if _, err := os.Stat(b.chonkPathLocked()); err == nil || !os.IsNotExist(err) {
		t.Errorf("os.Stat(chonkDir) = %v, want ErrNotExist", err)
	}
}

func TestTKASync(t *testing.T) {
	someKeyPriv := key.NewNLPrivate()
	someKey := tka.Key{Kind: tka.Key25519, Public: someKeyPriv.Public().Verifier(), Votes: 1}

	disablementSecret := bytes.Repeat([]byte{0xa5}, 32)

	type tkaSyncScenario struct {
		name string
		// controlAUMs is called (if non-nil) to get any AUMs which the tka state
		// on control should be seeded with.
		controlAUMs func(*testing.T, *tka.Authority, tka.Chonk, tka.Signer) []tka.AUM
		// controlAUMs is called (if non-nil) to get any AUMs which the tka state
		// on the node should be seeded with.
		nodeAUMs func(*testing.T, *tka.Authority, tka.Chonk, tka.Signer) []tka.AUM
	}

	tcs := []tkaSyncScenario{
		{name: "up to date"},
		{
			name: "control has an update",
			controlAUMs: func(t *testing.T, a *tka.Authority, storage tka.Chonk, signer tka.Signer) []tka.AUM {
				b := a.NewUpdater(signer)
				if err := b.RemoveKey(someKey.MustID()); err != nil {
					t.Fatal(err)
				}
				aums, err := b.Finalize(storage)
				if err != nil {
					t.Fatal(err)
				}
				return aums
			},
		},
		{
			// AKA 'control data loss' scenario
			name: "node has an update",
			nodeAUMs: func(t *testing.T, a *tka.Authority, storage tka.Chonk, signer tka.Signer) []tka.AUM {
				b := a.NewUpdater(signer)
				if err := b.RemoveKey(someKey.MustID()); err != nil {
					t.Fatal(err)
				}
				aums, err := b.Finalize(storage)
				if err != nil {
					t.Fatal(err)
				}
				return aums
			},
		},
		{
			// AKA 'control data loss + update in the meantime' scenario
			name: "node and control diverge",
			controlAUMs: func(t *testing.T, a *tka.Authority, storage tka.Chonk, signer tka.Signer) []tka.AUM {
				b := a.NewUpdater(signer)
				if err := b.SetKeyMeta(someKey.MustID(), map[string]string{"ye": "swiggity"}); err != nil {
					t.Fatal(err)
				}
				aums, err := b.Finalize(storage)
				if err != nil {
					t.Fatal(err)
				}
				return aums
			},
			nodeAUMs: func(t *testing.T, a *tka.Authority, storage tka.Chonk, signer tka.Signer) []tka.AUM {
				b := a.NewUpdater(signer)
				if err := b.SetKeyMeta(someKey.MustID(), map[string]string{"ye": "swooty"}); err != nil {
					t.Fatal(err)
				}
				aums, err := b.Finalize(storage)
				if err != nil {
					t.Fatal(err)
				}
				return aums
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			nodePriv := key.NewNode()
			nlPriv := key.NewNLPrivate()
			pm := must.Get(newProfileManager(new(mem.Store), t.Logf))
			must.Do(pm.SetPrefs((&ipn.Prefs{
				Persist: &persist.Persist{
					PrivateNodeKey: nodePriv,
					NetworkLockKey: nlPriv,
				},
			}).View(), ipn.NetworkProfile{}))

			// Setup the tka authority on the control plane.
			key := tka.Key{Kind: tka.Key25519, Public: nlPriv.Public().Verifier(), Votes: 2}
			controlStorage := &tka.Mem{}
			controlAuthority, bootstrap, err := tka.Create(controlStorage, tka.State{
				Keys:               []tka.Key{key, someKey},
				DisablementSecrets: [][]byte{tka.DisablementKDF(disablementSecret)},
			}, nlPriv)
			if err != nil {
				t.Fatalf("tka.Create() failed: %v", err)
			}
			if tc.controlAUMs != nil {
				if err := controlAuthority.Inform(controlStorage, tc.controlAUMs(t, controlAuthority, controlStorage, nlPriv)); err != nil {
					t.Fatalf("controlAuthority.Inform() failed: %v", err)
				}
			}

			temp := t.TempDir()
			tkaPath := filepath.Join(temp, "tka-profile", string(pm.CurrentProfile().ID))
			os.Mkdir(tkaPath, 0755)
			// Setup the TKA authority on the node.
			nodeStorage, err := tka.ChonkDir(tkaPath)
			if err != nil {
				t.Fatal(err)
			}
			nodeAuthority, err := tka.Bootstrap(nodeStorage, bootstrap)
			if err != nil {
				t.Fatalf("tka.Bootstrap() failed: %v", err)
			}
			if tc.nodeAUMs != nil {
				if err := nodeAuthority.Inform(nodeStorage, tc.nodeAUMs(t, nodeAuthority, nodeStorage, nlPriv)); err != nil {
					t.Fatalf("nodeAuthority.Inform() failed: %v", err)
				}
			}

			// Make a mock control server.
			ts, client := fakeNoiseServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer r.Body.Close()
				switch r.URL.Path {
				case "/machine/tka/sync/offer":
					body := new(tailcfg.TKASyncOfferRequest)
					if err := json.NewDecoder(r.Body).Decode(body); err != nil {
						t.Fatal(err)
					}
					t.Logf("got sync offer:\n%+v", body)
					nodeOffer, err := toSyncOffer(body.Head, body.Ancestors)
					if err != nil {
						t.Fatal(err)
					}
					controlOffer, err := controlAuthority.SyncOffer(controlStorage)
					if err != nil {
						t.Fatal(err)
					}
					sendAUMs, err := controlAuthority.MissingAUMs(controlStorage, nodeOffer)
					if err != nil {
						t.Fatal(err)
					}

					head, ancestors, err := fromSyncOffer(controlOffer)
					if err != nil {
						t.Fatal(err)
					}
					resp := tailcfg.TKASyncOfferResponse{
						Head:        head,
						Ancestors:   ancestors,
						MissingAUMs: make([]tkatype.MarshaledAUM, len(sendAUMs)),
					}
					for i, a := range sendAUMs {
						resp.MissingAUMs[i] = a.Serialize()
					}

					t.Logf("responding to sync offer with:\n%+v", resp)
					w.WriteHeader(200)
					if err := json.NewEncoder(w).Encode(resp); err != nil {
						t.Fatal(err)
					}

				case "/machine/tka/sync/send":
					body := new(tailcfg.TKASyncSendRequest)
					if err := json.NewDecoder(r.Body).Decode(body); err != nil {
						t.Fatal(err)
					}
					t.Logf("got sync send:\n%+v", body)

					var remoteHead tka.AUMHash
					if err := remoteHead.UnmarshalText([]byte(body.Head)); err != nil {
						t.Fatalf("head unmarshal: %v", err)
					}
					toApply := make([]tka.AUM, len(body.MissingAUMs))
					for i, a := range body.MissingAUMs {
						if err := toApply[i].Unserialize(a); err != nil {
							t.Fatalf("decoding missingAUM[%d]: %v", i, err)
						}
					}

					if len(toApply) > 0 {
						if err := controlAuthority.Inform(controlStorage, toApply); err != nil {
							t.Fatalf("control.Inform(%+v) failed: %v", toApply, err)
						}
					}
					head, err := controlAuthority.Head().MarshalText()
					if err != nil {
						t.Fatal(err)
					}

					w.WriteHeader(200)
					if err := json.NewEncoder(w).Encode(tailcfg.TKASyncSendResponse{
						Head: string(head),
					}); err != nil {
						t.Fatal(err)
					}

				default:
					t.Errorf("unhandled endpoint path: %v", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer ts.Close()

			// Setup the client.
			cc := fakeControlClient(t, client)
			b := LocalBackend{
				varRoot: temp,
				cc:      cc,
				ccAuto:  cc,
				logf:    t.Logf,
				pm:      pm,
				store:   pm.Store(),
				tka: &tkaState{
					authority: nodeAuthority,
					storage:   nodeStorage,
				},
			}

			// Finally, lets trigger a sync.
			err = b.tkaSyncIfNeeded(&netmap.NetworkMap{
				TKAEnabled: true,
				TKAHead:    controlAuthority.Head(),
			}, pm.CurrentPrefs())
			if err != nil {
				t.Errorf("tkaSyncIfNeededLocked() failed: %v", err)
			}

			// Check that at the end of this ordeal, the node and the control
			// plane are in sync.
			if nodeHead, controlHead := b.tka.authority.Head(), controlAuthority.Head(); nodeHead != controlHead {
				t.Errorf("node head = %v, want %v", nodeHead, controlHead)
			}
		})
	}
}

func TestTKAFilterNetmap(t *testing.T) {
	nlPriv := key.NewNLPrivate()
	nlKey := tka.Key{Kind: tka.Key25519, Public: nlPriv.Public().Verifier(), Votes: 2}
	storage := &tka.Mem{}
	authority, _, err := tka.Create(storage, tka.State{
		Keys:               []tka.Key{nlKey},
		DisablementSecrets: [][]byte{bytes.Repeat([]byte{0xa5}, 32)},
	}, nlPriv)
	if err != nil {
		t.Fatalf("tka.Create() failed: %v", err)
	}

	n1, n2, n3, n4, n5 := key.NewNode(), key.NewNode(), key.NewNode(), key.NewNode(), key.NewNode()
	n1GoodSig, err := signNodeKey(tailcfg.TKASignInfo{NodePublic: n1.Public()}, nlPriv)
	if err != nil {
		t.Fatal(err)
	}
	n4Sig, err := signNodeKey(tailcfg.TKASignInfo{NodePublic: n4.Public()}, nlPriv)
	if err != nil {
		t.Fatal(err)
	}
	n4Sig.Signature[3] = 42 // mess up the signature
	n4Sig.Signature[4] = 42 // mess up the signature
	n5GoodSig, err := signNodeKey(tailcfg.TKASignInfo{NodePublic: n5.Public()}, nlPriv)
	if err != nil {
		t.Fatal(err)
	}

	nm := &netmap.NetworkMap{
		Peers: nodeViews([]*tailcfg.Node{
			{ID: 1, Key: n1.Public(), KeySignature: n1GoodSig.Serialize()},
			{ID: 2, Key: n2.Public(), KeySignature: nil},                   // missing sig
			{ID: 3, Key: n3.Public(), KeySignature: n1GoodSig.Serialize()}, // someone elses sig
			{ID: 4, Key: n4.Public(), KeySignature: n4Sig.Serialize()},     // messed-up signature
			{ID: 5, Key: n5.Public(), KeySignature: n5GoodSig.Serialize()},
		}),
	}

	b := &LocalBackend{
		logf: t.Logf,
		tka:  &tkaState{authority: authority},
	}
	b.tkaFilterNetmapLocked(nm)

	want := nodeViews([]*tailcfg.Node{
		{ID: 1, Key: n1.Public(), KeySignature: n1GoodSig.Serialize()},
		{ID: 5, Key: n5.Public(), KeySignature: n5GoodSig.Serialize()},
	})
	nodePubComparer := cmp.Comparer(func(x, y key.NodePublic) bool {
		return x.Raw32() == y.Raw32()
	})
	if diff := cmp.Diff(nm.Peers, want, nodePubComparer); diff != "" {
		t.Errorf("filtered netmap differs (-want, +got):\n%s", diff)
	}
}

func TestTKADisable(t *testing.T) {
	nodePriv := key.NewNode()

	// Make a fake TKA authority, to seed local state.
	disablementSecret := bytes.Repeat([]byte{0xa5}, 32)
	nlPriv := key.NewNLPrivate()

	pm := must.Get(newProfileManager(new(mem.Store), t.Logf))
	must.Do(pm.SetPrefs((&ipn.Prefs{
		Persist: &persist.Persist{
			PrivateNodeKey: nodePriv,
			NetworkLockKey: nlPriv,
		},
	}).View(), ipn.NetworkProfile{}))

	temp := t.TempDir()
	tkaPath := filepath.Join(temp, "tka-profile", string(pm.CurrentProfile().ID))
	os.Mkdir(tkaPath, 0755)
	key := tka.Key{Kind: tka.Key25519, Public: nlPriv.Public().Verifier(), Votes: 2}
	chonk, err := tka.ChonkDir(tkaPath)
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

	ts, client := fakeNoiseServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		switch r.URL.Path {
		case "/machine/tka/disable":
			body := new(tailcfg.TKADisableRequest)
			if err := json.NewDecoder(r.Body).Decode(body); err != nil {
				t.Fatal(err)
			}
			if body.Version != tailcfg.CurrentCapabilityVersion {
				t.Errorf("disable CapVer = %v, want %v", body.Version, tailcfg.CurrentCapabilityVersion)
			}
			if body.NodeKey != nodePriv.Public() {
				t.Errorf("nodeKey = %v, want %v", body.NodeKey, nodePriv.Public())
			}
			if !bytes.Equal(body.DisablementSecret, disablementSecret) {
				t.Errorf("disablement secret = %x, want %x", body.DisablementSecret, disablementSecret)
			}

			var head tka.AUMHash
			if err := head.UnmarshalText([]byte(body.Head)); err != nil {
				t.Fatalf("failed unmarshal of body.Head: %v", err)
			}
			if head != authority.Head() {
				t.Errorf("reported head = %x, want %x", head, authority.Head())
			}

			w.WriteHeader(200)
			if err := json.NewEncoder(w).Encode(tailcfg.TKADisableResponse{}); err != nil {
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
			profile:   pm.CurrentProfile().ID,
			authority: authority,
			storage:   chonk,
		},
		pm:    pm,
		store: pm.Store(),
	}

	// Test that we get an error for an incorrect disablement secret.
	if err := b.NetworkLockDisable([]byte{1, 2, 3, 4}); err == nil || err.Error() != "incorrect disablement secret" {
		t.Errorf("NetworkLockDisable(<bad secret>).err = %v, want 'incorrect disablement secret'", err)
	}
	if err := b.NetworkLockDisable(disablementSecret); err != nil {
		t.Errorf("NetworkLockDisable() failed: %v", err)
	}
}

func TestTKASign(t *testing.T) {
	nodePriv := key.NewNode()
	toSign := key.NewNode()
	nlPriv := key.NewNLPrivate()

	pm := must.Get(newProfileManager(new(mem.Store), t.Logf))
	must.Do(pm.SetPrefs((&ipn.Prefs{
		Persist: &persist.Persist{
			PrivateNodeKey: nodePriv,
			NetworkLockKey: nlPriv,
		},
	}).View(), ipn.NetworkProfile{}))

	// Make a fake TKA authority, to seed local state.
	disablementSecret := bytes.Repeat([]byte{0xa5}, 32)
	key := tka.Key{Kind: tka.Key25519, Public: nlPriv.Public().Verifier(), Votes: 2}

	temp := t.TempDir()
	tkaPath := filepath.Join(temp, "tka-profile", string(pm.CurrentProfile().ID))
	os.Mkdir(tkaPath, 0755)
	chonk, err := tka.ChonkDir(tkaPath)
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

	ts, client := fakeNoiseServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		switch r.URL.Path {
		case "/machine/tka/sign":
			body := new(tailcfg.TKASubmitSignatureRequest)
			if err := json.NewDecoder(r.Body).Decode(body); err != nil {
				t.Fatal(err)
			}
			if body.Version != tailcfg.CurrentCapabilityVersion {
				t.Errorf("sign CapVer = %v, want %v", body.Version, tailcfg.CurrentCapabilityVersion)
			}
			if body.NodeKey != nodePriv.Public() {
				t.Errorf("nodeKey = %v, want %v", body.NodeKey, nodePriv.Public())
			}

			var sig tka.NodeKeySignature
			if err := sig.Unserialize(body.Signature); err != nil {
				t.Fatalf("malformed signature: %v", err)
			}

			if err := authority.NodeKeyAuthorized(toSign.Public(), body.Signature); err != nil {
				t.Errorf("signature does not verify: %v", err)
			}

			w.WriteHeader(200)
			if err := json.NewEncoder(w).Encode(tailcfg.TKASubmitSignatureResponse{}); err != nil {
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
		pm:    pm,
		store: pm.Store(),
	}

	if err := b.NetworkLockSign(toSign.Public(), nil); err != nil {
		t.Errorf("NetworkLockSign() failed: %v", err)
	}
}

func TestTKAForceDisable(t *testing.T) {
	nodePriv := key.NewNode()

	// Make a fake TKA authority, to seed local state.
	disablementSecret := bytes.Repeat([]byte{0xa5}, 32)
	nlPriv := key.NewNLPrivate()
	key := tka.Key{Kind: tka.Key25519, Public: nlPriv.Public().Verifier(), Votes: 2}

	pm := must.Get(newProfileManager(new(mem.Store), t.Logf))
	must.Do(pm.SetPrefs((&ipn.Prefs{
		Persist: &persist.Persist{
			PrivateNodeKey: nodePriv,
			NetworkLockKey: nlPriv,
		},
	}).View(), ipn.NetworkProfile{}))

	temp := t.TempDir()
	tkaPath := filepath.Join(temp, "tka-profile", string(pm.CurrentProfile().ID))
	os.Mkdir(tkaPath, 0755)
	chonk, err := tka.ChonkDir(tkaPath)
	if err != nil {
		t.Fatal(err)
	}
	authority, genesis, err := tka.Create(chonk, tka.State{
		Keys:               []tka.Key{key},
		DisablementSecrets: [][]byte{tka.DisablementKDF(disablementSecret)},
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
				t.Errorf("nodeKey=%v, want %v", body.NodeKey, nodePriv.Public())
			}

			w.WriteHeader(200)
			out := tailcfg.TKABootstrapResponse{
				GenesisAUM: genesis.Serialize(),
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
		pm:    pm,
		store: pm.Store(),
	}

	if err := b.NetworkLockForceLocalDisable(); err != nil {
		t.Fatalf("NetworkLockForceLocalDisable() failed: %v", err)
	}
	if b.tka != nil {
		t.Fatal("tka was not shut down")
	}
	if _, err := os.Stat(b.chonkPathLocked()); err == nil || !os.IsNotExist(err) {
		t.Errorf("os.Stat(chonkDir) = %v, want ErrNotExist", err)
	}

	err = b.tkaSyncIfNeeded(&netmap.NetworkMap{
		TKAEnabled: true,
		TKAHead:    authority.Head(),
	}, pm.CurrentPrefs())
	if err != nil && err.Error() != "bootstrap: TKA with stateID of \"0:0\" is disallowed on this node" {
		t.Errorf("tkaSyncIfNeededLocked() failed: %v", err)
	}

	if b.tka != nil {
		t.Fatal("tka was re-initialized")
	}
}

func TestTKAAffectedSigs(t *testing.T) {
	nodePriv := key.NewNode()
	// toSign := key.NewNode()
	nlPriv := key.NewNLPrivate()

	pm := must.Get(newProfileManager(new(mem.Store), t.Logf))
	must.Do(pm.SetPrefs((&ipn.Prefs{
		Persist: &persist.Persist{
			PrivateNodeKey: nodePriv,
			NetworkLockKey: nlPriv,
		},
	}).View(), ipn.NetworkProfile{}))

	// Make a fake TKA authority, to seed local state.
	disablementSecret := bytes.Repeat([]byte{0xa5}, 32)
	tkaKey := tka.Key{Kind: tka.Key25519, Public: nlPriv.Public().Verifier(), Votes: 2}

	temp := t.TempDir()
	tkaPath := filepath.Join(temp, "tka-profile", string(pm.CurrentProfile().ID))
	os.Mkdir(tkaPath, 0755)
	chonk, err := tka.ChonkDir(tkaPath)
	if err != nil {
		t.Fatal(err)
	}
	authority, _, err := tka.Create(chonk, tka.State{
		Keys:               []tka.Key{tkaKey},
		DisablementSecrets: [][]byte{tka.DisablementKDF(disablementSecret)},
	}, nlPriv)
	if err != nil {
		t.Fatalf("tka.Create() failed: %v", err)
	}

	untrustedKey := key.NewNLPrivate()
	tcs := []struct {
		name    string
		makeSig func() *tka.NodeKeySignature
		wantErr string
	}{
		{
			"no error",
			func() *tka.NodeKeySignature {
				sig, _ := signNodeKey(tailcfg.TKASignInfo{NodePublic: nodePriv.Public()}, nlPriv)
				return sig
			},
			"",
		},
		{
			"signature for different keyID",
			func() *tka.NodeKeySignature {
				sig, _ := signNodeKey(tailcfg.TKASignInfo{NodePublic: nodePriv.Public()}, untrustedKey)
				return sig
			},
			fmt.Sprintf("got signature with keyID %X from request for %X", untrustedKey.KeyID(), nlPriv.KeyID()),
		},
		{
			"invalid signature",
			func() *tka.NodeKeySignature {
				sig, _ := signNodeKey(tailcfg.TKASignInfo{NodePublic: nodePriv.Public()}, nlPriv)
				copy(sig.Signature, []byte{1, 2, 3, 4, 5, 6}) // overwrite with trash to invalid signature
				return sig
			},
			"signature 0 is not valid: invalid signature",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.makeSig()
			ts, client := fakeNoiseServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer r.Body.Close()
				switch r.URL.Path {
				case "/machine/tka/affected-sigs":
					body := new(tailcfg.TKASignaturesUsingKeyRequest)
					if err := json.NewDecoder(r.Body).Decode(body); err != nil {
						t.Fatal(err)
					}
					if body.Version != tailcfg.CurrentCapabilityVersion {
						t.Errorf("sign CapVer = %v, want %v", body.Version, tailcfg.CurrentCapabilityVersion)
					}
					if body.NodeKey != nodePriv.Public() {
						t.Errorf("nodeKey = %v, want %v", body.NodeKey, nodePriv.Public())
					}

					w.WriteHeader(200)
					if err := json.NewEncoder(w).Encode(tailcfg.TKASignaturesUsingKeyResponse{
						Signatures: []tkatype.MarshaledSignature{s.Serialize()},
					}); err != nil {
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
				pm:    pm,
				store: pm.Store(),
			}

			sigs, err := b.NetworkLockAffectedSigs(nlPriv.KeyID())
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("NetworkLockAffectedSigs() failed: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Errorf("NetworkLockAffectedSigs().err = nil, want %q", tc.wantErr)
			case tc.wantErr != "" && err.Error() != tc.wantErr:
				t.Errorf("NetworkLockAffectedSigs().err = %q, want %q", err.Error(), tc.wantErr)
			}

			if tc.wantErr == "" {
				if len(sigs) != 1 {
					t.Fatalf("len(sigs) = %d, want 1", len(sigs))
				}
				if !bytes.Equal(s.Serialize(), sigs[0]) {
					t.Errorf("unexpected signature: got %v, want %v", sigs[0], s.Serialize())
				}
			}
		})
	}
}

func TestTKARecoverCompromisedKeyFlow(t *testing.T) {
	nodePriv := key.NewNode()
	nlPriv := key.NewNLPrivate()
	cosignPriv := key.NewNLPrivate()
	compromisedPriv := key.NewNLPrivate()

	pm := must.Get(newProfileManager(new(mem.Store), t.Logf))
	must.Do(pm.SetPrefs((&ipn.Prefs{
		Persist: &persist.Persist{
			PrivateNodeKey: nodePriv,
			NetworkLockKey: nlPriv,
		},
	}).View(), ipn.NetworkProfile{}))

	// Make a fake TKA authority, to seed local state.
	disablementSecret := bytes.Repeat([]byte{0xa5}, 32)
	key := tka.Key{Kind: tka.Key25519, Public: nlPriv.Public().Verifier(), Votes: 2}
	cosignKey := tka.Key{Kind: tka.Key25519, Public: cosignPriv.Public().Verifier(), Votes: 2}
	compromisedKey := tka.Key{Kind: tka.Key25519, Public: compromisedPriv.Public().Verifier(), Votes: 1}

	temp := t.TempDir()
	tkaPath := filepath.Join(temp, "tka-profile", string(pm.CurrentProfile().ID))
	os.Mkdir(tkaPath, 0755)
	chonk, err := tka.ChonkDir(tkaPath)
	if err != nil {
		t.Fatal(err)
	}
	authority, _, err := tka.Create(chonk, tka.State{
		Keys:               []tka.Key{key, compromisedKey, cosignKey},
		DisablementSecrets: [][]byte{tka.DisablementKDF(disablementSecret)},
	}, nlPriv)
	if err != nil {
		t.Fatalf("tka.Create() failed: %v", err)
	}

	ts, client := fakeNoiseServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		switch r.URL.Path {
		case "/machine/tka/sync/send":
			body := new(tailcfg.TKASyncSendRequest)
			if err := json.NewDecoder(r.Body).Decode(body); err != nil {
				t.Fatal(err)
			}
			t.Logf("got sync send:\n%+v", body)

			var remoteHead tka.AUMHash
			if err := remoteHead.UnmarshalText([]byte(body.Head)); err != nil {
				t.Fatalf("head unmarshal: %v", err)
			}
			toApply := make([]tka.AUM, len(body.MissingAUMs))
			for i, a := range body.MissingAUMs {
				if err := toApply[i].Unserialize(a); err != nil {
					t.Fatalf("decoding missingAUM[%d]: %v", i, err)
				}
			}

			// Apply the recovery AUM to an authority to make sure it works.
			if err := authority.Inform(chonk, toApply); err != nil {
				t.Errorf("recovery AUM could not be applied: %v", err)
			}
			// Make sure the key we removed isn't trusted.
			if authority.KeyTrusted(compromisedPriv.KeyID()) {
				t.Error("compromised key was not removed from tka")
			}

			w.WriteHeader(200)
			if err := json.NewEncoder(w).Encode(tailcfg.TKASubmitSignatureResponse{}); err != nil {
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
		pm:    pm,
		store: pm.Store(),
	}

	aum, err := b.NetworkLockGenerateRecoveryAUM([]tkatype.KeyID{compromisedPriv.KeyID()}, tka.AUMHash{})
	if err != nil {
		t.Fatalf("NetworkLockGenerateRecoveryAUM() failed: %v", err)
	}

	// Cosign using the cosigning key.
	{
		pm := must.Get(newProfileManager(new(mem.Store), t.Logf))
		must.Do(pm.SetPrefs((&ipn.Prefs{
			Persist: &persist.Persist{
				PrivateNodeKey: nodePriv,
				NetworkLockKey: cosignPriv,
			},
		}).View(), ipn.NetworkProfile{}))
		b := LocalBackend{
			varRoot: temp,
			logf:    t.Logf,
			tka: &tkaState{
				authority: authority,
				storage:   chonk,
			},
			pm:    pm,
			store: pm.Store(),
		}
		if aum, err = b.NetworkLockCosignRecoveryAUM(aum); err != nil {
			t.Fatalf("NetworkLockCosignRecoveryAUM() failed: %v", err)
		}
	}

	// Finally, submit the recovery AUM. Validation is done
	// in the fake control handler.
	if err := b.NetworkLockSubmitRecoveryAUM(aum); err != nil {
		t.Errorf("NetworkLockSubmitRecoveryAUM() failed: %v", err)
	}
}
