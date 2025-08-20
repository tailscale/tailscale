// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The controll program trolls tailscaleds, simulating huge and busy tailnets.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/ptr"
	"tailscale.com/util/must"
)

var (
	flagNFake = flag.Int("nfake", 0, "number of fake nodes to add to network")
	certHost  = flag.String("certhost", "controll.fitz.dev", "hostname to use in TLS certificate")
)

type state struct {
	Legacy  key.ControlPrivate
	Machine key.MachinePrivate
}

func loadState() *state {
	st := &state{}
	path := filepath.Join(must.Get(os.UserCacheDir()), "controll.state")
	f, _ := os.ReadFile(path)
	f = bytes.TrimSpace(f)
	if err := json.Unmarshal(f, st); err == nil {
		return st
	}
	st.Legacy = key.NewControl()
	st.Machine = key.NewMachine()
	f = must.Get(json.Marshal(st))
	must.Do(os.WriteFile(path, f, 0600))
	return st
}

func main() {
	flag.Parse()

	var t fakeTB
	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")

	certManager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(*certHost),
		Cache:      autocert.DirCache(filepath.Join(must.Get(os.UserCacheDir()), "controll-cert")),
	}

	control := &testcontrol.Server{
		DERPMap:              derpMap,
		ExplicitBaseURL:      "http://127.0.0.1:9911",
		TolerateUnknownPaths: true,
		AltMapStream:         sendClientChaos,
	}

	st := loadState()
	control.SetPrivateKeys(st.Machine, st.Legacy)
	for range *flagNFake {
		control.AddFakeNode()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>con<b>troll</b>"))
	})
	mux.Handle("/", control)

	go func() {
		addr := "127.0.0.1:9911"
		log.Printf("listening on %s", addr)
		err := http.ListenAndServe(addr, mux)
		log.Fatal(err)
	}()

	if *certHost != "" {
		go func() {
			srv := &http.Server{
				Addr:      ":https",
				Handler:   mux,
				TLSConfig: certManager.TLSConfig(),
			}
			log.Fatalf("TLS: %v", srv.ListenAndServeTLS("", ""))
		}()
	}

	select {}
}

func node4(nid tailcfg.NodeID) netip.Prefix {
	return netip.PrefixFrom(
		netip.AddrFrom4([4]byte{100, 100 + byte(nid>>16), byte(nid >> 8), byte(nid)}),
		32)
}

func node6(nid tailcfg.NodeID) netip.Prefix {
	a := tsaddr.TailscaleULARange().Addr().As16()
	a[13] = byte(nid >> 16)
	a[14] = byte(nid >> 8)
	a[15] = byte(nid)
	v6 := netip.AddrFrom16(a)
	return netip.PrefixFrom(v6, 128)
}

func sendClientChaos(ctx context.Context, w testcontrol.MapStreamWriter, r *tailcfg.MapRequest) {
	selfPub := r.NodeKey

	nodeID := tailcfg.NodeID(0)
	newNodeID := func() tailcfg.NodeID {
		nodeID++
		return nodeID
	}

	selfNodeID := newNodeID()
	selfIP4 := node4(nodeID)
	selfIP6 := node6(nodeID)

	selfUserID := tailcfg.UserID(1_000_000)

	var peers []*tailcfg.Node
	for range *flagNFake {
		nid := newNodeID()
		v4, v6 := node4(nid), node6(nid)
		user := selfUserID
		if rand.IntN(2) == 0 {
			// Randomly assign a different user to the peer.
			// ...
		}
		peers = append(peers, &tailcfg.Node{
			ID:                nid,
			StableID:          tailcfg.StableNodeID(fmt.Sprintf("peer-%d", nid)),
			Name:              fmt.Sprintf("peer-%d.troll.ts.net.", nid),
			Key:               key.NewNode().Public(),
			MachineAuthorized: true,
			DiscoKey:          key.NewDisco().Public(),
			Addresses:         []netip.Prefix{v4, v6},
			AllowedIPs:        []netip.Prefix{v4, v6},
			User:              user,
		})
	}

	w.SendMapMessage(&tailcfg.MapResponse{
		Node: &tailcfg.Node{
			ID:                selfNodeID,
			StableID:          "self",
			Name:              "test-mctestfast.troll.ts.net.",
			User:              selfUserID,
			Key:               selfPub,
			KeyExpiry:         time.Now().Add(5000 * time.Hour),
			Machine:           key.NewMachine().Public(), // fake; client shouldn't care
			DiscoKey:          r.DiscoKey,
			MachineAuthorized: true,
			Addresses:         []netip.Prefix{selfIP4, selfIP6},
			AllowedIPs:        []netip.Prefix{selfIP4, selfIP6},
			Capabilities:      []tailcfg.NodeCapability{},
			CapMap:            map[tailcfg.NodeCapability][]tailcfg.RawMessage{},
		},
		DERPMap: &tailcfg.DERPMap{
			Regions: map[int]*tailcfg.DERPRegion{
				1: {RegionID: 1,
					Nodes: []*tailcfg.DERPNode{{
						RegionID:  1,
						Name:      "1i",
						IPv4:      "199.38.181.103",
						IPv6:      "2607:f740:f::e19",
						HostName:  "derp1i.tailscale.com",
						CanPort80: true,
					}}},
			},
		},
		Peers: peers,
	})

	sendChange := func() error {
		const (
			actionToggleOnline = iota
			numActions
		)
		action := rand.IntN(numActions)
		switch action {
		case actionToggleOnline:
			peer := peers[rand.IntN(len(peers))]
			online := peer.Online != nil && *peer.Online
			peer.Online = ptr.To(!online)
			var lastSeen *time.Time
			if !online {
				lastSeen = ptr.To(time.Now().UTC().Round(time.Second))
			}
			w.SendMapMessage(&tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{
					{
						NodeID:   peer.ID,
						Online:   peer.Online,
						LastSeen: lastSeen,
					},
				},
			})
		}
		return nil
	}

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := sendChange(); err != nil {
				log.Printf("sendChange: %v", err)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

type fakeTB struct {
	*testing.T
}

func (t fakeTB) Cleanup(_ func()) {}
func (t fakeTB) Error(args ...any) {
	t.Fatal(args...)
}
func (t fakeTB) Errorf(format string, args ...any) {
	t.Fatalf(format, args...)
}
func (t fakeTB) Fail() {
	t.Fatal("failed")
}
func (t fakeTB) FailNow() {
	t.Fatal("failed")
}
func (t fakeTB) Failed() bool {
	return false
}
func (t fakeTB) Fatal(args ...any) {
	log.Fatal(args...)
}
func (t fakeTB) Fatalf(format string, args ...any) {
	log.Fatalf(format, args...)
}
func (t fakeTB) Helper() {}
func (t fakeTB) Log(args ...any) {
	log.Print(args...)
}
func (t fakeTB) Logf(format string, args ...any) {
	log.Printf(format, args...)
}
func (t fakeTB) Name() string {
	return "faketest"
}
func (t fakeTB) Setenv(key string, value string) {
	panic("not implemented")
}
func (t fakeTB) Skip(args ...any) {
	t.Fatal("skipped")
}
func (t fakeTB) SkipNow() {
	t.Fatal("skipnow")
}
func (t fakeTB) Skipf(format string, args ...any) {
	t.Logf(format, args...)
	t.Fatal("skipped")
}
func (t fakeTB) Skipped() bool {
	return false
}
func (t fakeTB) TempDir() string {
	panic("not implemented")
}
