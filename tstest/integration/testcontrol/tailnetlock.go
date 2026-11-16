// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !experiment.reco && !ts_omit_tailnetlock

package testcontrol

import (
	"fmt"
	"log"
	"maps"
	"net/http"

	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/tstest/tkatest"
	"tailscale.com/util/must"
)

type tkaState struct {
	// tkaStorage records the Tailnet Lock state, if any.
	// If nil, Tailnet Lock is not enabled in the Tailnet.
	tkaStorage tka.CompactableChonk
}

func (s *Server) serveTKA(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "GET required for serveTKA", 400)
		return
	}

	switch r.URL.Path {
	case "/machine/tka/init/begin":
		s.serveTKAInitBegin(w, r)
	case "/machine/tka/init/finish":
		s.serveTKAInitFinish(w, r)
	case "/machine/tka/bootstrap":
		s.serveTKABootstrap(w, r)
	case "/machine/tka/sync/offer":
		s.serveTKASyncOffer(w, r)
	case "/machine/tka/sign":
		s.serveTKASign(w, r)
	default:
		s.serveUnhandled(w, r)
	}
}

func (s *Server) serveTKAInitBegin(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nodes := maps.Values(s.nodes)
	genesisAUM, err := tkatest.HandleTKAInitBegin(w, r, nodes)
	if err != nil {
		go panic(fmt.Sprintf("HandleTKAInitBegin: %v", err))
	}
	s.tkaStorage = tka.ChonkMem()
	s.tkaStorage.CommitVerifiedAUMs([]tka.AUM{*genesisAUM})
}

func (s *Server) serveTKAInitFinish(w http.ResponseWriter, r *http.Request) {
	signatures, err := tkatest.HandleTKAInitFinish(w, r)
	if err != nil {
		go panic(fmt.Sprintf("HandleTKAInitFinish: %v", err))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Apply the signatures to each of the nodes. Because s.nodes is keyed
	// by public key instead of node ID, we have to do this inefficiently.
	//
	// We only have small tailnets in the integration tests, so this isn't
	// much of an issue.
	for nodeID, sig := range signatures {
		for _, n := range s.nodes {
			if n.ID == nodeID {
				n.KeySignature = sig
			}
		}
	}
}

func (s *Server) serveTKABootstrap(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tkaStorage == nil {
		http.Error(w, "no TKA state when calling serveTKABootstrap", 400)
		return
	}

	// Find the genesis AUM, which we need to include in the response.
	var genesis *tka.AUM
	allAUMs, err := s.tkaStorage.AllAUMs()
	if err != nil {
		http.Error(w, "unable to retrieve all AUMs from TKA state", 500)
		return
	}
	for _, h := range allAUMs {
		aum := must.Get(s.tkaStorage.AUM(h))
		if _, hasParent := aum.Parent(); !hasParent {
			genesis = &aum
			break
		}
	}
	if genesis == nil {
		http.Error(w, "unable to find genesis AUM in TKA state", 500)
		return
	}

	resp := tailcfg.TKABootstrapResponse{
		GenesisAUM: genesis.Serialize(),
	}
	_, err = tkatest.HandleTKABootstrap(w, r, resp)
	if err != nil {
		go panic(fmt.Sprintf("HandleTKABootstrap: %v", err))
	}
}

func (s *Server) serveTKASyncOffer(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	authority, err := tka.Open(s.tkaStorage)
	if err != nil {
		go panic(fmt.Sprintf("serveTKASyncOffer: tka.Open: %v", err))
	}

	err = tkatest.HandleTKASyncOffer(w, r, authority, s.tkaStorage)
	if err != nil {
		go panic(fmt.Sprintf("HandleTKASyncOffer: %v", err))
	}
}

func (s *Server) serveTKASign(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	authority, err := tka.Open(s.tkaStorage)
	if err != nil {
		go panic(fmt.Sprintf("serveTKASign: tka.Open: %v", err))
	}

	sig, keyBeingSigned, err := tkatest.HandleTKASign(w, r, authority)
	if err != nil {
		go panic(fmt.Sprintf("HandleTKASign: %v", err))
	}
	s.nodes[*keyBeingSigned].KeySignature = *sig
	s.updateLocked("TKASign", s.nodeIDsLocked(0))
}

// tkaInfo returns the TKAInfo to include in a MapResponse, or nil if
// Tailnet Lock is not enabled or doesn't have a single head.
func (s *Server) tkaInfo() *tailcfg.TKAInfo {
	if s.tkaStorage == nil {
		return nil
	}
	heads, err := s.tkaStorage.Heads()
	if err != nil {
		log.Printf("unable to get TKA heads: %v", err)
		return nil
	}
	if len(heads) != 1 {
		log.Printf("unable to get single TKA head, got %v", heads)
		return nil
	}
	return &tailcfg.TKAInfo{Head: heads[0].Hash().String()}
}
