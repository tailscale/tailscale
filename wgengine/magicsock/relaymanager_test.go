// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"testing"

	"tailscale.com/disco"
	udprelay "tailscale.com/net/udprelay/endpoint"
	"tailscale.com/types/key"
	"tailscale.com/util/set"
)

func TestRelayManagerInitAndIdle(t *testing.T) {
	rm := relayManager{}
	rm.startUDPRelayPathDiscoveryFor(&endpoint{}, addrQuality{}, false)
	<-rm.runLoopStoppedCh

	rm = relayManager{}
	rm.stopWork(&endpoint{})
	<-rm.runLoopStoppedCh

	rm = relayManager{}
	rm.handleCallMeMaybeVia(&endpoint{c: &Conn{discoPrivate: key.NewDisco()}}, addrQuality{}, false, &disco.CallMeMaybeVia{UDPRelayEndpoint: disco.UDPRelayEndpoint{ServerDisco: key.NewDisco().Public()}})
	<-rm.runLoopStoppedCh

	rm = relayManager{}
	rm.handleRxDiscoMsg(&Conn{discoPrivate: key.NewDisco()}, &disco.BindUDPRelayEndpointChallenge{}, key.NodePublic{}, key.DiscoPublic{}, epAddr{})
	<-rm.runLoopStoppedCh

	rm = relayManager{}
	rm.handleRelayServersSet(make(set.Set[candidatePeerRelay]))
	<-rm.runLoopStoppedCh

	rm = relayManager{}
	rm.getServers()
	<-rm.runLoopStoppedCh

	rm = relayManager{}
	rm.handleDERPHomeChange(key.NodePublic{}, 1)
	<-rm.runLoopStoppedCh
}

func TestRelayManagerHandleDERPHomeChange(t *testing.T) {
	rm := relayManager{}
	servers := make(set.Set[candidatePeerRelay], 1)
	c := candidatePeerRelay{
		nodeKey:          key.NewNode().Public(),
		discoKey:         key.NewDisco().Public(),
		derpHomeRegionID: 1,
	}
	servers.Add(c)
	rm.handleRelayServersSet(servers)
	want := c
	want.derpHomeRegionID = 2
	rm.handleDERPHomeChange(c.nodeKey, 2)
	got := rm.getServers()
	if len(got) != 1 {
		t.Fatalf("got %d servers, want 1", len(got))
	}
	_, ok := got[want]
	if !ok {
		t.Fatal("DERP home change failed to propagate")
	}
}

func TestRelayManagerGetServers(t *testing.T) {
	rm := relayManager{}
	servers := make(set.Set[candidatePeerRelay], 1)
	c := candidatePeerRelay{
		nodeKey:  key.NewNode().Public(),
		discoKey: key.NewDisco().Public(),
	}
	servers.Add(c)
	rm.handleRelayServersSet(servers)
	got := rm.getServers()
	if !servers.Equal(got) {
		t.Errorf("got %v != want %v", got, servers)
	}
}

// Test for http://go/corp/32978
func TestRelayManager_handleNewServerEndpointRunLoop(t *testing.T) {
	rm := relayManager{}
	rm.init()
	<-rm.runLoopStoppedCh // prevent runLoop() from starting, we will inject/handle events in the test
	ep := &endpoint{}
	conn := newConn(t.Logf)
	ep.c = conn
	serverDisco := key.NewDisco().Public()
	rm.handleNewServerEndpointRunLoop(newRelayServerEndpointEvent{
		wlb: endpointWithLastBest{
			ep: ep,
		},
		se: udprelay.ServerEndpoint{
			ServerDisco: serverDisco,
			LamportID:   1,
			VNI:         1,
		},
	})
	rm.handleNewServerEndpointRunLoop(newRelayServerEndpointEvent{
		wlb: endpointWithLastBest{
			ep: ep,
		},
		se: udprelay.ServerEndpoint{
			ServerDisco: serverDisco,
			LamportID:   2,
			VNI:         2,
		},
	})
	rm.stopWorkRunLoop(ep)
	if len(rm.handshakeWorkByServerDiscoByEndpoint) != 0 ||
		len(rm.handshakeWorkByServerDiscoVNI) != 0 ||
		len(rm.handshakeWorkAwaitingPong) != 0 ||
		len(rm.addrPortVNIToHandshakeWork) != 0 {
		t.Fatal("stranded relayHandshakeWork state")
	}
}
