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

func TestRelayManager_handleNewServerEndpointRunLoop(t *testing.T) {
	wantHandshakeWorkCount := func(t *testing.T, rm *relayManager, n int) {
		t.Helper()
		byServerDiscoByEndpoint := 0
		for _, v := range rm.handshakeWorkByServerDiscoByEndpoint {
			byServerDiscoByEndpoint += len(v)
		}
		byServerDiscoVNI := len(rm.handshakeWorkByServerDiscoVNI)
		if byServerDiscoByEndpoint != n ||
			byServerDiscoVNI != n ||
			byServerDiscoByEndpoint != byServerDiscoVNI {
			t.Fatalf("want handshake work count %d byServerDiscoByEndpoint=%d byServerDiscoVNI=%d",
				n,
				byServerDiscoByEndpoint,
				byServerDiscoVNI,
			)
		}
	}

	conn := newConn(t.Logf)
	epA := &endpoint{c: conn}
	epB := &endpoint{c: conn}
	serverDiscoA := key.NewDisco().Public()
	serverDiscoB := key.NewDisco().Public()

	serverAendpointALamport1VNI1 := newRelayServerEndpointEvent{
		wlb: endpointWithLastBest{ep: epA},
		se:  udprelay.ServerEndpoint{ServerDisco: serverDiscoA, LamportID: 1, VNI: 1},
	}
	serverAendpointALamport1VNI1LastBestMatching := newRelayServerEndpointEvent{
		wlb: endpointWithLastBest{ep: epA, lastBestIsTrusted: true, lastBest: addrQuality{relayServerDisco: serverDiscoA}},
		se:  udprelay.ServerEndpoint{ServerDisco: serverDiscoA, LamportID: 1, VNI: 1},
	}
	serverAendpointALamport2VNI1 := newRelayServerEndpointEvent{
		wlb: endpointWithLastBest{ep: epA},
		se:  udprelay.ServerEndpoint{ServerDisco: serverDiscoA, LamportID: 2, VNI: 1},
	}
	serverAendpointALamport2VNI2 := newRelayServerEndpointEvent{
		wlb: endpointWithLastBest{ep: epA},
		se:  udprelay.ServerEndpoint{ServerDisco: serverDiscoA, LamportID: 2, VNI: 2},
	}
	serverAendpointBLamport1VNI2 := newRelayServerEndpointEvent{
		wlb: endpointWithLastBest{ep: epB},
		se:  udprelay.ServerEndpoint{ServerDisco: serverDiscoA, LamportID: 1, VNI: 2},
	}
	serverBendpointALamport1VNI1 := newRelayServerEndpointEvent{
		wlb: endpointWithLastBest{ep: epA},
		se:  udprelay.ServerEndpoint{ServerDisco: serverDiscoB, LamportID: 1, VNI: 1},
	}

	tests := []struct {
		name   string
		events []newRelayServerEndpointEvent
		want   []newRelayServerEndpointEvent
	}{
		{
			// Test for http://go/corp/32978
			name: "eq server+ep neq VNI higher lamport",
			events: []newRelayServerEndpointEvent{
				serverAendpointALamport1VNI1,
				serverAendpointALamport2VNI2,
			},
			want: []newRelayServerEndpointEvent{
				serverAendpointALamport2VNI2,
			},
		},
		{
			name: "eq server+ep neq VNI lower lamport",
			events: []newRelayServerEndpointEvent{
				serverAendpointALamport2VNI2,
				serverAendpointALamport1VNI1,
			},
			want: []newRelayServerEndpointEvent{
				serverAendpointALamport2VNI2,
			},
		},
		{
			name: "eq server+vni neq ep lower lamport",
			events: []newRelayServerEndpointEvent{
				serverAendpointALamport2VNI2,
				serverAendpointBLamport1VNI2,
			},
			want: []newRelayServerEndpointEvent{
				serverAendpointALamport2VNI2,
			},
		},
		{
			name: "eq server+vni neq ep higher lamport",
			events: []newRelayServerEndpointEvent{
				serverAendpointBLamport1VNI2,
				serverAendpointALamport2VNI2,
			},
			want: []newRelayServerEndpointEvent{
				serverAendpointALamport2VNI2,
			},
		},
		{
			name: "eq server+endpoint+vni higher lamport",
			events: []newRelayServerEndpointEvent{
				serverAendpointALamport1VNI1,
				serverAendpointALamport2VNI1,
			},
			want: []newRelayServerEndpointEvent{
				serverAendpointALamport2VNI1,
			},
		},
		{
			name: "eq server+endpoint+vni lower lamport",
			events: []newRelayServerEndpointEvent{
				serverAendpointALamport2VNI1,
				serverAendpointALamport1VNI1,
			},
			want: []newRelayServerEndpointEvent{
				serverAendpointALamport2VNI1,
			},
		},
		{
			name: "eq endpoint+vni+lamport neq server",
			events: []newRelayServerEndpointEvent{
				serverAendpointALamport1VNI1,
				serverBendpointALamport1VNI1,
			},
			want: []newRelayServerEndpointEvent{
				serverAendpointALamport1VNI1,
				serverBendpointALamport1VNI1,
			},
		},
		{
			name: "trusted last best with matching server",
			events: []newRelayServerEndpointEvent{
				serverAendpointALamport1VNI1LastBestMatching,
			},
			want: []newRelayServerEndpointEvent{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &relayManager{}
			rm.init()
			<-rm.runLoopStoppedCh // prevent runLoop() from starting

			// feed events
			for _, event := range tt.events {
				rm.handleNewServerEndpointRunLoop(event)
			}

			// validate state
			wantHandshakeWorkCount(t, rm, len(tt.want))
			for _, want := range tt.want {
				byServerDisco, ok := rm.handshakeWorkByServerDiscoByEndpoint[want.wlb.ep]
				if !ok {
					t.Fatal("work not found by endpoint")
				}
				workByServerDiscoByEndpoint, ok := byServerDisco[want.se.ServerDisco]
				if !ok {
					t.Fatal("work not found by server disco by endpoint")
				}
				workByServerDiscoVNI, ok := rm.handshakeWorkByServerDiscoVNI[serverDiscoVNI{want.se.ServerDisco, want.se.VNI}]
				if !ok {
					t.Fatal("work not found by server disco + VNI")
				}
				if workByServerDiscoByEndpoint != workByServerDiscoVNI {
					t.Fatal("workByServerDiscoByEndpoint != workByServerDiscoVNI")
				}
			}

			// cleanup
			for _, event := range tt.events {
				rm.stopWorkRunLoop(event.wlb.ep)
			}
			wantHandshakeWorkCount(t, rm, 0)
		})
	}
}
