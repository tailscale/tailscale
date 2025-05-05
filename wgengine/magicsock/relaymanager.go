// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"tailscale.com/disco"
	"tailscale.com/net/udprelay"
	"tailscale.com/types/key"
	"tailscale.com/util/httpm"
)

// relayManager manages allocation and handshaking of
// [tailscale.com/net/udprelay.Server] endpoints. The zero value is ready for
// use.
type relayManager struct {
	mu                     sync.Mutex // guards the following fields
	discoInfoByServerDisco map[key.DiscoPublic]*discoInfo
	// serversByAddrPort value is the disco key of the relay server, which is
	// discovered at relay endpoint allocation time. Map value will be zero
	// (key.DiscoPublic.IsZero()) if no endpoints have been successfully
	// allocated on the server, yet.
	serversByAddrPort        map[netip.AddrPort]key.DiscoPublic
	relaySetupWorkByEndpoint map[*endpoint]*relaySetupWork
}

// relaySetupWork serves to track in-progress relay endpoint allocation and
// handshaking work for an [*endpoint]. This structure is immutable once
// initialized.
type relaySetupWork struct {
	// ep is the [*endpoint] associated with the work
	ep *endpoint
	// cancel() will signal all associated goroutines to return
	cancel context.CancelFunc
	// wg.Wait() will return once all associated goroutines have returned
	wg *sync.WaitGroup
}

func (r *relayManager) initLocked() {
	if r.discoInfoByServerDisco != nil {
		return
	}
	r.discoInfoByServerDisco = make(map[key.DiscoPublic]*discoInfo)
	r.serversByAddrPort = make(map[netip.AddrPort]key.DiscoPublic)
}

// discoInfo returns a [*discoInfo] for 'serverDisco' if there is an
// active/ongoing handshake with it, otherwise it returns nil, false.
func (r *relayManager) discoInfo(serverDisco key.DiscoPublic) (_ *discoInfo, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.initLocked()
	di, ok := r.discoInfoByServerDisco[serverDisco]
	return di, ok
}

func (r *relayManager) handleCallMeMaybeVia(dm *disco.CallMeMaybeVia) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.initLocked()
	// TODO(jwhited): implement
}

func (r *relayManager) handleBindUDPRelayEndpointChallenge(dm *disco.BindUDPRelayEndpointChallenge, di *discoInfo, src netip.AddrPort, vni uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.initLocked()
	// TODO(jwhited): implement
}

// cancelOutstandingWork cancels any in-progress work for 'ep'.
func (r *relayManager) cancelOutstandingWork(ep *endpoint) {
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.relaySetupWorkByEndpoint[ep]
	if ok {
		existing.cancel()
		existing.wg.Wait()
		delete(r.relaySetupWorkByEndpoint, ep)
	}
}

// allocateAndHandshakeAllServers kicks off allocation and handshaking of relay
// endpoints for 'ep' on all known relay servers, canceling any existing
// in-progress work.
func (r *relayManager) allocateAndHandshakeAllServers(ep *endpoint) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.initLocked()
	existing, ok := r.relaySetupWorkByEndpoint[ep]
	if ok {
		existing.cancel()
		existing.wg.Wait()
		delete(r.relaySetupWorkByEndpoint, ep)
	}
	if len(r.serversByAddrPort) == 0 {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := &relaySetupWork{ep: ep, cancel: cancel, wg: &sync.WaitGroup{}}
	for k := range r.serversByAddrPort {
		started.wg.Add(1)
		go r.allocateAndHandshakeForServer(ctx, started.wg, k, ep)
	}
	r.relaySetupWorkByEndpoint[ep] = started

	go func() {
		started.wg.Wait()
		started.cancel()
		r.mu.Lock()
		defer r.mu.Unlock()
		maybeCleanup, ok := r.relaySetupWorkByEndpoint[ep]
		if ok && maybeCleanup == started {
			// A subsequent call to allocateAndHandshakeAllServers may have raced to
			// delete the associated key/value, so ensure the work we are
			// cleaning up from the map is the same as the one we were waiting
			// to finish.
			delete(r.relaySetupWorkByEndpoint, ep)
		}
	}()
}

func (r *relayManager) handleNewServerEndpoint(ctx context.Context, wg *sync.WaitGroup, server netip.AddrPort, se udprelay.ServerEndpoint) {
	// TODO(jwhited): implement
}

func (r *relayManager) allocateAndHandshakeForServer(ctx context.Context, wg *sync.WaitGroup, server netip.AddrPort, ep *endpoint) {
	// TODO(jwhited): introduce client metrics counters for notable failures
	defer wg.Done()
	var b bytes.Buffer
	remoteDisco := ep.disco.Load()
	if remoteDisco == nil {
		return
	}
	type allocateRelayEndpointReq struct {
		DiscoKeys []key.DiscoPublic
	}
	a := &allocateRelayEndpointReq{
		DiscoKeys: []key.DiscoPublic{ep.c.discoPublic, remoteDisco.key},
	}
	err := json.NewEncoder(&b).Encode(a)
	if err != nil {
		return
	}
	const reqTimeout = time.Second * 10
	reqCtx, cancel := context.WithTimeout(ctx, reqTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, httpm.POST, "http://"+server.String()+"/relay/endpoint", &b)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var se udprelay.ServerEndpoint
	err = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&se)
	if err != nil {
		return
	}
	r.handleNewServerEndpoint(ctx, wg, server, se)
}
