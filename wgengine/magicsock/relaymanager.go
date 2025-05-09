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
	udprelay "tailscale.com/net/udprelay/endpoint"
	"tailscale.com/types/key"
	"tailscale.com/util/httpm"
	"tailscale.com/util/set"
)

// relayManager manages allocation and handshaking of
// [tailscale.com/net/udprelay.Server] endpoints. The zero value is ready for
// use.
type relayManager struct {
	initOnce sync.Once

	// ===================================================================
	// The following fields are owned by a single goroutine, runLoop().
	serversByAddrPort   set.Set[netip.AddrPort]
	allocWorkByEndpoint map[*endpoint]*relayEndpointAllocWork

	// ===================================================================
	// The following chan fields serve event inputs to a single goroutine,
	// runLoop().
	allocateHandshakeCh chan *endpoint
	allocateWorkDoneCh  chan relayEndpointAllocWorkDoneEvent
	cancelWorkCh        chan *endpoint
	newServerEndpointCh chan newRelayServerEndpointEvent
	rxChallengeCh       chan relayHandshakeChallengeEvent
	rxCallMeMaybeViaCh  chan *disco.CallMeMaybeVia

	discoInfoMu            sync.Mutex // guards the following field
	discoInfoByServerDisco map[key.DiscoPublic]*discoInfo

	// runLoopStoppedCh is written to by runLoop() upon return, enabling event
	// writers to restart it when they are blocked (see
	// relayManagerInputEvent()).
	runLoopStoppedCh chan struct{}
}

type newRelayServerEndpointEvent struct {
	ep *endpoint
	se udprelay.ServerEndpoint
}

type relayEndpointAllocWorkDoneEvent struct {
	ep   *endpoint
	work *relayEndpointAllocWork
}

// activeWork returns true if there is outstanding allocation or handshaking
// work, otherwise it returns false.
func (r *relayManager) activeWork() bool {
	return len(r.allocWorkByEndpoint) > 0
	// TODO(jwhited): consider handshaking work
}

// runLoop is a form of event loop. It ensures exclusive access to most of
// [relayManager] state.
func (r *relayManager) runLoop() {
	defer func() {
		r.runLoopStoppedCh <- struct{}{}
	}()

	for {
		select {
		case ep := <-r.allocateHandshakeCh:
			r.cancelAndClearWork(ep)
			r.allocateAllServersForEndpoint(ep)
			if !r.activeWork() {
				return
			}
		case msg := <-r.allocateWorkDoneCh:
			work, ok := r.allocWorkByEndpoint[msg.ep]
			if ok && work == msg.work {
				// Verify the work in the map is the same as the one that we're
				// cleaning up. New events on r.allocateHandshakeCh can
				// overwrite pre-existing keys.
				delete(r.allocWorkByEndpoint, msg.ep)
			}
			if !r.activeWork() {
				return
			}
		case ep := <-r.cancelWorkCh:
			r.cancelAndClearWork(ep)
			if !r.activeWork() {
				return
			}
		case newEndpoint := <-r.newServerEndpointCh:
			_ = newEndpoint
			// TODO(jwhited): implement
			if !r.activeWork() {
				return
			}
		case challenge := <-r.rxChallengeCh:
			_ = challenge
			// TODO(jwhited): implement
			if !r.activeWork() {
				return
			}
		case via := <-r.rxCallMeMaybeViaCh:
			_ = via
			// TODO(jwhited): implement
			if !r.activeWork() {
				return
			}
		}
	}
}

type relayHandshakeChallengeEvent struct {
	challenge [32]byte
	disco     key.DiscoPublic
	from      netip.AddrPort
	vni       uint32
	at        time.Time
}

// relayEndpointAllocWork serves to track in-progress relay endpoint allocation
// for an [*endpoint]. This structure is immutable once initialized.
type relayEndpointAllocWork struct {
	// ep is the [*endpoint] associated with the work
	ep *endpoint
	// cancel() will signal all associated goroutines to return
	cancel context.CancelFunc
	// wg.Wait() will return once all associated goroutines have returned
	wg *sync.WaitGroup
}

// init initializes [relayManager] if it is not already initialized.
func (r *relayManager) init() {
	r.initOnce.Do(func() {
		r.discoInfoByServerDisco = make(map[key.DiscoPublic]*discoInfo)
		r.allocWorkByEndpoint = make(map[*endpoint]*relayEndpointAllocWork)
		r.allocateHandshakeCh = make(chan *endpoint)
		r.allocateWorkDoneCh = make(chan relayEndpointAllocWorkDoneEvent)
		r.cancelWorkCh = make(chan *endpoint)
		r.newServerEndpointCh = make(chan newRelayServerEndpointEvent)
		r.rxChallengeCh = make(chan relayHandshakeChallengeEvent)
		r.rxCallMeMaybeViaCh = make(chan *disco.CallMeMaybeVia)
		r.runLoopStoppedCh = make(chan struct{}, 1)
		go r.runLoop()
	})
}

// discoInfo returns a [*discoInfo] for 'serverDisco' if there is an
// active/ongoing handshake with it, otherwise it returns nil, false.
func (r *relayManager) discoInfo(serverDisco key.DiscoPublic) (_ *discoInfo, ok bool) {
	r.discoInfoMu.Lock()
	defer r.discoInfoMu.Unlock()
	di, ok := r.discoInfoByServerDisco[serverDisco]
	return di, ok
}

func (r *relayManager) handleCallMeMaybeVia(dm *disco.CallMeMaybeVia) {
	relayManagerInputEvent(r, nil, &r.rxCallMeMaybeViaCh, dm)
}

func (r *relayManager) handleBindUDPRelayEndpointChallenge(dm *disco.BindUDPRelayEndpointChallenge, di *discoInfo, src netip.AddrPort, vni uint32) {
	relayManagerInputEvent(r, nil, &r.rxChallengeCh, relayHandshakeChallengeEvent{challenge: dm.Challenge, disco: di.discoKey, from: src, vni: vni, at: time.Now()})
}

// relayManagerInputEvent initializes [relayManager] if necessary, starts
// relayManager.runLoop() if it is not running, and writes 'event' on 'eventCh'.
//
// [relayManager] initialization will make `*eventCh`, so it must be passed as
// a pointer to a channel.
//
// 'ctx' can be used for returning when runLoop is waiting for the caller to
// return, i.e. the calling goroutine was birthed by runLoop and is cancelable
// via 'ctx'. 'ctx' may be nil.
func relayManagerInputEvent[T any](r *relayManager, ctx context.Context, eventCh *chan T, event T) {
	r.init()
	var ctxDoneCh <-chan struct{}
	if ctx != nil {
		ctxDoneCh = ctx.Done()
	}
	for {
		select {
		case <-ctxDoneCh:
			return
		case *eventCh <- event:
			return
		case <-r.runLoopStoppedCh:
			go r.runLoop()
		}
	}
}

// allocateAndHandshakeAllServers kicks off allocation and handshaking of relay
// endpoints for 'ep' on all known relay servers, canceling any existing
// in-progress work.
func (r *relayManager) allocateAndHandshakeAllServers(ep *endpoint) {
	relayManagerInputEvent(r, nil, &r.allocateHandshakeCh, ep)
}

// cancelOutstandingWork cancels all outstanding allocation & handshaking work
// for 'ep'.
func (r *relayManager) cancelOutstandingWork(ep *endpoint) {
	relayManagerInputEvent(r, nil, &r.cancelWorkCh, ep)
}

// cancelAndClearWork cancels & clears any outstanding work for 'ep'.
func (r *relayManager) cancelAndClearWork(ep *endpoint) {
	allocWork, ok := r.allocWorkByEndpoint[ep]
	if ok {
		allocWork.cancel()
		allocWork.wg.Wait()
		delete(r.allocWorkByEndpoint, ep)
	}
	// TODO(jwhited): cancel & clear handshake work
}

func (r *relayManager) allocateAllServersForEndpoint(ep *endpoint) {
	if len(r.serversByAddrPort) == 0 {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := &relayEndpointAllocWork{ep: ep, cancel: cancel, wg: &sync.WaitGroup{}}
	for k := range r.serversByAddrPort {
		started.wg.Add(1)
		go r.allocateEndpoint(ctx, started.wg, k, ep)
	}
	r.allocWorkByEndpoint[ep] = started
	go func() {
		started.wg.Wait()
		started.cancel()
		relayManagerInputEvent(r, ctx, &r.allocateWorkDoneCh, relayEndpointAllocWorkDoneEvent{ep: ep, work: started})
	}()
}

func (r *relayManager) allocateEndpoint(ctx context.Context, wg *sync.WaitGroup, server netip.AddrPort, ep *endpoint) {
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
	relayManagerInputEvent(r, ctx, &r.newServerEndpointCh, newRelayServerEndpointEvent{
		ep: ep,
		se: se,
	})
}
