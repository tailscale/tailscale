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
	"tailscale.com/types/ptr"
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
	serversByAddrPort                    map[netip.AddrPort]key.DiscoPublic
	serversByDisco                       map[key.DiscoPublic]netip.AddrPort
	allocWorkByEndpoint                  map[*endpoint]*relayEndpointAllocWork
	handshakeWorkByEndpointByServerDisco map[*endpoint]map[key.DiscoPublic]*relayHandshakeWork
	handshakeWorkByServerDiscoVNI        map[serverDiscoVNI]*relayHandshakeWork

	// ===================================================================
	// The following chan fields serve event inputs to a single goroutine,
	// runLoop().
	allocateHandshakeCh chan *endpoint
	allocateWorkDoneCh  chan relayEndpointAllocWorkDoneEvent
	handshakeWorkDoneCh chan relayEndpointHandshakeWorkDoneEvent
	cancelWorkCh        chan *endpoint
	newServerEndpointCh chan newRelayServerEndpointEvent
	rxChallengeCh       chan relayHandshakeChallengeEvent

	discoInfoMu            sync.Mutex // guards the following field
	discoInfoByServerDisco map[key.DiscoPublic]*relayHandshakeDiscoInfo

	// runLoopStoppedCh is written to by runLoop() upon return, enabling event
	// writers to restart it when they are blocked (see
	// relayManagerInputEvent()).
	runLoopStoppedCh chan struct{}
}

// serverDiscoVNI represents a [tailscale.com/net/udprelay.Server] disco key
// and Geneve header VNI value for a given [udprelay.ServerEndpoint].
type serverDiscoVNI struct {
	serverDisco key.DiscoPublic
	vni         uint32
}

// relayHandshakeWork serves to track in-progress relay handshake work for a
// [udprelay.ServerEndpoint]. This structure is immutable once initialized.
type relayHandshakeWork struct {
	ep *endpoint
	se udprelay.ServerEndpoint

	// In order to not deadlock, runLoop() must select{} read doneCh when
	// attempting to write into rxChallengeCh, and the handshake work goroutine
	// must close(doneCh) before attempting to write to
	// relayManager.handshakeWorkDoneCh.
	rxChallengeCh chan relayHandshakeChallengeEvent
	doneCh        chan struct{}

	ctx    context.Context
	cancel context.CancelFunc
	wg     *sync.WaitGroup
}

// newRelayServerEndpointEvent indicates a new [udprelay.ServerEndpoint] has
// become known either via allocation with a relay server, or via
// [disco.CallMeMaybeVia] reception. This structure is immutable once
// initialized.
type newRelayServerEndpointEvent struct {
	ep     *endpoint
	se     udprelay.ServerEndpoint
	server netip.AddrPort // zero value if learned via [disco.CallMeMaybeVia]
}

// relayEndpointAllocWorkDoneEvent indicates relay server endpoint allocation
// work for an [*endpoint] has completed. This structure is immutable once
// initialized.
type relayEndpointAllocWorkDoneEvent struct {
	work *relayEndpointAllocWork
}

// relayEndpointHandshakeWorkDoneEvent indicates relay server endpoint handshake
// work for an [*endpoint] has completed. This structure is immutable once
// initialized.
type relayEndpointHandshakeWorkDoneEvent struct {
	work         *relayHandshakeWork
	answerSentTo netip.AddrPort // zero value if answer was not transmitted
}

// activeWorkRunLoop returns true if there is outstanding allocation or
// handshaking work, otherwise it returns false.
func (r *relayManager) activeWorkRunLoop() bool {
	return len(r.allocWorkByEndpoint) > 0 || len(r.handshakeWorkByEndpointByServerDisco) > 0
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
			r.stopWorkRunLoop(ep, stopHandshakeWorkOnlyKnownServers)
			r.allocateAllServersRunLoop(ep)
			if !r.activeWorkRunLoop() {
				return
			}
		case done := <-r.allocateWorkDoneCh:
			work, ok := r.allocWorkByEndpoint[done.work.ep]
			if ok && work == done.work {
				// Verify the work in the map is the same as the one that we're
				// cleaning up. New events on r.allocateHandshakeCh can
				// overwrite pre-existing keys.
				delete(r.allocWorkByEndpoint, done.work.ep)
			}
			if !r.activeWorkRunLoop() {
				return
			}
		case ep := <-r.cancelWorkCh:
			r.stopWorkRunLoop(ep, stopHandshakeWorkAllServers)
			if !r.activeWorkRunLoop() {
				return
			}
		case newServerEndpoint := <-r.newServerEndpointCh:
			r.handleNewServerEndpointRunLoop(newServerEndpoint)
			if !r.activeWorkRunLoop() {
				return
			}
		case done := <-r.handshakeWorkDoneCh:
			r.handleHandshakeWorkDoneRunLoop(done)
			if !r.activeWorkRunLoop() {
				return
			}
		case challenge := <-r.rxChallengeCh:
			r.handleRxChallengeRunLoop(challenge)
			if !r.activeWorkRunLoop() {
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
		r.discoInfoByServerDisco = make(map[key.DiscoPublic]*relayHandshakeDiscoInfo)
		r.serversByDisco = make(map[key.DiscoPublic]netip.AddrPort)
		r.serversByAddrPort = make(map[netip.AddrPort]key.DiscoPublic)
		r.allocWorkByEndpoint = make(map[*endpoint]*relayEndpointAllocWork)
		r.handshakeWorkByEndpointByServerDisco = make(map[*endpoint]map[key.DiscoPublic]*relayHandshakeWork)
		r.handshakeWorkByServerDiscoVNI = make(map[serverDiscoVNI]*relayHandshakeWork)
		r.allocateHandshakeCh = make(chan *endpoint)
		r.allocateWorkDoneCh = make(chan relayEndpointAllocWorkDoneEvent)
		r.handshakeWorkDoneCh = make(chan relayEndpointHandshakeWorkDoneEvent)
		r.cancelWorkCh = make(chan *endpoint)
		r.newServerEndpointCh = make(chan newRelayServerEndpointEvent)
		r.rxChallengeCh = make(chan relayHandshakeChallengeEvent)
		r.runLoopStoppedCh = make(chan struct{}, 1)
		go r.runLoop()
	})
}

// relayHandshakeDiscoInfo serves to cache a [*discoInfo] for outstanding
// [*relayHandshakeWork] against a given relay server.
type relayHandshakeDiscoInfo struct {
	work set.Set[*relayHandshakeWork] // guarded by relayManager.discoInfoMu
	di   *discoInfo                   // immutable once initialized
}

// ensureDiscoInfoFor ensures a [*discoInfo] will be returned by discoInfo() for
// the server disco key associated with 'work'. Callers must also call
// derefDiscoInfoFor() when 'work' is complete.
func (r *relayManager) ensureDiscoInfoFor(work *relayHandshakeWork) {
	r.discoInfoMu.Lock()
	defer r.discoInfoMu.Unlock()
	di, ok := r.discoInfoByServerDisco[work.se.ServerDisco]
	if !ok {
		di = &relayHandshakeDiscoInfo{}
		di.work.Make()
		r.discoInfoByServerDisco[work.se.ServerDisco] = di
	}
	di.work.Add(work)
	if di.di == nil {
		di.di = &discoInfo{
			discoKey:   work.se.ServerDisco,
			discoShort: work.se.ServerDisco.ShortString(),
			sharedKey:  work.ep.c.discoPrivate.Shared(work.se.ServerDisco),
		}
	}
}

// derefDiscoInfoFor decrements the reference count of the [*discoInfo]
// associated with 'work'.
func (r *relayManager) derefDiscoInfoFor(work *relayHandshakeWork) {
	r.discoInfoMu.Lock()
	defer r.discoInfoMu.Unlock()
	di, ok := r.discoInfoByServerDisco[work.se.ServerDisco]
	if !ok {
		// TODO(jwhited): unexpected
		return
	}
	di.work.Delete(work)
	if di.work.Len() == 0 {
		delete(r.discoInfoByServerDisco, work.se.ServerDisco)
	}
}

// discoInfo returns a [*discoInfo] for 'serverDisco' if there is an
// active/ongoing handshake with it, otherwise it returns nil, false.
func (r *relayManager) discoInfo(serverDisco key.DiscoPublic) (_ *discoInfo, ok bool) {
	r.discoInfoMu.Lock()
	defer r.discoInfoMu.Unlock()
	di, ok := r.discoInfoByServerDisco[serverDisco]
	if ok {
		return di.di, ok
	}
	return nil, false
}

func (r *relayManager) handleCallMeMaybeVia(ep *endpoint, dm *disco.CallMeMaybeVia) {
	se := udprelay.ServerEndpoint{
		ServerDisco: dm.ServerDisco,
		LamportID:   dm.LamportID,
		AddrPorts:   dm.AddrPorts,
		VNI:         dm.VNI,
	}
	se.BindLifetime.Duration = dm.BindLifetime
	se.SteadyStateLifetime.Duration = dm.SteadyStateLifetime
	relayManagerInputEvent(r, nil, &r.newServerEndpointCh, newRelayServerEndpointEvent{
		ep: ep,
		se: se,
	})
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
// 'ctx' can be used for returning when runLoop is waiting for the calling
// goroutine to return, i.e. the calling goroutine was birthed by runLoop and is
// cancelable via 'ctx'. 'ctx' may be nil.
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

// stopWork stops all outstanding allocation & handshaking work for 'ep'.
func (r *relayManager) stopWork(ep *endpoint) {
	relayManagerInputEvent(r, nil, &r.cancelWorkCh, ep)
}

// stopHandshakeWorkFilter represents filters for handshake work cancellation
type stopHandshakeWorkFilter bool

const (
	stopHandshakeWorkAllServers       stopHandshakeWorkFilter = false
	stopHandshakeWorkOnlyKnownServers                         = true
)

// stopWorkRunLoop cancels & clears outstanding allocation and handshaking
// work for 'ep'. Handshake work cancellation is subject to the filter supplied
// in 'f'.
func (r *relayManager) stopWorkRunLoop(ep *endpoint, f stopHandshakeWorkFilter) {
	allocWork, ok := r.allocWorkByEndpoint[ep]
	if ok {
		allocWork.cancel()
		allocWork.wg.Wait()
		delete(r.allocWorkByEndpoint, ep)
	}
	byServerDisco, ok := r.handshakeWorkByEndpointByServerDisco[ep]
	if ok {
		for disco, handshakeWork := range byServerDisco {
			_, knownServer := r.serversByDisco[disco]
			if knownServer || f == stopHandshakeWorkAllServers {
				handshakeWork.cancel()
				handshakeWork.wg.Wait()
				delete(byServerDisco, disco)
				delete(r.handshakeWorkByServerDiscoVNI, serverDiscoVNI{handshakeWork.se.ServerDisco, handshakeWork.se.VNI})
			}
		}
		if len(byServerDisco) == 0 {
			delete(r.handshakeWorkByEndpointByServerDisco, ep)
		}
	}
}

func (r *relayManager) handleRxChallengeRunLoop(challenge relayHandshakeChallengeEvent) {
	work, ok := r.handshakeWorkByServerDiscoVNI[serverDiscoVNI{challenge.disco, challenge.vni}]
	if !ok {
		return
	}
	select {
	case <-work.doneCh:
		return
	case work.rxChallengeCh <- challenge:
		return
	}
}

func (r *relayManager) handleHandshakeWorkDoneRunLoop(done relayEndpointHandshakeWorkDoneEvent) {
	byServerDisco, ok := r.handshakeWorkByEndpointByServerDisco[done.work.ep]
	if !ok {
		return
	}
	work, ok := byServerDisco[done.work.se.ServerDisco]
	if !ok || work != done.work {
		return
	}
	delete(byServerDisco, done.work.se.ServerDisco)
	if len(byServerDisco) == 0 {
		delete(r.handshakeWorkByEndpointByServerDisco, done.work.ep)
	}
	delete(r.handshakeWorkByServerDiscoVNI, serverDiscoVNI{done.work.se.ServerDisco, done.work.se.VNI})
	if !done.answerSentTo.IsValid() {
		// The handshake timed out.
		return
	}
	// We received a challenge from and transmitted an answer towards the relay
	// server.
	// TODO(jwhited): Make the associated [*endpoint] aware of this
	//  [tailscale.com/net/udprelay.ServerEndpoint].
}

func (r *relayManager) handleNewServerEndpointRunLoop(newServerEndpoint newRelayServerEndpointEvent) {
	// Check for duplicate work by server disco + VNI.
	sdv := serverDiscoVNI{newServerEndpoint.se.ServerDisco, newServerEndpoint.se.VNI}
	existingWork, ok := r.handshakeWorkByServerDiscoVNI[sdv]
	if ok {
		// There's in-progress handshake work for the server disco + VNI, which
		// uniquely identify a [udprelay.ServerEndpoint]. Compare Lamport
		// IDs to determine which is newer.
		if existingWork.se.LamportID >= newServerEndpoint.se.LamportID {
			// The existing work is a duplicate or newer. Return early.
			return
		}

		// The existing work is no longer valid, clean it up. Be sure to lookup
		// by the existing work's [*endpoint], not the incoming "new" work as
		// they are not necessarily matching.
		existingWork.cancel()
		existingWork.wg.Wait()
		delete(r.handshakeWorkByServerDiscoVNI, sdv)
		byServerDisco, ok := r.handshakeWorkByEndpointByServerDisco[existingWork.ep]
		if ok {
			delete(byServerDisco, sdv.serverDisco)
			if len(byServerDisco) == 0 {
				delete(r.handshakeWorkByEndpointByServerDisco, existingWork.ep)
			}
		}
	}

	// Check for duplicate work by [*endpoint] + server disco.
	byServerDisco, ok := r.handshakeWorkByEndpointByServerDisco[newServerEndpoint.ep]
	if ok {
		existingWork, ok := byServerDisco[newServerEndpoint.se.ServerDisco]
		if ok {
			if newServerEndpoint.se.LamportID <= existingWork.se.LamportID {
				// The "new" server endpoint is outdated or duplicate in
				// consideration against existing handshake work. Return early.
				return
			}
			// Cancel existing handshake that has a lower lamport ID.
			existingWork.cancel()
			existingWork.wg.Wait()
			delete(r.handshakeWorkByServerDiscoVNI, sdv)
			delete(byServerDisco, sdv.serverDisco)
			if len(byServerDisco) == 0 {
				delete(r.handshakeWorkByEndpointByServerDisco, existingWork.ep)
			}
		}
	}

	// We're now reasonably sure we're dealing with the latest
	// [udprelay.ServerEndpoint] from a server event order perspective
	// (LamportID). Update server disco key tracking if appropriate.
	if newServerEndpoint.server.IsValid() {
		serverDisco, ok := r.serversByAddrPort[newServerEndpoint.server]
		if !ok {
			// Allocation raced with an update to our known servers set. This
			// server is no longer known. Return early.
			return
		}
		if serverDisco.Compare(newServerEndpoint.se.ServerDisco) != 0 {
			// The server's disco key has either changed, or simply become
			// known for the first time. In the former case we end up detaching
			// any in-progress handshake work from a "known" relay server.
			// Practically speaking we expect the detached work to fail
			// if the server key did in fact change (server restart) while we
			// were attempting to handshake with it. It is possible, though
			// unlikely, for a server addr:port to effectively move between
			// nodes. Either way, there is no harm in detaching existing work,
			// and we explicitly let that happen for the rare case the detached
			// handshake would complete and remain functional.
			delete(r.serversByDisco, serverDisco)
			delete(r.serversByAddrPort, newServerEndpoint.server)
			r.serversByDisco[serverDisco] = newServerEndpoint.server
			r.serversByAddrPort[newServerEndpoint.server] = serverDisco
		}
	}

	// We're ready to start a new handshake.
	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}
	work := &relayHandshakeWork{
		ep:     newServerEndpoint.ep,
		se:     newServerEndpoint.se,
		doneCh: make(chan struct{}),
		ctx:    ctx,
		cancel: cancel,
		wg:     wg,
	}
	if byServerDisco == nil {
		byServerDisco = make(map[key.DiscoPublic]*relayHandshakeWork)
		r.handshakeWorkByEndpointByServerDisco[newServerEndpoint.ep] = byServerDisco
	}
	byServerDisco[newServerEndpoint.se.ServerDisco] = work
	r.handshakeWorkByServerDiscoVNI[sdv] = work

	wg.Add(1)
	go r.handshakeServerEndpoint(work)
}

func (r *relayManager) handshakeServerEndpoint(work *relayHandshakeWork) {
	defer work.wg.Done()

	done := relayEndpointHandshakeWorkDoneEvent{work: work}
	r.ensureDiscoInfoFor(work)

	defer func() {
		r.derefDiscoInfoFor(work)
		close(work.doneCh)
		relayManagerInputEvent(r, work.ctx, &r.handshakeWorkDoneCh, done)
		work.cancel()
	}()

	sentBindAny := false
	bind := &disco.BindUDPRelayEndpoint{}
	for _, addrPort := range work.se.AddrPorts {
		if addrPort.IsValid() {
			sentBindAny = true
			go work.ep.c.sendDiscoMessage(addrPort, ptr.To(work.se.VNI), key.NodePublic{}, work.se.ServerDisco, bind, discoLog)
		}
	}
	if !sentBindAny {
		return
	}

	// Limit goroutine lifetime to a reasonable duration. This is intentionally
	// detached and independent of 'BindLifetime' to prevent relay server
	// (mis)configuration from negatively impacting client resource usage.
	const maxHandshakeLifetime = time.Second * 30
	timer := time.NewTimer(min(work.se.BindLifetime.Duration, maxHandshakeLifetime))
	defer timer.Stop()

	// Wait for cancellation, a challenge to be rx'd, or handshake lifetime to
	// expire. Our initial implementation values simplicity over other aspects,
	// e.g. it is not resilient to any packet loss.
	//
	// We may want to eventually consider [disc.BindUDPRelayEndpoint]
	// retransmission lacking challenge rx, and
	// [disco.BindUDPRelayEndpointAnswer] duplication in front of
	// [disco.Ping] until [disco.Ping] or [disco.Pong] is received.
	select {
	case <-work.ctx.Done():
		return
	case challenge := <-work.rxChallengeCh:
		answer := &disco.BindUDPRelayEndpointAnswer{Answer: challenge.challenge}
		done.answerSentTo = challenge.from
		// Send answer back to relay server. Typically sendDiscoMessage() calls
		// are invoked via a new goroutine in attempt to limit crypto+syscall
		// time contributing to system backpressure, and to fire roundtrip
		// latency-relevant messages as closely together as possible. We
		// intentionally don't do that here, because:
		//  1. The primary backpressure concern is around the work.rxChallengeCh
		//     writer on the [Conn] packet rx path, who is already unblocked
		//     since we read from the channel. Relay servers only ever tx one
		//     challenge per rx'd bind message for a given (the first seen) src.
		//  2. runLoop() may be waiting for this 'work' to complete if
		//     explicitly canceled for some reason elsewhere, but this is
		//     typically only around [*endpoint] and/or [Conn] shutdown.
		//  3. It complicates the defer()'d [*discoInfo] deref and 'work'
		//     completion event order. sendDiscoMessage() assumes the related
		//     [*discoInfo] is still available. We also don't want the
		//     [*endpoint] to send a [disco.Ping] before the
		//     [disco.BindUDPRelayEndpointAnswer] has gone out, otherwise the
		//     remote side will never see the ping, delaying/preventing the
		//     [udprelay.ServerEndpoint] from becoming fully operational.
		//  4. This is a singular tx with no roundtrip latency measurements
		//     involved.
		work.ep.c.sendDiscoMessage(challenge.from, ptr.To(work.se.VNI), key.NodePublic{}, work.se.ServerDisco, answer, discoLog)
		return
	case <-timer.C:
		// The handshake timed out.
		return
	}
}

func (r *relayManager) allocateAllServersRunLoop(ep *endpoint) {
	if len(r.serversByAddrPort) == 0 {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := &relayEndpointAllocWork{ep: ep, cancel: cancel, wg: &sync.WaitGroup{}}
	for k := range r.serversByAddrPort {
		started.wg.Add(1)
		go r.allocateSingleServer(ctx, started.wg, k, ep)
	}
	r.allocWorkByEndpoint[ep] = started
	go func() {
		started.wg.Wait()
		started.cancel()
		relayManagerInputEvent(r, ctx, &r.allocateWorkDoneCh, relayEndpointAllocWorkDoneEvent{work: started})
	}()
}

func (r *relayManager) allocateSingleServer(ctx context.Context, wg *sync.WaitGroup, server netip.AddrPort, ep *endpoint) {
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
