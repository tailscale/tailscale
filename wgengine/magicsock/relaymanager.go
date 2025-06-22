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
	"tailscale.com/net/stun"
	udprelay "tailscale.com/net/udprelay/endpoint"
	"tailscale.com/types/key"
	"tailscale.com/util/httpm"
	"tailscale.com/util/set"
)

// relayManager manages allocation, handshaking, and initial probing (disco
// ping/pong) of [tailscale.com/net/udprelay.Server] endpoints. The zero value
// is ready for use.
//
// [relayManager] methods can be called by [Conn] and [endpoint] while their .mu
// mutexes are held. Therefore, in order to avoid deadlocks, [relayManager] must
// never attempt to acquire those mutexes, including synchronous calls back
// towards [Conn] or [endpoint] methods that acquire them.
type relayManager struct {
	initOnce sync.Once

	// ===================================================================
	// The following fields are owned by a single goroutine, runLoop().
	serversByAddrPort                    map[netip.AddrPort]key.DiscoPublic
	serversByDisco                       map[key.DiscoPublic]netip.AddrPort
	allocWorkByEndpoint                  map[*endpoint]*relayEndpointAllocWork
	handshakeWorkByEndpointByServerDisco map[*endpoint]map[key.DiscoPublic]*relayHandshakeWork
	handshakeWorkByServerDiscoVNI        map[serverDiscoVNI]*relayHandshakeWork
	handshakeWorkAwaitingPong            map[*relayHandshakeWork]addrPortVNI
	addrPortVNIToHandshakeWork           map[addrPortVNI]*relayHandshakeWork

	// ===================================================================
	// The following chan fields serve event inputs to a single goroutine,
	// runLoop().
	allocateHandshakeCh   chan *endpoint
	allocateWorkDoneCh    chan relayEndpointAllocWorkDoneEvent
	handshakeWorkDoneCh   chan relayEndpointHandshakeWorkDoneEvent
	cancelWorkCh          chan *endpoint
	newServerEndpointCh   chan newRelayServerEndpointEvent
	rxHandshakeDiscoMsgCh chan relayHandshakeDiscoMsgEvent
	serversCh             chan set.Set[netip.AddrPort]

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

	// handshakeServerEndpoint() always writes to doneCh (len 1) when it
	// returns. It may end up writing the same event afterward to
	// relayManager.handshakeWorkDoneCh if runLoop() can receive it. runLoop()
	// must select{} read on doneCh to prevent deadlock when attempting to write
	// to rxDiscoMsgCh.
	rxDiscoMsgCh chan relayHandshakeDiscoMsgEvent
	doneCh       chan relayEndpointHandshakeWorkDoneEvent

	ctx    context.Context
	cancel context.CancelFunc
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
	work             *relayHandshakeWork
	pongReceivedFrom netip.AddrPort // or zero value if handshake or ping/pong did not complete
	latency          time.Duration  // only relevant if pongReceivedFrom.IsValid()
}

// hasActiveWorkRunLoop returns true if there is outstanding allocation or
// handshaking work for any endpoint, otherwise it returns false.
func (r *relayManager) hasActiveWorkRunLoop() bool {
	return len(r.allocWorkByEndpoint) > 0 || len(r.handshakeWorkByEndpointByServerDisco) > 0
}

// hasActiveWorkForEndpointRunLoop returns true if there is outstanding
// allocation or handshaking work for the provided endpoint, otherwise it
// returns false.
func (r *relayManager) hasActiveWorkForEndpointRunLoop(ep *endpoint) bool {
	_, handshakeWork := r.handshakeWorkByEndpointByServerDisco[ep]
	_, allocWork := r.allocWorkByEndpoint[ep]
	return handshakeWork || allocWork
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
			if !r.hasActiveWorkForEndpointRunLoop(ep) {
				r.allocateAllServersRunLoop(ep)
			}
			if !r.hasActiveWorkRunLoop() {
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
			if !r.hasActiveWorkRunLoop() {
				return
			}
		case ep := <-r.cancelWorkCh:
			r.stopWorkRunLoop(ep)
			if !r.hasActiveWorkRunLoop() {
				return
			}
		case newServerEndpoint := <-r.newServerEndpointCh:
			r.handleNewServerEndpointRunLoop(newServerEndpoint)
			if !r.hasActiveWorkRunLoop() {
				return
			}
		case done := <-r.handshakeWorkDoneCh:
			r.handleHandshakeWorkDoneRunLoop(done)
			if !r.hasActiveWorkRunLoop() {
				return
			}
		case discoMsgEvent := <-r.rxHandshakeDiscoMsgCh:
			r.handleRxHandshakeDiscoMsgRunLoop(discoMsgEvent)
			if !r.hasActiveWorkRunLoop() {
				return
			}
		case serversUpdate := <-r.serversCh:
			r.handleServersUpdateRunLoop(serversUpdate)
			if !r.hasActiveWorkRunLoop() {
				return
			}
		}
	}
}

func (r *relayManager) handleServersUpdateRunLoop(update set.Set[netip.AddrPort]) {
	for k, v := range r.serversByAddrPort {
		if !update.Contains(k) {
			delete(r.serversByAddrPort, k)
			delete(r.serversByDisco, v)
		}
	}
	for _, v := range update.Slice() {
		_, ok := r.serversByAddrPort[v]
		if ok {
			// don't zero known disco keys
			continue
		}
		r.serversByAddrPort[v] = key.DiscoPublic{}
	}
}

type relayHandshakeDiscoMsgEvent struct {
	conn  *Conn // for access to [Conn] if there is no associated [relayHandshakeWork]
	msg   disco.Message
	disco key.DiscoPublic
	from  netip.AddrPort
	vni   uint32
	at    time.Time
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
		r.handshakeWorkAwaitingPong = make(map[*relayHandshakeWork]addrPortVNI)
		r.addrPortVNIToHandshakeWork = make(map[addrPortVNI]*relayHandshakeWork)
		r.allocateHandshakeCh = make(chan *endpoint)
		r.allocateWorkDoneCh = make(chan relayEndpointAllocWorkDoneEvent)
		r.handshakeWorkDoneCh = make(chan relayEndpointHandshakeWorkDoneEvent)
		r.cancelWorkCh = make(chan *endpoint)
		r.newServerEndpointCh = make(chan newRelayServerEndpointEvent)
		r.rxHandshakeDiscoMsgCh = make(chan relayHandshakeDiscoMsgEvent)
		r.serversCh = make(chan set.Set[netip.AddrPort])
		r.runLoopStoppedCh = make(chan struct{}, 1)
		r.runLoopStoppedCh <- struct{}{}
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

// handleGeneveEncapDiscoMsgNotBestAddr handles reception of Geneve-encapsulated
// disco messages if they are not associated with any known
// [*endpoint.bestAddr].
func (r *relayManager) handleGeneveEncapDiscoMsgNotBestAddr(conn *Conn, dm disco.Message, di *discoInfo, src epAddr) {
	relayManagerInputEvent(r, nil, &r.rxHandshakeDiscoMsgCh, relayHandshakeDiscoMsgEvent{conn: conn, msg: dm, disco: di.discoKey, from: src.ap, vni: src.vni.get(), at: time.Now()})
}

// handleRelayServersSet handles an update of the complete relay server set.
func (r *relayManager) handleRelayServersSet(servers set.Set[netip.AddrPort]) {
	relayManagerInputEvent(r, nil, &r.serversCh, servers)
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
// endpoints for 'ep' on all known relay servers if there is no outstanding
// work.
func (r *relayManager) allocateAndHandshakeAllServers(ep *endpoint) {
	relayManagerInputEvent(r, nil, &r.allocateHandshakeCh, ep)
}

// stopWork stops all outstanding allocation & handshaking work for 'ep'.
func (r *relayManager) stopWork(ep *endpoint) {
	relayManagerInputEvent(r, nil, &r.cancelWorkCh, ep)
}

// stopWorkRunLoop cancels & clears outstanding allocation and handshaking
// work for 'ep'.
func (r *relayManager) stopWorkRunLoop(ep *endpoint) {
	allocWork, ok := r.allocWorkByEndpoint[ep]
	if ok {
		allocWork.cancel()
		allocWork.wg.Wait()
		delete(r.allocWorkByEndpoint, ep)
	}
	byServerDisco, ok := r.handshakeWorkByEndpointByServerDisco[ep]
	if ok {
		for _, handshakeWork := range byServerDisco {
			handshakeWork.cancel()
			done := <-handshakeWork.doneCh
			r.handleHandshakeWorkDoneRunLoop(done)
		}
	}
}

// addrPortVNI represents a combined netip.AddrPort and Geneve header virtual
// network identifier.
type addrPortVNI struct {
	addrPort netip.AddrPort
	vni      uint32
}

func (r *relayManager) handleRxHandshakeDiscoMsgRunLoop(event relayHandshakeDiscoMsgEvent) {
	var (
		work *relayHandshakeWork
		ok   bool
	)
	apv := addrPortVNI{event.from, event.vni}
	switch msg := event.msg.(type) {
	case *disco.BindUDPRelayEndpointChallenge:
		work, ok = r.handshakeWorkByServerDiscoVNI[serverDiscoVNI{event.disco, event.vni}]
		if !ok {
			// No outstanding work tied to this challenge, discard.
			return
		}
		_, ok = r.handshakeWorkAwaitingPong[work]
		if ok {
			// We've seen a challenge for this relay endpoint previously,
			// discard. Servers only respond to the first src ip:port they see
			// binds from.
			return
		}
		_, ok = r.addrPortVNIToHandshakeWork[apv]
		if ok {
			// There is existing work for the same [addrPortVNI] that is not
			// 'work'. If both instances happen to be on the same server we
			// could attempt to resolve event order using LamportID. For now
			// just leave both work instances alone and take no action other
			// than to discard this challenge msg.
			return
		}
		// Update state so that future ping/pong will route to 'work'.
		r.handshakeWorkAwaitingPong[work] = apv
		r.addrPortVNIToHandshakeWork[apv] = work
	case *disco.Ping:
		// Always TX a pong. We might not have any associated work if ping
		// reception raced with our call to [endpoint.relayEndpointReady()], so
		// err on the side of enabling the remote side to use this path.
		//
		// Conn.handlePingLocked() makes efforts to suppress duplicate pongs
		// where the same ping can be received both via raw socket and UDP
		// socket on Linux. We make no such efforts here as the raw socket BPF
		// program does not support Geneve-encapsulated disco, and is also
		// disabled by default.
		vni := virtualNetworkID{}
		vni.set(event.vni)
		go event.conn.sendDiscoMessage(epAddr{ap: event.from, vni: vni}, key.NodePublic{}, event.disco, &disco.Pong{
			TxID: msg.TxID,
			Src:  event.from,
		}, discoVerboseLog)

		work, ok = r.addrPortVNIToHandshakeWork[apv]
		if !ok {
			// No outstanding work tied to this [addrPortVNI], return early.
			return
		}
	case *disco.Pong:
		work, ok = r.addrPortVNIToHandshakeWork[apv]
		if !ok {
			// No outstanding work tied to this [addrPortVNI], discard.
			return
		}
	default:
		// Unexpected message type, discard.
		return
	}
	select {
	case done := <-work.doneCh:
		// handshakeServerEndpoint() returned, clean up its state.
		r.handleHandshakeWorkDoneRunLoop(done)
		return
	case work.rxDiscoMsgCh <- event:
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
	apv, ok := r.handshakeWorkAwaitingPong[work]
	if ok {
		delete(r.handshakeWorkAwaitingPong, work)
		delete(r.addrPortVNIToHandshakeWork, apv)
	}
	if !done.pongReceivedFrom.IsValid() {
		// The handshake or ping/pong probing timed out.
		return
	}
	// This relay endpoint is functional.
	vni := virtualNetworkID{}
	vni.set(done.work.se.VNI)
	addr := epAddr{ap: done.pongReceivedFrom, vni: vni}
	// ep.relayEndpointReady() must be called in a new goroutine to prevent
	// deadlocks as it acquires [endpoint] & [Conn] mutexes. See [relayManager]
	// docs for details.
	go done.work.ep.relayEndpointReady(addr, done.latency)
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

		// The existing work is no longer valid, clean it up.
		existingWork.cancel()
		done := <-existingWork.doneCh
		r.handleHandshakeWorkDoneRunLoop(done)
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
			done := <-existingWork.doneCh
			r.handleHandshakeWorkDoneRunLoop(done)
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
	work := &relayHandshakeWork{
		ep:           newServerEndpoint.ep,
		se:           newServerEndpoint.se,
		rxDiscoMsgCh: make(chan relayHandshakeDiscoMsgEvent),
		doneCh:       make(chan relayEndpointHandshakeWorkDoneEvent, 1),
		ctx:          ctx,
		cancel:       cancel,
	}
	if byServerDisco == nil {
		byServerDisco = make(map[key.DiscoPublic]*relayHandshakeWork)
		r.handshakeWorkByEndpointByServerDisco[newServerEndpoint.ep] = byServerDisco
	}
	byServerDisco[newServerEndpoint.se.ServerDisco] = work
	r.handshakeWorkByServerDiscoVNI[sdv] = work

	go r.handshakeServerEndpoint(work)
}

func (r *relayManager) handshakeServerEndpoint(work *relayHandshakeWork) {
	done := relayEndpointHandshakeWorkDoneEvent{work: work}
	r.ensureDiscoInfoFor(work)

	defer func() {
		r.derefDiscoInfoFor(work)
		work.doneCh <- done
		relayManagerInputEvent(r, work.ctx, &r.handshakeWorkDoneCh, done)
		work.cancel()
	}()

	sentBindAny := false
	bind := &disco.BindUDPRelayEndpoint{}
	vni := virtualNetworkID{}
	vni.set(work.se.VNI)
	for _, addrPort := range work.se.AddrPorts {
		if addrPort.IsValid() {
			sentBindAny = true
			go work.ep.c.sendDiscoMessage(epAddr{ap: addrPort, vni: vni}, key.NodePublic{}, work.se.ServerDisco, bind, discoVerboseLog)
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

	// Limit the number of pings we will transmit. Inbound pings trigger
	// outbound pings, so we want to be a little defensive.
	const limitPings = 10

	var (
		handshakeState disco.BindUDPRelayHandshakeState = disco.BindUDPRelayHandshakeStateBindSent
		sentPingAt                                      = make(map[stun.TxID]time.Time)
	)

	txPing := func(to netip.AddrPort, withAnswer *[32]byte) {
		if len(sentPingAt) == limitPings {
			return
		}
		epDisco := work.ep.disco.Load()
		if epDisco == nil {
			return
		}
		txid := stun.NewTxID()
		sentPingAt[txid] = time.Now()
		ping := &disco.Ping{
			TxID:    txid,
			NodeKey: work.ep.c.publicKeyAtomic.Load(),
		}
		go func() {
			if withAnswer != nil {
				answer := &disco.BindUDPRelayEndpointAnswer{Answer: *withAnswer}
				work.ep.c.sendDiscoMessage(epAddr{ap: to, vni: vni}, key.NodePublic{}, work.se.ServerDisco, answer, discoVerboseLog)
			}
			work.ep.c.sendDiscoMessage(epAddr{ap: to, vni: vni}, key.NodePublic{}, epDisco.key, ping, discoVerboseLog)
		}()
	}

	// This for{select{}} is responsible for handshaking and tx'ing ping/pong
	// when the handshake is complete.
	for {
		select {
		case <-work.ctx.Done():
			return
		case msgEvent := <-work.rxDiscoMsgCh:
			switch msg := msgEvent.msg.(type) {
			case *disco.BindUDPRelayEndpointChallenge:
				if handshakeState >= disco.BindUDPRelayHandshakeStateAnswerSent {
					continue
				}
				txPing(msgEvent.from, &msg.Challenge)
				handshakeState = disco.BindUDPRelayHandshakeStateAnswerSent
			case *disco.Ping:
				if handshakeState < disco.BindUDPRelayHandshakeStateAnswerSent {
					continue
				}
				// An inbound ping from the remote peer indicates we completed a
				// handshake with the relay server (our answer msg was
				// received). Chances are our ping was dropped before the remote
				// handshake was complete. We need to rx a pong to determine
				// latency, so send another ping. Since the handshake is
				// complete we do not need to send an answer in front of this
				// one.
				//
				// We don't need to TX a pong, that was already handled for us
				// in handleRxHandshakeDiscoMsgRunLoop().
				txPing(msgEvent.from, nil)
			case *disco.Pong:
				at, ok := sentPingAt[msg.TxID]
				if !ok {
					continue
				}
				// The relay server endpoint is functional! Record the
				// round-trip latency and return.
				done.pongReceivedFrom = msgEvent.from
				done.latency = time.Since(at)
				return
			default:
				// unexpected message type, silently discard
				continue
			}
			return
		case <-timer.C:
			// The handshake timed out.
			return
		}
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
	req, err := http.NewRequestWithContext(reqCtx, httpm.POST, "http://"+server.String()+"/v0/relay/endpoint", &b)
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
