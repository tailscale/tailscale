// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"tailscale.com/disco"
	"tailscale.com/net/packet"
	"tailscale.com/net/stun"
	udprelay "tailscale.com/net/udprelay/endpoint"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/util/set"
)

// relayManager manages allocation, handshaking, and initial probing (disco
// ping/pong) of [tailscale.com/net/udprelay.Server] endpoints. The zero value
// is ready for use.
//
// [relayManager] methods can be called by [Conn] and [endpoint] while their .mu
// mutexes are held. Therefore, in order to avoid deadlocks, [relayManager] must
// never attempt to acquire those mutexes synchronously from its runLoop(),
// including synchronous calls back towards [Conn] or [endpoint] methods that
// acquire them.
type relayManager struct {
	initOnce sync.Once

	// ===================================================================
	// The following fields are owned by a single goroutine, runLoop().
	serversByNodeKey                        map[key.NodePublic]candidatePeerRelay
	allocWorkByCandidatePeerRelayByEndpoint map[*endpoint]map[candidatePeerRelay]*relayEndpointAllocWork
	allocWorkByDiscoKeysByServerNodeKey     map[key.NodePublic]map[key.SortedPairOfDiscoPublic]*relayEndpointAllocWork
	handshakeWorkByServerDiscoByEndpoint    map[*endpoint]map[key.DiscoPublic]*relayHandshakeWork
	handshakeWorkByServerDiscoVNI           map[serverDiscoVNI]*relayHandshakeWork
	handshakeWorkAwaitingPong               map[*relayHandshakeWork]addrPortVNI
	addrPortVNIToHandshakeWork              map[addrPortVNI]*relayHandshakeWork
	handshakeGeneration                     uint32
	allocGeneration                         uint32

	// ===================================================================
	// The following chan fields serve event inputs to a single goroutine,
	// runLoop().
	startDiscoveryCh    chan endpointWithLastBest
	allocateWorkDoneCh  chan relayEndpointAllocWorkDoneEvent
	handshakeWorkDoneCh chan relayEndpointHandshakeWorkDoneEvent
	cancelWorkCh        chan *endpoint
	newServerEndpointCh chan newRelayServerEndpointEvent
	rxDiscoMsgCh        chan relayDiscoMsgEvent
	serversCh           chan set.Set[candidatePeerRelay]
	getServersCh        chan chan set.Set[candidatePeerRelay]
	derpHomeChangeCh    chan derpHomeChangeEvent

	discoInfoMu            syncs.Mutex // guards the following field
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
	wlb    endpointWithLastBest
	se     udprelay.ServerEndpoint
	server candidatePeerRelay

	handshakeGen uint32

	// handshakeServerEndpoint() always writes to doneCh (len 1) when it
	// returns. It may end up writing the same event afterward to
	// relayManager.handshakeWorkDoneCh if runLoop() can receive it. runLoop()
	// must select{} read on doneCh to prevent deadlock when attempting to write
	// to rxDiscoMsgCh.
	rxDiscoMsgCh chan relayDiscoMsgEvent
	doneCh       chan relayEndpointHandshakeWorkDoneEvent

	ctx    context.Context
	cancel context.CancelFunc
}

func (r *relayHandshakeWork) dlogf(format string, args ...any) {
	if !r.wlb.ep.c.debugLogging.Load() {
		return
	}
	var relay string
	if r.server.nodeKey.IsZero() {
		relay = "from-call-me-maybe-via"
	} else {
		relay = r.server.nodeKey.ShortString()
	}
	r.wlb.ep.c.logf("%s node=%v relay=%v handshakeGen=%d disco[0]=%v disco[1]=%v",
		fmt.Sprintf(format, args...),
		r.wlb.ep.publicKey.ShortString(),
		relay,
		r.handshakeGen,
		r.se.ClientDisco[0].ShortString(),
		r.se.ClientDisco[1].ShortString(),
	)
}

// newRelayServerEndpointEvent indicates a new [udprelay.ServerEndpoint] has
// become known either via allocation with a relay server, or via
// [disco.CallMeMaybeVia] reception. This structure is immutable once
// initialized.
type newRelayServerEndpointEvent struct {
	wlb    endpointWithLastBest
	se     udprelay.ServerEndpoint
	server candidatePeerRelay // zero value if learned via [disco.CallMeMaybeVia]
}

// relayEndpointAllocWorkDoneEvent indicates relay server endpoint allocation
// work for an [*endpoint] has completed. This structure is immutable once
// initialized.
type relayEndpointAllocWorkDoneEvent struct {
	work      *relayEndpointAllocWork
	allocated udprelay.ServerEndpoint // !allocated.ServerDisco.IsZero() if allocation succeeded
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
	return len(r.allocWorkByCandidatePeerRelayByEndpoint) > 0 || len(r.handshakeWorkByServerDiscoByEndpoint) > 0
}

// hasActiveWorkForEndpointRunLoop returns true if there is outstanding
// allocation or handshaking work for the provided endpoint, otherwise it
// returns false.
func (r *relayManager) hasActiveWorkForEndpointRunLoop(ep *endpoint) bool {
	_, handshakeWork := r.handshakeWorkByServerDiscoByEndpoint[ep]
	_, allocWork := r.allocWorkByCandidatePeerRelayByEndpoint[ep]
	return handshakeWork || allocWork
}

// derpHomeChangeEvent represents a change in the DERP home region for the
// node identified by nodeKey. This structure is immutable once initialized.
type derpHomeChangeEvent struct {
	nodeKey  key.NodePublic
	regionID uint16
}

// handleDERPHomeChange handles a DERP home change event for nodeKey and
// regionID.
func (r *relayManager) handleDERPHomeChange(nodeKey key.NodePublic, regionID uint16) {
	relayManagerInputEvent(r, nil, &r.derpHomeChangeCh, derpHomeChangeEvent{
		nodeKey:  nodeKey,
		regionID: regionID,
	})
}

func (r *relayManager) handleDERPHomeChangeRunLoop(event derpHomeChangeEvent) {
	c, ok := r.serversByNodeKey[event.nodeKey]
	if ok {
		c.derpHomeRegionID = event.regionID
		r.serversByNodeKey[event.nodeKey] = c
	}
}

// runLoop is a form of event loop. It ensures exclusive access to most of
// [relayManager] state.
func (r *relayManager) runLoop() {
	defer func() {
		r.runLoopStoppedCh <- struct{}{}
	}()

	for {
		select {
		case startDiscovery := <-r.startDiscoveryCh:
			if !r.hasActiveWorkForEndpointRunLoop(startDiscovery.ep) {
				r.allocateAllServersRunLoop(startDiscovery)
			}
			if !r.hasActiveWorkRunLoop() {
				return
			}
		case done := <-r.allocateWorkDoneCh:
			r.handleAllocWorkDoneRunLoop(done)
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
		case discoMsgEvent := <-r.rxDiscoMsgCh:
			r.handleRxDiscoMsgRunLoop(discoMsgEvent)
			if !r.hasActiveWorkRunLoop() {
				return
			}
		case serversUpdate := <-r.serversCh:
			r.handleServersUpdateRunLoop(serversUpdate)
			if !r.hasActiveWorkRunLoop() {
				return
			}
		case getServersCh := <-r.getServersCh:
			r.handleGetServersRunLoop(getServersCh)
			if !r.hasActiveWorkRunLoop() {
				return
			}
		case derpHomeChange := <-r.derpHomeChangeCh:
			r.handleDERPHomeChangeRunLoop(derpHomeChange)
			if !r.hasActiveWorkRunLoop() {
				return
			}
		}
	}
}

func (r *relayManager) handleGetServersRunLoop(getServersCh chan set.Set[candidatePeerRelay]) {
	servers := make(set.Set[candidatePeerRelay], len(r.serversByNodeKey))
	for _, v := range r.serversByNodeKey {
		servers.Add(v)
	}
	getServersCh <- servers
}

func (r *relayManager) getServers() set.Set[candidatePeerRelay] {
	ch := make(chan set.Set[candidatePeerRelay])
	relayManagerInputEvent(r, nil, &r.getServersCh, ch)
	return <-ch
}

func (r *relayManager) handleServersUpdateRunLoop(update set.Set[candidatePeerRelay]) {
	for _, v := range r.serversByNodeKey {
		if !update.Contains(v) {
			delete(r.serversByNodeKey, v.nodeKey)
		}
	}
	for _, v := range update.Slice() {
		r.serversByNodeKey[v.nodeKey] = v
	}
}

type relayDiscoMsgEvent struct {
	conn               *Conn // for access to [Conn] if there is no associated [relayHandshakeWork]
	msg                disco.Message
	relayServerNodeKey key.NodePublic // nonzero if msg is a [*disco.AllocateUDPRelayEndpointResponse]
	disco              key.DiscoPublic
	from               netip.AddrPort
	vni                uint32
	at                 time.Time
}

// relayEndpointAllocWork serves to track in-progress relay endpoint allocation
// for an [*endpoint]. This structure is immutable once initialized.
type relayEndpointAllocWork struct {
	wlb                endpointWithLastBest
	discoKeys          key.SortedPairOfDiscoPublic
	candidatePeerRelay candidatePeerRelay // zero value if learned via [disco.CallMeMaybeVia]

	allocGen uint32

	// allocateServerEndpoint() always writes to doneCh (len 1) when it
	// returns. It may end up writing the same event afterward to
	// [relayManager.allocateWorkDoneCh] if runLoop() can receive it. runLoop()
	// must select{} read on doneCh to prevent deadlock when attempting to write
	// to rxDiscoMsgCh.
	rxDiscoMsgCh chan *disco.AllocateUDPRelayEndpointResponse
	doneCh       chan relayEndpointAllocWorkDoneEvent

	ctx    context.Context
	cancel context.CancelFunc
}

func (r *relayEndpointAllocWork) dlogf(format string, args ...any) {
	if !r.wlb.ep.c.debugLogging.Load() {
		return
	}
	r.wlb.ep.c.logf("%s node=%v relay=%v allocGen=%d disco[0]=%v disco[1]=%v",
		fmt.Sprintf(format, args...),
		r.wlb.ep.publicKey.ShortString(),
		r.candidatePeerRelay.nodeKey.ShortString(),
		r.allocGen,
		r.discoKeys.Get()[0].ShortString(),
		r.discoKeys.Get()[1].ShortString(),
	)
}

// init initializes [relayManager] if it is not already initialized.
func (r *relayManager) init() {
	r.initOnce.Do(func() {
		r.discoInfoByServerDisco = make(map[key.DiscoPublic]*relayHandshakeDiscoInfo)
		r.serversByNodeKey = make(map[key.NodePublic]candidatePeerRelay)
		r.allocWorkByCandidatePeerRelayByEndpoint = make(map[*endpoint]map[candidatePeerRelay]*relayEndpointAllocWork)
		r.allocWorkByDiscoKeysByServerNodeKey = make(map[key.NodePublic]map[key.SortedPairOfDiscoPublic]*relayEndpointAllocWork)
		r.handshakeWorkByServerDiscoByEndpoint = make(map[*endpoint]map[key.DiscoPublic]*relayHandshakeWork)
		r.handshakeWorkByServerDiscoVNI = make(map[serverDiscoVNI]*relayHandshakeWork)
		r.handshakeWorkAwaitingPong = make(map[*relayHandshakeWork]addrPortVNI)
		r.addrPortVNIToHandshakeWork = make(map[addrPortVNI]*relayHandshakeWork)
		r.startDiscoveryCh = make(chan endpointWithLastBest)
		r.allocateWorkDoneCh = make(chan relayEndpointAllocWorkDoneEvent)
		r.handshakeWorkDoneCh = make(chan relayEndpointHandshakeWorkDoneEvent)
		r.cancelWorkCh = make(chan *endpoint)
		r.newServerEndpointCh = make(chan newRelayServerEndpointEvent)
		r.rxDiscoMsgCh = make(chan relayDiscoMsgEvent)
		r.serversCh = make(chan set.Set[candidatePeerRelay])
		r.getServersCh = make(chan chan set.Set[candidatePeerRelay])
		r.derpHomeChangeCh = make(chan derpHomeChangeEvent)
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
			sharedKey:  work.wlb.ep.c.discoAtomic.Private().Shared(work.se.ServerDisco),
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

func (r *relayManager) handleCallMeMaybeVia(ep *endpoint, lastBest addrQuality, lastBestIsTrusted bool, dm *disco.CallMeMaybeVia) {
	se := udprelay.ServerEndpoint{
		ServerDisco: dm.ServerDisco,
		ClientDisco: dm.ClientDisco,
		LamportID:   dm.LamportID,
		AddrPorts:   dm.AddrPorts,
		VNI:         dm.VNI,
	}
	se.BindLifetime.Duration = dm.BindLifetime
	se.SteadyStateLifetime.Duration = dm.SteadyStateLifetime
	relayManagerInputEvent(r, nil, &r.newServerEndpointCh, newRelayServerEndpointEvent{
		wlb: endpointWithLastBest{
			ep:                ep,
			lastBest:          lastBest,
			lastBestIsTrusted: lastBestIsTrusted,
		},
		se: se,
	})
}

// handleRxDiscoMsg handles reception of disco messages that [relayManager]
// may be interested in. This includes all Geneve-encapsulated disco messages
// and [*disco.AllocateUDPRelayEndpointResponse]. If dm is a
// [*disco.AllocateUDPRelayEndpointResponse] then relayServerNodeKey must be
// nonzero.
func (r *relayManager) handleRxDiscoMsg(conn *Conn, dm disco.Message, relayServerNodeKey key.NodePublic, discoKey key.DiscoPublic, src epAddr) {
	relayManagerInputEvent(r, nil, &r.rxDiscoMsgCh, relayDiscoMsgEvent{
		conn:               conn,
		msg:                dm,
		relayServerNodeKey: relayServerNodeKey,
		disco:              discoKey,
		from:               src.ap,
		vni:                src.vni.Get(),
		at:                 time.Now(),
	})
}

// handleRelayServersSet handles an update of the complete relay server set.
func (r *relayManager) handleRelayServersSet(servers set.Set[candidatePeerRelay]) {
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

// endpointWithLastBest represents an [*endpoint], its last bestAddr, and if
// the last bestAddr was trusted (see endpoint.trustBestAddrUntil) at the time
// of init. This structure is immutable once initialized.
type endpointWithLastBest struct {
	ep                *endpoint
	lastBest          addrQuality
	lastBestIsTrusted bool
}

// startUDPRelayPathDiscoveryFor starts UDP relay path discovery for ep on all
// known relay servers if ep has no in-progress work.
func (r *relayManager) startUDPRelayPathDiscoveryFor(ep *endpoint, lastBest addrQuality, lastBestIsTrusted bool) {
	relayManagerInputEvent(r, nil, &r.startDiscoveryCh, endpointWithLastBest{
		ep:                ep,
		lastBest:          lastBest,
		lastBestIsTrusted: lastBestIsTrusted,
	})
}

// stopWork stops all outstanding allocation & handshaking work for 'ep'.
func (r *relayManager) stopWork(ep *endpoint) {
	relayManagerInputEvent(r, nil, &r.cancelWorkCh, ep)
}

// stopWorkRunLoop cancels & clears outstanding allocation and handshaking
// work for 'ep'.
func (r *relayManager) stopWorkRunLoop(ep *endpoint) {
	byDiscoKeys, ok := r.allocWorkByCandidatePeerRelayByEndpoint[ep]
	if ok {
		for _, work := range byDiscoKeys {
			work.cancel()
			done := <-work.doneCh
			r.handleAllocWorkDoneRunLoop(done)
		}
	}
	byServerDisco, ok := r.handshakeWorkByServerDiscoByEndpoint[ep]
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

func (r *relayManager) handleRxDiscoMsgRunLoop(event relayDiscoMsgEvent) {
	var (
		work *relayHandshakeWork
		ok   bool
	)
	apv := addrPortVNI{event.from, event.vni}
	switch msg := event.msg.(type) {
	case *disco.AllocateUDPRelayEndpointResponse:
		sorted := key.NewSortedPairOfDiscoPublic(msg.ClientDisco[0], msg.ClientDisco[1])
		byDiscoKeys, ok := r.allocWorkByDiscoKeysByServerNodeKey[event.relayServerNodeKey]
		if !ok {
			// No outstanding work tied to this relay sever, discard.
			return
		}
		allocWork, ok := byDiscoKeys[sorted]
		if !ok {
			// No outstanding work tied to these disco keys, discard.
			return
		}
		select {
		case done := <-allocWork.doneCh:
			// allocateServerEndpoint returned, clean up its state
			r.handleAllocWorkDoneRunLoop(done)
			return
		case allocWork.rxDiscoMsgCh <- msg:
			return
		}
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
		// reception raced with our call to [endpoint.udpRelayEndpointReady()], so
		// err on the side of enabling the remote side to use this path.
		//
		// Conn.handlePingLocked() makes efforts to suppress duplicate pongs
		// where the same ping can be received both via raw socket and UDP
		// socket on Linux. We make no such efforts here as the raw socket BPF
		// program does not support Geneve-encapsulated disco, and is also
		// disabled by default.
		vni := packet.VirtualNetworkID{}
		vni.Set(event.vni)
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

func (r *relayManager) handleAllocWorkDoneRunLoop(done relayEndpointAllocWorkDoneEvent) {
	byCandidatePeerRelay, ok := r.allocWorkByCandidatePeerRelayByEndpoint[done.work.wlb.ep]
	if !ok {
		return
	}
	work, ok := byCandidatePeerRelay[done.work.candidatePeerRelay]
	if !ok || work != done.work {
		return
	}
	delete(byCandidatePeerRelay, done.work.candidatePeerRelay)
	if len(byCandidatePeerRelay) == 0 {
		delete(r.allocWorkByCandidatePeerRelayByEndpoint, done.work.wlb.ep)
	}
	byDiscoKeys, ok := r.allocWorkByDiscoKeysByServerNodeKey[done.work.candidatePeerRelay.nodeKey]
	if !ok {
		// unexpected
		return
	}
	delete(byDiscoKeys, done.work.discoKeys)
	if len(byDiscoKeys) == 0 {
		delete(r.allocWorkByDiscoKeysByServerNodeKey, done.work.candidatePeerRelay.nodeKey)
	}
	if !done.allocated.ServerDisco.IsZero() {
		r.handleNewServerEndpointRunLoop(newRelayServerEndpointEvent{
			wlb:    done.work.wlb,
			se:     done.allocated,
			server: done.work.candidatePeerRelay,
		})
	}
}

func (r *relayManager) handleHandshakeWorkDoneRunLoop(done relayEndpointHandshakeWorkDoneEvent) {
	byServerDisco, ok := r.handshakeWorkByServerDiscoByEndpoint[done.work.wlb.ep]
	if !ok {
		return
	}
	work, ok := byServerDisco[done.work.se.ServerDisco]
	if !ok || work != done.work {
		return
	}
	delete(byServerDisco, done.work.se.ServerDisco)
	if len(byServerDisco) == 0 {
		delete(r.handshakeWorkByServerDiscoByEndpoint, done.work.wlb.ep)
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
	vni := packet.VirtualNetworkID{}
	vni.Set(done.work.se.VNI)
	addr := epAddr{ap: done.pongReceivedFrom, vni: vni}
	// ep.udpRelayEndpointReady() must be called in a new goroutine to prevent
	// deadlocks as it acquires [endpoint] & [Conn] mutexes. See [relayManager]
	// docs for details.
	go done.work.wlb.ep.udpRelayEndpointReady(addrQuality{
		epAddr:           addr,
		relayServerDisco: done.work.se.ServerDisco,
		latency:          done.latency,
		wireMTU:          pingSizeToPktLen(0, addr),
	})
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
	byServerDisco, ok := r.handshakeWorkByServerDiscoByEndpoint[newServerEndpoint.wlb.ep]
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
	// (LamportID).

	if newServerEndpoint.server.isValid() {
		// Send a [disco.CallMeMaybeVia] to the remote peer if we allocated this
		// endpoint, regardless of if we start a handshake below.
		go r.sendCallMeMaybeVia(newServerEndpoint.wlb.ep, newServerEndpoint.se)
	}

	lastBestMatchingServer := newServerEndpoint.se.ServerDisco.Compare(newServerEndpoint.wlb.lastBest.relayServerDisco) == 0
	if lastBestMatchingServer && newServerEndpoint.wlb.lastBestIsTrusted {
		// This relay server endpoint is the same as [endpoint]'s bestAddr at
		// the time UDP relay path discovery was started, and it was also a
		// trusted path (see endpoint.trustBestAddrUntil), so return early.
		//
		// If we were to start a new handshake, there is a chance that we
		// cause [endpoint] to blackhole some packets on its bestAddr if we end
		// up shifting to a new address family or src, e.g. IPv4 to IPv6, due to
		// the window of time between the handshake completing, and our call to
		// udpRelayEndpointReady(). The relay server can only forward packets
		// from us on a single [epAddr].
		return
	}

	// TODO(jwhited): if lastBest is untrusted, consider some strategies
	//  to reduce the chance we blackhole if it were to transition to
	//  trusted during/before the new handshake:
	//    1. Start by attempting a handshake with only lastBest.epAddr. If
	//       that fails then try the remaining [epAddr]s.
	//    2. Signal bestAddr trust transitions between [endpoint] and
	//       [relayManager] in order to prevent a handshake from starting
	//       and/or stop one that is running.

	// We're ready to start a new handshake.
	ctx, cancel := context.WithCancel(context.Background())
	work := &relayHandshakeWork{
		wlb:          newServerEndpoint.wlb,
		se:           newServerEndpoint.se,
		server:       newServerEndpoint.server,
		rxDiscoMsgCh: make(chan relayDiscoMsgEvent),
		doneCh:       make(chan relayEndpointHandshakeWorkDoneEvent, 1),
		ctx:          ctx,
		cancel:       cancel,
	}
	// We must look up byServerDisco again. The previous value may have been
	// deleted from the outer map when cleaning up duplicate work.
	byServerDisco, ok = r.handshakeWorkByServerDiscoByEndpoint[newServerEndpoint.wlb.ep]
	if !ok {
		byServerDisco = make(map[key.DiscoPublic]*relayHandshakeWork)
		r.handshakeWorkByServerDiscoByEndpoint[newServerEndpoint.wlb.ep] = byServerDisco
	}
	byServerDisco[newServerEndpoint.se.ServerDisco] = work
	r.handshakeWorkByServerDiscoVNI[sdv] = work

	r.handshakeGeneration++
	if r.handshakeGeneration == 0 { // generation must be nonzero
		r.handshakeGeneration++
	}
	work.handshakeGen = r.handshakeGeneration

	go r.handshakeServerEndpoint(work)
}

// sendCallMeMaybeVia sends a [disco.CallMeMaybeVia] to ep over DERP. It must be
// called as part of a goroutine independent from runLoop(), for 2 reasons:
//  1. it acquires ep.mu (refer to [relayManager] docs for reasoning)
//  2. it makes a networking syscall, which can introduce unwanted backpressure
func (r *relayManager) sendCallMeMaybeVia(ep *endpoint, se udprelay.ServerEndpoint) {
	ep.mu.Lock()
	derpAddr := ep.derpAddr
	ep.mu.Unlock()
	epDisco := ep.disco.Load()
	if epDisco == nil || !derpAddr.IsValid() {
		return
	}
	callMeMaybeVia := &disco.CallMeMaybeVia{
		UDPRelayEndpoint: disco.UDPRelayEndpoint{
			ServerDisco:         se.ServerDisco,
			ClientDisco:         se.ClientDisco,
			LamportID:           se.LamportID,
			VNI:                 se.VNI,
			BindLifetime:        se.BindLifetime.Duration,
			SteadyStateLifetime: se.SteadyStateLifetime.Duration,
			AddrPorts:           se.AddrPorts,
		},
	}
	ep.c.sendDiscoMessage(epAddr{ap: derpAddr}, ep.publicKey, epDisco.key, callMeMaybeVia, discoVerboseLog)
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

	ep := work.wlb.ep
	epDisco := ep.disco.Load()
	if epDisco == nil {
		return
	}

	common := disco.BindUDPRelayEndpointCommon{
		VNI:        work.se.VNI,
		Generation: work.handshakeGen,
		RemoteKey:  epDisco.key,
	}

	work.dlogf("[v1] magicsock: relayManager: starting handshake addrPorts=%v",
		work.se.AddrPorts,
	)
	sentBindAny := false
	bind := &disco.BindUDPRelayEndpoint{
		BindUDPRelayEndpointCommon: common,
	}
	vni := packet.VirtualNetworkID{}
	vni.Set(work.se.VNI)
	for _, addrPort := range work.se.AddrPorts {
		if addrPort.IsValid() {
			sentBindAny = true
			go ep.c.sendDiscoMessage(epAddr{ap: addrPort, vni: vni}, key.NodePublic{}, work.se.ServerDisco, bind, discoVerboseLog)
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
		txid := stun.NewTxID()
		sentPingAt[txid] = time.Now()
		ping := &disco.Ping{
			TxID:    txid,
			NodeKey: ep.c.publicKeyAtomic.Load(),
		}
		go func() {
			if withAnswer != nil {
				answer := &disco.BindUDPRelayEndpointAnswer{BindUDPRelayEndpointCommon: common}
				answer.Challenge = *withAnswer
				ep.c.sendDiscoMessage(epAddr{ap: to, vni: vni}, key.NodePublic{}, work.se.ServerDisco, answer, discoVerboseLog)
			}
			ep.c.sendDiscoMessage(epAddr{ap: to, vni: vni}, key.NodePublic{}, epDisco.key, ping, discoVerboseLog)
		}()
	}

	validateVNIAndRemoteKey := func(common disco.BindUDPRelayEndpointCommon) error {
		if common.VNI != work.se.VNI {
			return errors.New("mismatching VNI")
		}
		if common.RemoteKey.Compare(epDisco.key) != 0 {
			return errors.New("mismatching RemoteKey")
		}
		return nil
	}

	// This for{select{}} is responsible for handshaking and tx'ing ping/pong
	// when the handshake is complete.
	for {
		select {
		case <-work.ctx.Done():
			work.dlogf("[v1] magicsock: relayManager: handshake canceled")
			return
		case msgEvent := <-work.rxDiscoMsgCh:
			switch msg := msgEvent.msg.(type) {
			case *disco.BindUDPRelayEndpointChallenge:
				err := validateVNIAndRemoteKey(msg.BindUDPRelayEndpointCommon)
				if err != nil {
					continue
				}
				if handshakeState >= disco.BindUDPRelayHandshakeStateAnswerSent {
					continue
				}
				work.dlogf("[v1] magicsock: relayManager: got handshake challenge from %v", msgEvent.from)
				txPing(msgEvent.from, &msg.Challenge)
				handshakeState = disco.BindUDPRelayHandshakeStateAnswerSent
			case *disco.Ping:
				if handshakeState < disco.BindUDPRelayHandshakeStateAnswerSent {
					continue
				}
				work.dlogf("[v1] magicsock: relayManager: got relayed ping from %v", msgEvent.from)
				// An inbound ping from the remote peer indicates we completed a
				// handshake with the relay server (our answer msg was
				// received). Chances are our ping was dropped before the remote
				// handshake was complete. We need to rx a pong to determine
				// latency, so send another ping. Since the handshake is
				// complete we do not need to send an answer in front of this
				// one.
				//
				// We don't need to TX a pong, that was already handled for us
				// in handleRxDiscoMsgRunLoop().
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
				work.dlogf("[v1] magicsock: relayManager: got relayed pong from %v latency=%v",
					msgEvent.from,
					done.latency.Round(time.Millisecond),
				)
				return
			default:
				// unexpected message type, silently discard
				continue
			}
		case <-timer.C:
			// The handshake timed out.
			work.dlogf("[v1] magicsock: relayManager: handshake timed out")
			return
		}
	}
}

const allocateUDPRelayEndpointRequestTimeout = time.Second * 10

func (r *relayManager) allocateServerEndpoint(work *relayEndpointAllocWork) {
	done := relayEndpointAllocWorkDoneEvent{work: work}

	defer func() {
		work.doneCh <- done
		relayManagerInputEvent(r, work.ctx, &r.allocateWorkDoneCh, done)
		work.cancel()
	}()

	dm := &disco.AllocateUDPRelayEndpointRequest{
		ClientDisco: work.discoKeys.Get(),
		Generation:  work.allocGen,
	}

	sendAllocReq := func() {
		work.wlb.ep.c.sendDiscoAllocateUDPRelayEndpointRequest(
			epAddr{
				ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, work.candidatePeerRelay.derpHomeRegionID),
			},
			work.candidatePeerRelay.nodeKey,
			work.candidatePeerRelay.discoKey,
			dm,
			discoVerboseLog,
		)
		work.dlogf("[v1] magicsock: relayManager: sent alloc request")
	}
	go sendAllocReq()

	returnAfterTimer := time.NewTimer(allocateUDPRelayEndpointRequestTimeout)
	defer returnAfterTimer.Stop()
	// While connections to DERP are over TCP, they can be lossy on the DERP
	// server when data moves between the two independent streams. Also, the
	// peer relay server may not be "ready" (see [tailscale.com/net/udprelay.ErrServerNotReady]).
	// So, start a timer to retry once if needed.
	retryAfterTimer := time.NewTimer(udprelay.ServerRetryAfter)
	defer retryAfterTimer.Stop()

	for {
		select {
		case <-work.ctx.Done():
			work.dlogf("[v1] magicsock: relayManager: alloc request canceled")
			return
		case <-returnAfterTimer.C:
			work.dlogf("[v1] magicsock: relayManager: alloc request timed out")
			return
		case <-retryAfterTimer.C:
			go sendAllocReq()
		case resp := <-work.rxDiscoMsgCh:
			if resp.Generation != work.allocGen ||
				!work.discoKeys.Equal(key.NewSortedPairOfDiscoPublic(resp.ClientDisco[0], resp.ClientDisco[1])) {
				continue
			}
			work.dlogf("[v1] magicsock: relayManager: got alloc response")
			done.allocated = udprelay.ServerEndpoint{
				ServerDisco:         resp.ServerDisco,
				ClientDisco:         resp.ClientDisco,
				LamportID:           resp.LamportID,
				AddrPorts:           resp.AddrPorts,
				VNI:                 resp.VNI,
				BindLifetime:        tstime.GoDuration{Duration: resp.BindLifetime},
				SteadyStateLifetime: tstime.GoDuration{Duration: resp.SteadyStateLifetime},
			}
			return
		}
	}
}

func (r *relayManager) allocateAllServersRunLoop(wlb endpointWithLastBest) {
	if len(r.serversByNodeKey) == 0 {
		return
	}
	remoteDisco := wlb.ep.disco.Load()
	if remoteDisco == nil {
		return
	}
	discoKeys := key.NewSortedPairOfDiscoPublic(wlb.ep.c.discoAtomic.Public(), remoteDisco.key)
	for _, v := range r.serversByNodeKey {
		byDiscoKeys, ok := r.allocWorkByDiscoKeysByServerNodeKey[v.nodeKey]
		if !ok {
			byDiscoKeys = make(map[key.SortedPairOfDiscoPublic]*relayEndpointAllocWork)
			r.allocWorkByDiscoKeysByServerNodeKey[v.nodeKey] = byDiscoKeys
		} else {
			_, ok = byDiscoKeys[discoKeys]
			if ok {
				// If there is an existing key, a disco key collision may have
				// occurred across peers ([*endpoint]). Do not overwrite the
				// existing work, let it finish.
				wlb.ep.c.logf("[unexpected] magicsock: relayManager: suspected disco key collision on server %v for keys: %v", v.nodeKey.ShortString(), discoKeys)
				continue
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		started := &relayEndpointAllocWork{
			wlb:                wlb,
			discoKeys:          discoKeys,
			candidatePeerRelay: v,
			rxDiscoMsgCh:       make(chan *disco.AllocateUDPRelayEndpointResponse),
			doneCh:             make(chan relayEndpointAllocWorkDoneEvent, 1),
			ctx:                ctx,
			cancel:             cancel,
		}
		byDiscoKeys[discoKeys] = started
		byCandidatePeerRelay, ok := r.allocWorkByCandidatePeerRelayByEndpoint[wlb.ep]
		if !ok {
			byCandidatePeerRelay = make(map[candidatePeerRelay]*relayEndpointAllocWork)
			r.allocWorkByCandidatePeerRelayByEndpoint[wlb.ep] = byCandidatePeerRelay
		}
		byCandidatePeerRelay[v] = started
		r.allocGeneration++
		started.allocGen = r.allocGeneration
		go r.allocateServerEndpoint(started)
	}
}
