// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bufio"
	"context"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"time"
	"unsafe"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/health"
	"tailscale.com/logtail/backoff"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/tsaddr"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
	"tailscale.com/util/rands"
	"tailscale.com/util/sysresources"
	"tailscale.com/util/testenv"
)

// frameReceiveRecordRate is the minimum time between updates to last frame
// received times.
// Note: this is relevant to other parts of the system, such as netcheck
// preferredDERPFrameTime, so update with care.
const frameReceiveRecordRate = 5 * time.Second

// derpRoute is a route entry for a public key, saying that a certain
// peer should be available at DERP regionID, as long as the
// current connection for that regionID is dc. (but dc should not be
// used to write directly; it's owned by the read/write loops)
type derpRoute struct {
	regionID int
	dc       *derphttp.Client // don't use directly; see comment above
}

// removeDerpPeerRoute removes a DERP route entry previously added by addDerpPeerRoute.
func (c *Conn) removeDerpPeerRoute(peer key.NodePublic, regionID int, dc *derphttp.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r2 := derpRoute{regionID, dc}
	if r, ok := c.derpRoute[peer]; ok && r == r2 {
		delete(c.derpRoute, peer)
	}
}

// addDerpPeerRoute adds a DERP route entry, noting that peer was seen
// on DERP node derpID, at least on the connection identified by dc.
// See issue 150 for details.
func (c *Conn) addDerpPeerRoute(peer key.NodePublic, derpID int, dc *derphttp.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	mak.Set(&c.derpRoute, peer, derpRoute{derpID, dc})
}

// activeDerp contains fields for an active DERP connection.
type activeDerp struct {
	c       *derphttp.Client
	cancel  context.CancelFunc
	writeCh chan<- derpWriteRequest
	// lastWrite is the time of the last request for its write
	// channel (currently even if there was no write).
	// It is always non-nil and initialized to a non-zero Time.
	lastWrite  *time.Time
	createTime time.Time
}

var (
	pickDERPFallbackForTests func() int
)

// pickDERPFallback returns a non-zero but deterministic DERP node to
// connect to.  This is only used if netcheck couldn't find the
// nearest one (for instance, if UDP is blocked and thus STUN latency
// checks aren't working).
//
// c.mu must NOT be held.
func (c *Conn) pickDERPFallback() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.wantDerpLocked() {
		return 0
	}
	ids := c.derpMap.RegionIDs()
	if len(ids) == 0 {
		// No DERP regions in non-nil map.
		return 0
	}

	// TODO: figure out which DERP region most of our peers are using,
	// and use that region as our fallback.
	//
	// If we already had selected something in the past and it has any
	// peers, we want to stay on it. If there are no peers at all,
	// stay on whatever DERP we previously picked. If we need to pick
	// one and have no peer info, pick a region randomly.
	//
	// We used to do the above for legacy clients, but never updated
	// it for disco.

	if c.myDerp != 0 {
		return c.myDerp
	}

	if pickDERPFallbackForTests != nil {
		return pickDERPFallbackForTests()
	}

	metricDERPHomeFallback.Add(1)
	return ids[rands.IntN(uint64(uintptr(unsafe.Pointer(c))), len(ids))]
}

// This allows existing tests to pass, but allows us to still test the
// behaviour during tests.
var checkControlHealthDuringNearestDERPInTests = false

// maybeSetNearestDERP selects and changes the nearest/preferred DERP server
// based on the netcheck report and other heuristics. It returns the DERP
// region that it selected and set (via setNearestDERP).
//
// c.mu must NOT be held.
func (c *Conn) maybeSetNearestDERP(report *netcheck.Report) (preferredDERP int) {
	// Don't change our PreferredDERP if we don't have a connection to
	// control; if we don't, then we can't inform peers about a DERP home
	// change, which breaks all connectivity. Even if this DERP region is
	// down, changing our home DERP isn't correct since peers can't
	// discover that change.
	//
	// See https://github.com/tailscale/corp/issues/18095
	//
	// For tests, always assume we're connected to control unless we're
	// explicitly testing this behaviour.
	//
	// Despite the above behaviour, ensure that we set the nearest DERP if
	// we don't currently have one set; any DERP server is better than
	// none, even if not connected to control.
	var connectedToControl bool
	if testenv.InTest() && !checkControlHealthDuringNearestDERPInTests {
		connectedToControl = true
	} else {
		connectedToControl = c.health.GetInPollNetMap()
	}
	if !connectedToControl {
		c.mu.Lock()
		myDerp := c.myDerp
		c.mu.Unlock()
		if myDerp != 0 {
			metricDERPHomeNoChangeNoControl.Add(1)
			return myDerp
		}

		// Intentionally fall through; we don't have a current DERP, so
		// as mentioned above selecting one even if not connected is
		// strictly better than doing nothing.
	}

	preferredDERP = report.PreferredDERP
	if preferredDERP == 0 {
		// Perhaps UDP is blocked. Pick a deterministic but arbitrary
		// one.
		preferredDERP = c.pickDERPFallback()
	}
	if !c.setNearestDERP(preferredDERP) {
		preferredDERP = 0
	}
	return
}

func (c *Conn) derpRegionCodeLocked(regionID int) string {
	if c.derpMap == nil {
		return ""
	}
	if dr, ok := c.derpMap.Regions[regionID]; ok {
		return dr.RegionCode
	}
	return ""
}

// c.mu must NOT be held.
func (c *Conn) setNearestDERP(derpNum int) (wantDERP bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.wantDerpLocked() {
		c.myDerp = 0
		c.health.SetMagicSockDERPHome(0, c.homeless)
		return false
	}
	if c.homeless {
		c.myDerp = 0
		c.health.SetMagicSockDERPHome(0, c.homeless)
		return false
	}
	if derpNum == c.myDerp {
		// No change.
		return true
	}
	if c.myDerp != 0 && derpNum != 0 {
		metricDERPHomeChange.Add(1)
	}
	c.myDerp = derpNum
	c.health.SetMagicSockDERPHome(derpNum, c.homeless)

	if c.privateKey.IsZero() {
		// No private key yet, so DERP connections won't come up anyway.
		// Return early rather than ultimately log a couple lines of noise.
		return true
	}

	// On change, notify all currently connected DERP servers and
	// start connecting to our home DERP if we are not already.
	dr := c.derpMap.Regions[derpNum]
	if dr == nil {
		c.logf("[unexpected] magicsock: derpMap.Regions[%v] is nil", derpNum)
	} else {
		c.logf("magicsock: home is now derp-%v (%v)", derpNum, c.derpMap.Regions[derpNum].RegionCode)
	}
	for i, ad := range c.activeDerp {
		go ad.c.NotePreferred(i == c.myDerp)
	}
	c.goDerpConnect(derpNum)
	return true
}

// startDerpHomeConnectLocked starts connecting to our DERP home, if any.
//
// c.mu must be held.
func (c *Conn) startDerpHomeConnectLocked() {
	c.goDerpConnect(c.myDerp)
}

// goDerpConnect starts a goroutine to start connecting to the given
// DERP region ID.
//
// c.mu may be held, but does not need to be.
func (c *Conn) goDerpConnect(regionID int) {
	if regionID == 0 {
		return
	}
	go c.derpWriteChanForRegion(regionID, key.NodePublic{})
}

var (
	bufferedDerpWrites     int
	bufferedDerpWritesOnce sync.Once
)

// bufferedDerpWritesBeforeDrop returns how many packets writes can be queued
// up the DERP client to write on the wire before we start dropping.
func bufferedDerpWritesBeforeDrop() int {
	// For mobile devices, always return the previous minimum value of 32;
	// we can do this outside the sync.Once to avoid that overhead.
	if runtime.GOOS == "ios" || runtime.GOOS == "android" {
		return 32
	}

	bufferedDerpWritesOnce.Do(func() {
		// Some rough sizing: for the previous fixed value of 32, the
		// total consumed memory can be:
		// = numDerpRegions * messages/region * sizeof(message)
		//
		// For sake of this calculation, assume 100 DERP regions; at
		// time of writing (2023-04-03), we have 24.
		//
		// A reasonable upper bound for the worst-case average size of
		// a message is a *disco.CallMeMaybe message with 16 endpoints;
		// since sizeof(netip.AddrPort) = 32, that's 512 bytes. Thus:
		// = 100 * 32 * 512
		// = 1638400 (1.6MiB)
		//
		// On a reasonably-small node with 4GiB of memory that's
		// connected to each region and handling a lot of load, 1.6MiB
		// is about 0.04% of the total system memory.
		//
		// For sake of this calculation, then, let's double that memory
		// usage to 0.08% and scale based on total system memory.
		//
		// For a 16GiB Linux box, this should buffer just over 256
		// messages.
		systemMemory := sysresources.TotalMemory()
		memoryUsable := float64(systemMemory) * 0.0008

		const (
			theoreticalDERPRegions  = 100
			messageMaximumSizeBytes = 512
		)
		bufferedDerpWrites = int(memoryUsable / (theoreticalDERPRegions * messageMaximumSizeBytes))

		// Never drop below the previous minimum value.
		if bufferedDerpWrites < 32 {
			bufferedDerpWrites = 32
		}
	})
	return bufferedDerpWrites
}

// derpWriteChanForRegion returns a channel to which to send DERP packet write
// requests. It creates a new DERP connection to regionID if necessary.
//
// If peer is non-zero, it can be used to find an active reverse path, without
// using regionID.
//
// It returns nil if the network is down, the Conn is closed, or the regionID is
// not known.
func (c *Conn) derpWriteChanForRegion(regionID int, peer key.NodePublic) chan<- derpWriteRequest {
	if c.networkDown() {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.wantDerpLocked() || c.closed {
		return nil
	}
	if c.derpMap == nil || c.derpMap.Regions[regionID] == nil {
		return nil
	}
	if c.privateKey.IsZero() {
		c.logf("magicsock: DERP lookup of region %v with no private key; ignoring", regionID)
		return nil
	}

	// See if we have a connection open to that DERP node ID
	// first. If so, might as well use it. (It's a little
	// arbitrary whether we use this one vs. the reverse route
	// below when we have both.)
	ad, ok := c.activeDerp[regionID]
	if ok {
		*ad.lastWrite = time.Now()
		c.setPeerLastDerpLocked(peer, regionID, regionID)
		return ad.writeCh
	}

	// If we don't have an open connection to the peer's home DERP
	// node, see if we have an open connection to a DERP node
	// where we'd heard from that peer already. For instance,
	// perhaps peer's home is Frankfurt, but they dialed our home DERP
	// node in SF to reach us, so we can reply to them using our
	// SF connection rather than dialing Frankfurt. (Issue 150)
	if !peer.IsZero() {
		if r, ok := c.derpRoute[peer]; ok {
			if ad, ok := c.activeDerp[r.regionID]; ok && ad.c == r.dc {
				c.setPeerLastDerpLocked(peer, r.regionID, regionID)
				*ad.lastWrite = time.Now()
				return ad.writeCh
			}
		}
	}

	why := "home-keep-alive"
	if !peer.IsZero() {
		why = peer.ShortString()
	}
	c.logf("magicsock: adding connection to derp-%v for %v", regionID, why)

	firstDerp := false
	if c.activeDerp == nil {
		firstDerp = true
		c.activeDerp = make(map[int]activeDerp)
		c.prevDerp = make(map[int]*syncs.WaitGroupChan)
	}

	// Note that derphttp.NewRegionClient does not dial the server
	// (it doesn't block) so it is safe to do under the c.mu lock.
	dc := derphttp.NewRegionClient(c.privateKey, c.logf, c.netMon, func() *tailcfg.DERPRegion {
		// Warning: it is not legal to acquire
		// magicsock.Conn.mu from this callback.
		// It's run from derphttp.Client.connect (via Send, etc)
		// and the lock ordering rules are that magicsock.Conn.mu
		// must be acquired before derphttp.Client.mu.
		// See https://github.com/tailscale/tailscale/issues/3726
		if c.connCtx.Err() != nil {
			// We're closing anyway; return nil to stop dialing.
			return nil
		}
		derpMap := c.derpMapAtomic.Load()
		if derpMap == nil {
			return nil
		}
		return derpMap.Regions[regionID]
	})
	dc.HealthTracker = c.health

	dc.SetCanAckPings(true)
	dc.NotePreferred(c.myDerp == regionID)
	dc.SetAddressFamilySelector(derpAddrFamSelector{c})
	dc.DNSCache = dnscache.Get()

	ctx, cancel := context.WithCancel(c.connCtx)
	ch := make(chan derpWriteRequest, bufferedDerpWritesBeforeDrop())

	ad.c = dc
	ad.writeCh = ch
	ad.cancel = cancel
	ad.lastWrite = new(time.Time)
	*ad.lastWrite = time.Now()
	ad.createTime = time.Now()
	c.activeDerp[regionID] = ad
	metricNumDERPConns.Set(int64(len(c.activeDerp)))
	c.logActiveDerpLocked()
	c.setPeerLastDerpLocked(peer, regionID, regionID)
	c.scheduleCleanStaleDerpLocked()

	// Build a startGate for the derp reader+writer
	// goroutines, so they don't start running until any
	// previous generation is closed.
	startGate := syncs.ClosedChan()
	if prev := c.prevDerp[regionID]; prev != nil {
		startGate = prev.DoneChan()
	}
	// And register a WaitGroup(Chan) for this generation.
	wg := syncs.NewWaitGroupChan()
	wg.Add(2)
	c.prevDerp[regionID] = wg

	if firstDerp {
		startGate = c.derpStarted
		go func() {
			dc.Connect(ctx)
			close(c.derpStarted)
			c.muCond.Broadcast()
		}()
	}

	go c.runDerpReader(ctx, regionID, dc, wg, startGate)
	go c.runDerpWriter(ctx, dc, ch, wg, startGate)
	go c.derpActiveFunc()

	return ad.writeCh
}

// setPeerLastDerpLocked notes that peer is now being written to via
// the provided DERP regionID, and that the peer advertises a DERP
// home region ID of homeID.
//
// If there's any change, it logs.
//
// c.mu must be held.
func (c *Conn) setPeerLastDerpLocked(peer key.NodePublic, regionID, homeID int) {
	if peer.IsZero() {
		return
	}
	old := c.peerLastDerp[peer]
	if old == regionID {
		return
	}
	c.peerLastDerp[peer] = regionID

	var newDesc string
	switch {
	case regionID == homeID && regionID == c.myDerp:
		newDesc = "shared home"
	case regionID == homeID:
		newDesc = "their home"
	case regionID == c.myDerp:
		newDesc = "our home"
	case regionID != homeID:
		newDesc = "alt"
	}
	if old == 0 {
		c.logf("[v1] magicsock: derp route for %s set to derp-%d (%s)", peer.ShortString(), regionID, newDesc)
	} else {
		c.logf("[v1] magicsock: derp route for %s changed from derp-%d => derp-%d (%s)", peer.ShortString(), old, regionID, newDesc)
	}
}

// derpReadResult is the type sent by Conn.runDerpReader to connBind.receiveDERP
// when a derp.ReceivedPacket is available.
//
// Notably, it doesn't include the derp.ReceivedPacket because we
// don't want to give the receiver access to the aliased []byte.  To
// get at the packet contents they need to call copyBuf to copy it
// out, which also releases the buffer.
type derpReadResult struct {
	regionID int
	n        int // length of data received
	src      key.NodePublic
	// copyBuf is called to copy the data to dst.  It returns how
	// much data was copied, which will be n if dst is large
	// enough. copyBuf can only be called once.
	// If copyBuf is nil, that's a signal from the sender to ignore
	// this message.
	copyBuf func(dst []byte) int
}

// runDerpReader runs in a goroutine for the life of a DERP
// connection, handling received packets.
func (c *Conn) runDerpReader(ctx context.Context, regionID int, dc *derphttp.Client, wg *syncs.WaitGroupChan, startGate <-chan struct{}) {
	defer wg.Decr()
	defer dc.Close()

	select {
	case <-startGate:
	case <-ctx.Done():
		return
	}

	didCopy := make(chan struct{}, 1)
	res := derpReadResult{regionID: regionID}
	var pkt derp.ReceivedPacket
	res.copyBuf = func(dst []byte) int {
		n := copy(dst, pkt.Data)
		didCopy <- struct{}{}
		return n
	}

	defer c.health.SetDERPRegionConnectedState(regionID, false)
	defer c.health.SetDERPRegionHealth(regionID, "")

	// peerPresent is the set of senders we know are present on this
	// connection, based on messages we've received from the server.
	peerPresent := map[key.NodePublic]bool{}
	bo := backoff.NewBackoff(fmt.Sprintf("derp-%d", regionID), c.logf, 5*time.Second)
	var lastPacketTime time.Time
	var lastPacketSrc key.NodePublic

	for {
		msg, connGen, err := dc.RecvDetail()
		if err != nil {
			c.health.SetDERPRegionConnectedState(regionID, false)
			// Forget that all these peers have routes.
			for peer := range peerPresent {
				delete(peerPresent, peer)
				c.removeDerpPeerRoute(peer, regionID, dc)
			}
			if err == derphttp.ErrClientClosed {
				return
			}
			if c.networkDown() {
				c.logf("[v1] magicsock: derp.Recv(derp-%d): network down, closing", regionID)
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}

			c.logf("magicsock: [%p] derp.Recv(derp-%d): %v", dc, regionID, err)

			// If our DERP connection broke, it might be because our network
			// conditions changed. Start that check.
			c.ReSTUN("derp-recv-error")

			// Back off a bit before reconnecting.
			bo.BackOff(ctx, err)
			select {
			case <-ctx.Done():
				return
			default:
			}
			continue
		}
		bo.BackOff(ctx, nil) // reset

		now := time.Now()
		if lastPacketTime.IsZero() || now.Sub(lastPacketTime) > frameReceiveRecordRate {
			c.health.NoteDERPRegionReceivedFrame(regionID)
			lastPacketTime = now
		}

		switch m := msg.(type) {
		case derp.ServerInfoMessage:
			c.health.SetDERPRegionConnectedState(regionID, true)
			c.health.SetDERPRegionHealth(regionID, "") // until declared otherwise
			c.logf("magicsock: derp-%d connected; connGen=%v", regionID, connGen)
			continue
		case derp.ReceivedPacket:
			pkt = m
			res.n = len(m.Data)
			res.src = m.Source
			if logDerpVerbose() {
				c.logf("magicsock: got derp-%v packet: %q", regionID, m.Data)
			}
			// If this is a new sender we hadn't seen before, remember it and
			// register a route for this peer.
			if res.src != lastPacketSrc { // avoid map lookup w/ high throughput single peer
				lastPacketSrc = res.src
				if _, ok := peerPresent[res.src]; !ok {
					peerPresent[res.src] = true
					c.addDerpPeerRoute(res.src, regionID, dc)
				}
			}
			select {
			case <-ctx.Done():
				return
			case c.derpRecvCh <- res:
			}
			select {
			case <-ctx.Done():
				return
			case <-didCopy:
				continue
			}
		case derp.PingMessage:
			// Best effort reply to the ping.
			pingData := [8]byte(m)
			go func() {
				if err := dc.SendPong(pingData); err != nil {
					c.logf("magicsock: derp-%d SendPong error: %v", regionID, err)
				}
			}()
			continue
		case derp.HealthMessage:
			c.health.SetDERPRegionHealth(regionID, m.Problem)
			continue
		case derp.PeerGoneMessage:
			switch m.Reason {
			case derp.PeerGoneReasonDisconnected:
				// Do nothing.
			case derp.PeerGoneReasonNotHere:
				metricRecvDiscoDERPPeerNotHere.Add(1)
				c.logf("[unexpected] magicsock: derp-%d does not know about peer %s, removing route",
					regionID, key.NodePublic(m.Peer).ShortString())
			default:
				metricRecvDiscoDERPPeerGoneUnknown.Add(1)
				c.logf("[unexpected] magicsock: derp-%d peer %s gone, reason %v, removing route",
					regionID, key.NodePublic(m.Peer).ShortString(), m.Reason)
			}
			c.removeDerpPeerRoute(key.NodePublic(m.Peer), regionID, dc)
			continue
		default:
			// Ignore.
			continue
		}
	}
}

type derpWriteRequest struct {
	addr   netip.AddrPort
	pubKey key.NodePublic
	b      []byte // copied; ownership passed to receiver
}

// runDerpWriter runs in a goroutine for the life of a DERP
// connection, handling received packets.
func (c *Conn) runDerpWriter(ctx context.Context, dc *derphttp.Client, ch <-chan derpWriteRequest, wg *syncs.WaitGroupChan, startGate <-chan struct{}) {
	defer wg.Decr()
	select {
	case <-startGate:
	case <-ctx.Done():
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case wr := <-ch:
			err := dc.Send(wr.pubKey, wr.b)
			if err != nil {
				c.logf("magicsock: derp.Send(%v): %v", wr.addr, err)
				metricSendDERPError.Add(1)
			} else {
				metricSendDERP.Add(1)
			}
		}
	}
}

func (c *connBind) receiveDERP(buffs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if s := c.Conn.health.ReceiveFuncStats(health.ReceiveDERP); s != nil {
		s.Enter()
		defer s.Exit()
	}

	for dm := range c.derpRecvCh {
		if c.isClosed() {
			break
		}
		n, ep := c.processDERPReadResult(dm, buffs[0])
		if n == 0 {
			// No data read occurred. Wait for another packet.
			continue
		}
		metricRecvDataDERP.Add(1)
		sizes[0] = n
		eps[0] = ep
		return 1, nil
	}
	return 0, net.ErrClosed
}

func (c *Conn) processDERPReadResult(dm derpReadResult, b []byte) (n int, ep *endpoint) {
	if dm.copyBuf == nil {
		return 0, nil
	}
	var regionID int
	n, regionID = dm.n, dm.regionID
	ncopy := dm.copyBuf(b)
	if ncopy != n {
		err := fmt.Errorf("received DERP packet of length %d that's too big for WireGuard buf size %d", n, ncopy)
		c.logf("magicsock: %v", err)
		return 0, nil
	}

	ipp := netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, uint16(regionID))
	if c.handleDiscoMessage(b[:n], ipp, dm.src, discoRXPathDERP) {
		return 0, nil
	}

	var ok bool
	c.mu.Lock()
	ep, ok = c.peerMap.endpointForNodeKey(dm.src)
	c.mu.Unlock()
	if !ok {
		// We don't know anything about this node key, nothing to
		// record or process.
		return 0, nil
	}

	ep.noteRecvActivity(ipp, mono.Now())
	if stats := c.stats.Load(); stats != nil {
		stats.UpdateRxPhysical(ep.nodeAddr, ipp, dm.n)
	}
	return n, ep
}

// SetOnlyTCP443 set whether the magicsock connection is restricted
// to only using TCP port 443 outbound. If true, no UDP is allowed,
// no STUN checks are performend, etc.
func (c *Conn) SetOnlyTCP443(v bool) {
	c.onlyTCP443.Store(v)
}

// SetDERPMap controls which (if any) DERP servers are used.
// A nil value means to disable DERP; it's disabled by default.
func (c *Conn) SetDERPMap(dm *tailcfg.DERPMap) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var derpAddr = debugUseDERPAddr()
	if derpAddr != "" {
		derpPort := 443
		if debugUseDERPHTTP() {
			// Match the port for -dev in derper.go
			derpPort = 3340
		}
		dm = &tailcfg.DERPMap{
			OmitDefaultRegions: true,
			Regions: map[int]*tailcfg.DERPRegion{
				999: {
					RegionID: 999,
					Nodes: []*tailcfg.DERPNode{{
						Name:     "999dev",
						RegionID: 999,
						HostName: derpAddr,
						DERPPort: derpPort,
					}},
				},
			},
		}
	}

	if reflect.DeepEqual(dm, c.derpMap) {
		return
	}

	c.derpMapAtomic.Store(dm)
	old := c.derpMap
	c.derpMap = dm
	if dm == nil {
		c.closeAllDerpLocked("derp-disabled")
		return
	}

	// Reconnect any DERP region that changed definitions.
	if old != nil {
		changes := false
		for rid, oldDef := range old.Regions {
			if reflect.DeepEqual(oldDef, dm.Regions[rid]) {
				continue
			}
			changes = true
			if rid == c.myDerp {
				c.myDerp = 0
			}
			c.closeDerpLocked(rid, "derp-region-redefined")
		}
		if changes {
			c.logActiveDerpLocked()
		}
	}

	go c.ReSTUN("derp-map-update")
}
func (c *Conn) wantDerpLocked() bool { return c.derpMap != nil }

// c.mu must be held.
func (c *Conn) closeAllDerpLocked(why string) {
	if len(c.activeDerp) == 0 {
		return // without the useless log statement
	}
	for i := range c.activeDerp {
		c.closeDerpLocked(i, why)
	}
	c.logActiveDerpLocked()
}

// DebugBreakDERPConns breaks all DERP connections for debug/testing reasons.
func (c *Conn) DebugBreakDERPConns() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.activeDerp) == 0 {
		c.logf("magicsock: DebugBreakDERPConns: no active DERP connections")
		return nil
	}
	c.closeAllDerpLocked("debug-break-derp")
	c.startDerpHomeConnectLocked()
	return nil
}

// maybeCloseDERPsOnRebind, in response to a rebind, closes all
// DERP connections that don't have a local address in okayLocalIPs
// and pings all those that do.
func (c *Conn) maybeCloseDERPsOnRebind(okayLocalIPs []netip.Prefix) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for regionID, ad := range c.activeDerp {
		la, err := ad.c.LocalAddr()
		if err != nil {
			c.closeOrReconnectDERPLocked(regionID, "rebind-no-localaddr")
			continue
		}
		if !tsaddr.PrefixesContainsIP(okayLocalIPs, la.Addr()) {
			c.closeOrReconnectDERPLocked(regionID, "rebind-default-route-change")
			continue
		}
		regionID := regionID
		dc := ad.c
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := dc.Ping(ctx); err != nil {
				c.mu.Lock()
				defer c.mu.Unlock()
				c.closeOrReconnectDERPLocked(regionID, "rebind-ping-fail")
				return
			}
			c.logf("post-rebind ping of DERP region %d okay", regionID)
		}()
	}
	c.logActiveDerpLocked()
}

// closeOrReconnectDERPLocked closes the DERP connection to the
// provided regionID and starts reconnecting it if it's our current
// home DERP.
//
// why is a reason for logging.
//
// c.mu must be held.
func (c *Conn) closeOrReconnectDERPLocked(regionID int, why string) {
	c.closeDerpLocked(regionID, why)
	if !c.privateKey.IsZero() && c.myDerp == regionID {
		c.startDerpHomeConnectLocked()
	}
}

// c.mu must be held.
// It is the responsibility of the caller to call logActiveDerpLocked after any set of closes.
func (c *Conn) closeDerpLocked(regionID int, why string) {
	if ad, ok := c.activeDerp[regionID]; ok {
		c.logf("magicsock: closing connection to derp-%v (%v), age %v", regionID, why, time.Since(ad.createTime).Round(time.Second))
		go ad.c.Close()
		ad.cancel()
		delete(c.activeDerp, regionID)
		metricNumDERPConns.Set(int64(len(c.activeDerp)))
	}
}

// c.mu must be held.
func (c *Conn) logActiveDerpLocked() {
	now := time.Now()
	c.logf("magicsock: %v active derp conns%s", len(c.activeDerp), logger.ArgWriter(func(buf *bufio.Writer) {
		if len(c.activeDerp) == 0 {
			return
		}
		buf.WriteString(":")
		c.foreachActiveDerpSortedLocked(func(node int, ad activeDerp) {
			fmt.Fprintf(buf, " derp-%d=cr%v,wr%v", node, simpleDur(now.Sub(ad.createTime)), simpleDur(now.Sub(*ad.lastWrite)))
		})
	}))
}

// c.mu must be held.
func (c *Conn) foreachActiveDerpSortedLocked(fn func(regionID int, ad activeDerp)) {
	if len(c.activeDerp) < 2 {
		for id, ad := range c.activeDerp {
			fn(id, ad)
		}
		return
	}
	for _, id := range slices.Sorted(maps.Keys(c.activeDerp)) {
		fn(id, c.activeDerp[id])
	}
}

func (c *Conn) cleanStaleDerp() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.derpCleanupTimerArmed = false

	tooOld := time.Now().Add(-derpInactiveCleanupTime)
	dirty := false
	someNonHomeOpen := false
	for i, ad := range c.activeDerp {
		if i == c.myDerp {
			continue
		}
		if ad.lastWrite.Before(tooOld) {
			c.closeDerpLocked(i, "idle")
			metricDERPStaleCleaned.Add(1)
			dirty = true
		} else {
			someNonHomeOpen = true
		}
	}
	if dirty {
		c.logActiveDerpLocked()
	}
	if someNonHomeOpen {
		c.scheduleCleanStaleDerpLocked()
	}
}

func (c *Conn) scheduleCleanStaleDerpLocked() {
	if c.derpCleanupTimerArmed {
		// Already going to fire soon. Let the existing one
		// fire lest it get infinitely delayed by repeated
		// calls to scheduleCleanStaleDerpLocked.
		return
	}
	c.derpCleanupTimerArmed = true
	if c.derpCleanupTimer != nil {
		c.derpCleanupTimer.Reset(derpCleanStaleInterval)
	} else {
		c.derpCleanupTimer = time.AfterFunc(derpCleanStaleInterval, c.cleanStaleDerp)
	}
}

// DERPs reports the number of active DERP connections.
func (c *Conn) DERPs() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.activeDerp)
}

func (c *Conn) derpRegionCodeOfIDLocked(regionID int) string {
	if c.derpMap == nil {
		return ""
	}
	if r, ok := c.derpMap.Regions[regionID]; ok {
		return r.RegionCode
	}
	return ""
}

// derpAddrFamSelector is the derphttp.AddressFamilySelector we pass
// to derphttp.Client.SetAddressFamilySelector.
//
// It provides the hint as to whether in an IPv4-vs-IPv6 race that
// IPv4 should be held back a bit to give IPv6 a better-than-50/50
// chance of winning. We only return true when we believe IPv6 will
// work anyway, so we don't artificially delay the connection speed.
type derpAddrFamSelector struct{ c *Conn }

func (s derpAddrFamSelector) PreferIPv6() bool {
	if r := s.c.lastNetCheckReport.Load(); r != nil {
		return r.IPv6
	}
	return false
}

const (
	// derpInactiveCleanupTime is how long a non-home DERP connection
	// needs to be idle (last written to) before we close it.
	derpInactiveCleanupTime = 60 * time.Second

	// derpCleanStaleInterval is how often cleanStaleDerp runs when there
	// are potentially-stale DERP connections to close.
	derpCleanStaleInterval = 15 * time.Second
)
