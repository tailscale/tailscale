// Copyright 2019 Tailscale & AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package magicsock implements a socket that can change its communication path while
// in use, actively searching for the best way to communicate.
package magicsock

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/wgcfg"
	"golang.org/x/time/rate"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpmap"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/interfaces"
	"tailscale.com/netcheck"
	"tailscale.com/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/version"
)

// A Conn routes UDP packets and actively manages a list of its endpoints.
// It implements wireguard/device.Bind.
type Conn struct {
	pconn         *RebindingUDPConn
	pconnPort     uint16
	startEpUpdate chan struct{} // send to trigger endpoint update
	epFunc        func(endpoints []string)
	logf          logger.Logf
	sendLogLimit  *rate.Limiter
	derps         *derpmap.World
	netChecker    *netcheck.Client
	goroutines    sync.WaitGroup

	// bufferedIPv4From and bufferedIPv4Packet are owned by
	// ReceiveIPv4, and used when both a DERP and IPv4 packet arrive
	// at the same time. It stores the IPv4 packet for use in the next call.
	bufferedIPv4From   *net.UDPAddr // if non-nil, then bufferedIPv4Packet is valid
	bufferedIPv4Packet []byte       // the received packet (reused, owned by ReceiveIPv4)

	connCtx       context.Context // closed on Conn.Close
	connCtxCancel func()          // closes connCtx

	linkChangeMu sync.Mutex
	linkState    *interfaces.State

	// addrsByUDP is a map of every remote ip:port to a priority
	// list of endpoint addresses for a peer.
	// The priority list is provided by wgengine configuration.
	//
	// Given a wgcfg describing:
	//	machineA: 10.0.0.1:1, 10.0.0.2:2
	//	machineB: 10.0.0.3:3
	// the addrsByUDP map contains:
	//	10.0.0.1:1 -> [10.0.0.1:1, 10.0.0.2:2]
	//	10.0.0.2:2 -> [10.0.0.1:1, 10.0.0.2:2]
	//	10.0.0.3:3 -> [10.0.0.3:3]
	addrsMu    sync.Mutex
	addrsByUDP map[udpAddr]*AddrSet    // TODO: clean up this map sometime?
	addrsByKey map[key.Public]*AddrSet // TODO: clean up this map sometime?

	// stunReceiveFunc holds the current STUN packet processing func.
	// Its Loaded value is always non-nil.
	stunReceiveFunc atomic.Value // of func(p []byte, fromAddr *net.UDPAddr)

	netInfoMu   sync.Mutex
	netInfoFunc func(*tailcfg.NetInfo) // nil until set
	netInfoLast *tailcfg.NetInfo

	udpRecvCh  chan udpReadResult
	derpRecvCh chan derpReadResult

	derpMu        sync.Mutex
	wantDerp      bool
	privateKey    key.Private
	myDerp        int // nearest DERP server; 0 means none/unknown
	activeDerp    map[int]activeDerp
	derpTLSConfig *tls.Config // normally nil; used by tests
}

// DerpMagicIP is a fake WireGuard endpoint IP address that means
// to use DERP. When used, the port number of the WireGuard endpoint
// is the DERP server number to use.
//
// Mnemonic: 3.3.40 are numbers above the keys D, E, R, P.
const DerpMagicIP = "127.3.3.40"

var derpMagicIP = net.ParseIP(DerpMagicIP).To4()

// activeDerp contains fields for an active DERP connection.
type activeDerp struct {
	c         *derphttp.Client
	cancel    context.CancelFunc
	writeCh   chan<- derpWriteRequest
	lastWrite *time.Time
}

// udpAddr is the key in the addrsByUDP map.
// It maps an ip:port onto an *AddrSet.
type udpAddr struct {
	ip   wgcfg.IP
	port uint16
}

// DefaultPort is the default port to listen on.
// The current default (zero) means to auto-select a random free port.
const DefaultPort = 0

var DisableSTUNForTesting bool

// Options contains options for Listen.
type Options struct {
	Logf logger.Logf

	// Port is the port to listen on.
	// Zero means to pick one automatically.
	Port uint16

	// DERPs, if non-nil, is used instead of derpmap.Prod.
	DERPs *derpmap.World

	// EndpointsFunc optionally provides a func to be called when
	// endpoints change. The called func does not own the slice.
	EndpointsFunc func(endpoint []string)

	derpTLSConfig *tls.Config // normally nil; used by tests
}

func (o *Options) endpointsFunc() func([]string) {
	if o == nil || o.EndpointsFunc == nil {
		return func([]string) {}
	}
	return o.EndpointsFunc
}

// Listen creates a magic Conn listening on opts.Port.
// As the set of possible endpoints for a Conn changes, the
// callback opts.EndpointsFunc is called.
func Listen(opts Options) (*Conn, error) {
	var packetConn net.PacketConn
	var err error

	logf := log.Printf
	if opts.Logf != nil {
		logf = opts.Logf
	}

	if opts.Port == 0 {
		// Our choice of port. Start with DefaultPort.
		// If unavailable, pick any port.
		want := fmt.Sprintf(":%d", DefaultPort)
		logf("magicsock: bind: trying %v\n", want)
		packetConn, err = net.ListenPacket("udp4", want)
		if err != nil {
			want = ":0"
			logf("magicsock: bind: falling back to %v (%v)\n", want, err)
			packetConn, err = net.ListenPacket("udp4", want)
		}
	} else {
		packetConn, err = net.ListenPacket("udp4", fmt.Sprintf(":%d", opts.Port))
	}
	if err != nil {
		return nil, fmt.Errorf("magicsock.Listen: %v", err)
	}

	connCtx, connCtxCancel := context.WithCancel(context.Background())
	c := &Conn{
		pconn:         new(RebindingUDPConn),
		pconnPort:     opts.Port,
		sendLogLimit:  rate.NewLimiter(rate.Every(1*time.Minute), 1),
		startEpUpdate: make(chan struct{}, 1),
		connCtx:       connCtx,
		connCtxCancel: connCtxCancel,
		epFunc:        opts.endpointsFunc(),
		logf:          logf,
		addrsByUDP:    make(map[udpAddr]*AddrSet),
		addrsByKey:    make(map[key.Public]*AddrSet),
		wantDerp:      true,
		derpRecvCh:    make(chan derpReadResult),
		udpRecvCh:     make(chan udpReadResult),
		derpTLSConfig: opts.derpTLSConfig,
		derps:         opts.DERPs,
	}
	c.linkState, _ = getLinkState()
	if c.derps == nil {
		c.derps = derpmap.Prod()
	}
	c.netChecker = &netcheck.Client{
		DERP:         c.derps,
		Logf:         logger.WithPrefix(c.logf, "netcheck: "),
		GetSTUNConn4: func() netcheck.STUNConn { return c.pconn },
		// TODO: add GetSTUNConn6 once Conn has a pconn6
	}

	c.ignoreSTUNPackets()
	c.pconn.Reset(packetConn.(*net.UDPConn))
	c.reSTUN()

	c.goroutines.Add(1)
	go func() {
		defer c.goroutines.Done()
		c.epUpdate(connCtx)
	}()
	return c, nil
}

func (c *Conn) donec() <-chan struct{} { return c.connCtx.Done() }

// ignoreSTUNPackets sets a STUN packet processing func that does nothing.
func (c *Conn) ignoreSTUNPackets() {
	c.stunReceiveFunc.Store(func([]byte, *net.UDPAddr) {})
}

// epUpdate runs in its own goroutine until ctx is shut down.
// Whenever c.startEpUpdate receives a value, it starts an
// STUN endpoint lookup.
func (c *Conn) epUpdate(ctx context.Context) {
	var lastEndpoints []string
	var lastCancel func()
	var lastDone chan struct{}

	var regularUpdate <-chan time.Time
	if !version.IsMobile() {
		// We assume that LinkChange notifications are plumbed through well
		// on our mobile clients, so don't do the timer thing to save radio/battery/CPU/etc.
		ticker := time.NewTicker(28 * time.Second) // just under 30s, a likely UDP NAT timeout
		defer ticker.Stop()
		regularUpdate = ticker.C
	}

	for {
		select {
		case <-ctx.Done():
			if lastCancel != nil {
				lastCancel()
				<-lastDone
			}
			return
		case <-c.startEpUpdate:
		case <-regularUpdate:
		}

		if lastCancel != nil {
			lastCancel()
			<-lastDone
		}
		var epCtx context.Context
		epCtx, lastCancel = context.WithCancel(ctx)
		lastDone = make(chan struct{})

		go func() {
			defer close(lastDone)

			c.cleanStaleDerp()

			netReport, err := c.updateNetInfo(epCtx)
			if err != nil {
				c.logf("magicsock.Conn: updateNetInfo failed: %v", err)
				return
			}
			endpoints, err := c.determineEndpoints(epCtx, netReport)
			if err != nil {
				c.logf("magicsock.Conn: endpoint update failed: %v", err)
				// TODO(crawshaw): are there any conditions under which
				// we should trigger a retry based on the error here?
				return
			}
			if stringsEqual(endpoints, lastEndpoints) {
				return
			}
			lastEndpoints = endpoints
			c.epFunc(endpoints)
		}()
	}
}

func (c *Conn) updateNetInfo(ctx context.Context) (*netcheck.Report, error) {
	if DisableSTUNForTesting {
		return new(netcheck.Report), nil
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	c.stunReceiveFunc.Store(c.netChecker.ReceiveSTUNPacket)
	defer c.ignoreSTUNPackets()

	report, err := c.netChecker.GetReport(ctx)
	if err != nil {
		return nil, err
	}

	ni := &tailcfg.NetInfo{
		DERPLatency:           map[string]float64{},
		MappingVariesByDestIP: report.MappingVariesByDestIP,
		HairPinning:           report.HairPinning,
	}
	for server, d := range report.DERPLatency {
		ni.DERPLatency[server] = d.Seconds()
	}
	ni.WorkingIPv6.Set(report.IPv6)
	ni.WorkingUDP.Set(report.UDP)
	ni.PreferredDERP = report.PreferredDERP

	if ni.PreferredDERP == 0 {
		// Perhaps UDP is blocked. Pick a deterministic but arbitrary
		// one.
		ni.PreferredDERP = c.pickDERPFallback()
	}
	if !c.setNearestDERP(ni.PreferredDERP) {
		ni.PreferredDERP = 0
	}

	// TODO: set link type

	c.callNetInfoCallback(ni)
	return report, nil
}

var processStartUnixNano = time.Now().UnixNano()

// pickDERPFallback returns a non-zero but deterministic DERP node to
// connect to.  This is only used if netcheck couldn't find the
// nearest one (for instance, if UDP is blocked and thus STUN latency
// checks aren't working).
func (c *Conn) pickDERPFallback() int {
	c.derpMu.Lock()
	defer c.derpMu.Unlock()

	if c.myDerp != 0 {
		// If we already had one in the past, stay on it.
		return c.myDerp
	}

	ids := c.derps.IDs()
	if len(ids) == 0 {
		// No DERP nodes registered.
		return 0
	}

	h := fnv.New64()
	h.Write([]byte(fmt.Sprintf("%p/%d", c, processStartUnixNano))) // arbitrary
	return ids[rand.New(rand.NewSource(int64(h.Sum64()))).Intn(len(ids))]
}

// callNetInfoCallback calls the NetInfo callback (if previously
// registered with SetNetInfoCallback) if ni has substantially changed
// since the last state.
//
// callNetInfoCallback takes ownership of ni.
func (c *Conn) callNetInfoCallback(ni *tailcfg.NetInfo) {
	c.netInfoMu.Lock()
	defer c.netInfoMu.Unlock()
	if ni.BasicallyEqual(c.netInfoLast) {
		return
	}
	c.netInfoLast = ni
	if c.netInfoFunc != nil {
		c.logf("netInfo update: %+v", ni)
		go c.netInfoFunc(ni)
	}
}

func (c *Conn) SetNetInfoCallback(fn func(*tailcfg.NetInfo)) {
	if fn == nil {
		panic("nil NetInfoCallback")
	}
	c.netInfoMu.Lock()
	last := c.netInfoLast
	c.netInfoFunc = fn
	c.netInfoMu.Unlock()

	if last != nil {
		fn(last)
	}
}

func (c *Conn) setNearestDERP(derpNum int) (wantDERP bool) {
	c.derpMu.Lock()
	defer c.derpMu.Unlock()
	if !c.wantDerp {
		c.myDerp = 0
		return false
	}
	if derpNum == c.myDerp {
		// No change.
		return true
	}
	c.myDerp = derpNum
	c.logf("home DERP server is now %v, %v", derpNum, c.derps.ServerByID(derpNum))
	for i, ad := range c.activeDerp {
		go ad.c.NotePreferred(i == c.myDerp)
	}
	if derpNum != 0 && derpNum != c.myDerp {
		// On change, start connecting to it:
		go c.derpWriteChanOfAddr(&net.UDPAddr{IP: derpMagicIP, Port: derpNum})
	}
	return true
}

// determineEndpoints returns the machine's endpoint addresses. It
// does a STUN lookup to determine its public address.
func (c *Conn) determineEndpoints(ctx context.Context, nr *netcheck.Report) (ipPorts []string, err error) {
	already := make(map[string]bool) // endpoint -> true
	var eps []string                 // unique endpoints

	addAddr := func(s, reason string) {
		c.logf("magicsock: found local %s (%s)\n", s, reason)
		if !already[s] {
			already[s] = true
			eps = append(eps, s)
		}
	}

	if nr.GlobalV4 != "" {
		addAddr(nr.GlobalV4, "stun")
	}
	const tailControlDoesIPv6 = false // TODO: when IPv6 filtering/splitting is enabled in tailcontrol
	if nr.GlobalV6 != "" && tailControlDoesIPv6 {
		addAddr(nr.GlobalV6, "stun")
	}

	c.ignoreSTUNPackets()

	if localAddr := c.pconn.LocalAddr(); localAddr.IP.IsUnspecified() {
		ips, loopback, err := interfaces.LocalAddresses()
		if err != nil {
			return nil, err
		}
		reason := "localAddresses"
		if len(ips) == 0 {
			// Only include loopback addresses if we have no
			// interfaces at all to use as endpoints. This allows
			// for localhost testing when you're on a plane and
			// offline, for example.
			ips = loopback
			reason = "loopback"
		}
		for _, ipStr := range ips {
			addAddr(net.JoinHostPort(ipStr, fmt.Sprint(localAddr.Port)), reason)
		}
	} else {
		// Our local endpoint is bound to a particular address.
		// Do not offer addresses on other local interfaces.
		addAddr(localAddr.String(), "socket")
	}

	// Note: the endpoints are intentionally returned in priority order,
	// from "farthest but most reliable" to "closest but least
	// reliable." Addresses returned from STUN should be globally
	// addressable, but might go farther on the network than necessary.
	// Local interface addresses might have lower latency, but not be
	// globally addressable.
	//
	// The STUN address(es) are always first so that legacy wireguard
	// can use eps[0] as its only known endpoint address (although that's
	// obviously non-ideal).
	return eps, nil
}

func stringsEqual(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func (c *Conn) LocalPort() uint16 {
	laddr := c.pconn.LocalAddr()
	return uint16(laddr.Port)
}

func shouldSprayPacket(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	msgType := binary.LittleEndian.Uint32(b[:4])
	switch msgType {
	case device.MessageInitiationType,
		device.MessageResponseType,
		device.MessageCookieReplyType: // TODO: necessary?
		return true
	}
	return false
}

var logPacketDests, _ = strconv.ParseBool(os.Getenv("DEBUG_LOG_PACKET_DESTS"))

// appendDests appends to dsts the destinations that b should be
// written to in order to reach as. Some of the returned UDPAddrs may
// be fake addrs representing DERP servers.
//
// It also returns as's current roamAddr, if any.
func (as *AddrSet) appendDests(dsts []*net.UDPAddr, b []byte) (_ []*net.UDPAddr, roamAddr *net.UDPAddr) {
	spray := shouldSprayPacket(b) // true for handshakes
	now := as.timeNow()

	as.mu.Lock()
	defer as.mu.Unlock()

	// Spray logic.
	//
	// After exchanging a handshake with a peer, we send some outbound
	// packets to every endpoint of that peer. These packets are spaced out
	// over several seconds to make sure that our peer has an opportunity to
	// send its own spray packet to us before we are done spraying.
	//
	// Multiple packets are necessary because we have to both establish the
	// NAT mappings between two peers *and use* the mappings to switch away
	// from DERP to a higher-priority UDP endpoint.
	const sprayPeriod = 3 * time.Second
	const sprayFreq = 250 * time.Millisecond
	if spray {
		as.lastSpray = now
		as.stopSpray = now.Add(sprayPeriod)

		// Reset our favorite route on new handshakes so we
		// can downgrade to a worse path if our better path
		// goes away. (https://github.com/tailscale/tailscale/issues/92)
		as.curAddr = -1
	} else if now.Before(as.stopSpray) {
		// We are in the spray window. If it has been sprayFreq since we
		// last sprayed a packet, spray this packet.
		if now.Sub(as.lastSpray) >= sprayFreq {
			spray = true
			as.lastSpray = now
		}
	}

	// Pick our destination address(es).
	switch {
	case spray:
		// This packet is being sprayed to all addresses.
		for i := range as.addrs {
			dsts = append(dsts, &as.addrs[i])
		}
		if as.roamAddr != nil {
			dsts = append(dsts, as.roamAddr)
		}
	case as.roamAddr != nil:
		// We have a roaming address, prefer it over other addrs.
		// TODO(danderson): this is not correct, there's no reason
		// roamAddr should be special like this.
		dsts = append(dsts, as.roamAddr)
	case as.curAddr != -1:
		if as.curAddr >= len(as.addrs) {
			log.Printf("[unexpected] magicsock bug: as.curAddr >= len(as.addrs): %d >= %d", as.curAddr, len(as.addrs))
			break
		}
		// No roaming addr, but we've seen packets from a known peer
		// addr, so keep using that one.
		dsts = append(dsts, &as.addrs[as.curAddr])
	default:
		// We know nothing about how to reach this peer, and we're not
		// spraying. Use the first address in the array, which will
		// usually be a DERP address that guarantees connectivity.
		if len(as.addrs) > 0 {
			dsts = append(dsts, &as.addrs[0])
		}
	}

	if logPacketDests {
		log.Printf("spray=%v; roam=%v; dests=%v", spray, as.roamAddr, dsts)
	}
	return dsts, as.roamAddr
}

var errNoDestinations = errors.New("magicsock: no destinations")

func (c *Conn) Send(b []byte, ep conn.Endpoint) error {
	var as *AddrSet
	switch v := ep.(type) {
	default:
		panic(fmt.Sprintf("[unexpected] Endpoint type %T", v))
	case *singleEndpoint:
		addr := (*net.UDPAddr)(v)
		if addr.IP.Equal(derpMagicIP) {
			c.logf("[unexpected] DERP BUG: attempting to send packet to DERP address %v", addr)
			return nil
		}
		_, err := c.pconn.WriteTo(b, addr)
		return err
	case *AddrSet:
		as = v
	}

	var addrBuf [8]*net.UDPAddr
	dsts, roamAddr := as.appendDests(addrBuf[:0], b)

	if len(dsts) == 0 {
		return errNoDestinations
	}

	var success bool
	var ret error
	for _, addr := range dsts {
		err := c.sendAddr(addr, as.publicKey, b)
		if err == nil {
			success = true
		} else if ret == nil {
			ret = err
		}
		if err != nil && addr != roamAddr && c.sendLogLimit.Allow() {
			if c.connCtx.Err() == nil { // don't log if we're closed
				c.logf("magicsock: Conn.Send(%v): %v", addr, err)
			}
		}
	}
	if success {
		return nil
	}
	return ret
}

var errConnClosed = errors.New("Conn closed")

var errDropDerpPacket = errors.New("too many DERP packets queued; dropping")

// sendAddr sends packet b to addr, which is either a real UDP address
// or a fake UDP address representing a DERP server (see derpmap.go).
// The provided public key identifies the recipient.
func (c *Conn) sendAddr(addr *net.UDPAddr, pubKey key.Public, b []byte) error {
	if !addr.IP.Equal(derpMagicIP) {
		_, err := c.pconn.WriteTo(b, addr)
		return err
	}

	ch := c.derpWriteChanOfAddr(addr)
	if ch == nil {
		return nil
	}
	errc := make(chan error, 1)
	select {
	case <-c.donec():
		return errConnClosed
	case ch <- derpWriteRequest{addr, pubKey, b, errc}:
		select {
		case <-c.donec():
			return errConnClosed
		case err := <-errc:
			return err // usually nil
		}
	default:
		// Too many writes queued. Drop packet.
		return errDropDerpPacket
	}
}

// bufferedDerpWritesBeforeDrop is how many packets writes can be
// queued up the DERP client to write on the wire before we start
// dropping.
//
// TODO: this is currently arbitrary. Figure out something better?
const bufferedDerpWritesBeforeDrop = 4

// derpWriteChanOfAddr returns a DERP client for fake UDP addresses that
// represent DERP servers, creating them as necessary. For real UDP
// addresses, it returns nil.
func (c *Conn) derpWriteChanOfAddr(addr *net.UDPAddr) chan<- derpWriteRequest {
	if !addr.IP.Equal(derpMagicIP) {
		return nil
	}
	c.derpMu.Lock()
	defer c.derpMu.Unlock()
	if !c.wantDerp {
		return nil
	}
	if c.privateKey.IsZero() {
		c.logf("DERP lookup of %v with no private key; ignoring", addr.IP)
		return nil
	}
	ad, ok := c.activeDerp[addr.Port]
	if !ok {
		if c.activeDerp == nil {
			c.activeDerp = make(map[int]activeDerp)
		}
		derpSrv := c.derps.ServerByID(addr.Port)
		if derpSrv == nil || derpSrv.HostHTTPS == "" {
			return nil
		}

		// Note that derphttp.NewClient does not dial the server
		// so it is safe to do under the derpMu lock.
		dc, err := derphttp.NewClient(c.privateKey, "https://"+derpSrv.HostHTTPS+"/derp", c.logf)
		if err != nil {
			c.logf("derphttp.NewClient: port %d, host %q invalid? err: %v", addr.Port, derpSrv.HostHTTPS, err)
			return nil
		}
		dc.NotePreferred(c.myDerp == addr.Port)
		dc.DNSCache = dnscache.Get()
		dc.TLSConfig = c.derpTLSConfig

		ctx, cancel := context.WithCancel(context.Background())
		ch := make(chan derpWriteRequest, bufferedDerpWritesBeforeDrop)

		ad.c = dc
		ad.writeCh = ch
		ad.cancel = cancel
		ad.lastWrite = new(time.Time)
		c.activeDerp[addr.Port] = ad

		go c.runDerpReader(ctx, addr, dc)
		go c.runDerpWriter(ctx, addr, dc, ch)
	}
	*ad.lastWrite = time.Now()
	return ad.writeCh
}

// derpReadResult is the type sent by runDerpClient to ReceiveIPv4
// when a DERP packet is available.
//
// Notably, it doesn't include the derp.ReceivedPacket because we
// don't want to give the receiver access to the aliased []byte.  To
// get at the packet contents they need to call copyBuf to copy it
// out, which also releases the buffer.
type derpReadResult struct {
	derpAddr *net.UDPAddr
	n        int        // length of data received
	src      key.Public // may be zero until server deployment if v2+
	// copyBuf is called to copy the data to dst.  It returns how
	// much data was copied, which will be n if dst is large
	// enough. copyBuf can only be called once.
	copyBuf func(dst []byte) int
}

var logDerpVerbose, _ = strconv.ParseBool(os.Getenv("DEBUG_DERP_VERBOSE"))

// runDerpReader runs in a goroutine for the life of a DERP
// connection, handling received packets.
func (c *Conn) runDerpReader(ctx context.Context, derpFakeAddr *net.UDPAddr, dc *derphttp.Client) {
	didCopy := make(chan struct{}, 1)
	var buf [derp.MaxPacketSize]byte

	res := derpReadResult{derpAddr: derpFakeAddr}
	var pkt derp.ReceivedPacket
	res.copyBuf = func(dst []byte) int {
		n := copy(dst, pkt.Data)
		didCopy <- struct{}{}
		return n
	}

	for {
		msg, err := dc.Recv(buf[:])
		if err == derphttp.ErrClientClosed {
			return
		}
		if err != nil {
			select {
			case <-c.donec():
				return
			case <-ctx.Done():
				return
			default:
			}
			c.logf("[%p] derp.Recv(derp%d): %v", dc, derpFakeAddr.Port, err)
			time.Sleep(250 * time.Millisecond)
			continue
		}
		switch m := msg.(type) {
		case derp.ReceivedPacket:
			pkt = m
			res.n = len(m.Data)
			res.src = m.Source
			if logDerpVerbose {
				c.logf("got derp %v packet: %q", derpFakeAddr, m.Data)
			}
		default:
			// Ignore.
			// TODO: handle endpoint notification messages.
			continue
		}
		select {
		case <-c.donec():
			return
		case c.derpRecvCh <- res:
			<-didCopy
		}
	}
}

type derpWriteRequest struct {
	addr   *net.UDPAddr
	pubKey key.Public
	b      []byte
	errc   chan<- error
}

// runDerpWriter runs in a goroutine for the life of a DERP
// connection, handling received packets.
func (c *Conn) runDerpWriter(ctx context.Context, derpFakeAddr *net.UDPAddr, dc *derphttp.Client, ch <-chan derpWriteRequest) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.donec():
			return
		case wr := <-ch:
			err := dc.Send(wr.pubKey, wr.b)
			if err != nil {
				c.logf("magicsock: derp.Send(%v): %v", wr.addr, err)
			}
			select {
			case wr.errc <- err:
			case <-c.donec():
				return
			}
		}
	}
}

// findEndpoint maps from a UDP address to a WireGuard endpoint, for
// ReceiveIPv4/ReceiveIPv6.
func (c *Conn) findEndpoint(addr *net.UDPAddr) conn.Endpoint {
	if as := c.findAddrSet(addr); as != nil {
		return as
	}
	// The peer that sent this packet has roamed beyond the
	// knowledge provided by the control server.
	// If the packet is valid wireguard will call UpdateDst
	// on the original endpoint using this addr.
	return (*singleEndpoint)(addr)
}

func (c *Conn) findAddrSet(addr *net.UDPAddr) *AddrSet {
	var epAddr udpAddr
	copy(epAddr.ip.Addr[:], addr.IP.To16())
	epAddr.port = uint16(addr.Port)

	c.addrsMu.Lock()
	defer c.addrsMu.Unlock()

	return c.addrsByUDP[epAddr]
}

type udpReadResult struct {
	n    int
	err  error
	addr *net.UDPAddr
}

// aLongTimeAgo is a non-zero time, far in the past, used for
// immediate cancellation of network operations.
var aLongTimeAgo = time.Unix(233431200, 0)

// awaitUDP4 reads a single IPv4 UDP packet (or an error) and sends it
// to c.udpRecvCh, skipping over (but handling) any STUN replies.
func (c *Conn) awaitUDP4(b []byte) {
	for {
		n, pAddr, err := c.pconn.ReadFrom(b)
		if err != nil {
			select {
			case c.udpRecvCh <- udpReadResult{err: err}:
			case <-c.donec():
			}
			return
		}
		addr := pAddr.(*net.UDPAddr)
		if stun.Is(b[:n]) {
			c.stunReceiveFunc.Load().(func([]byte, *net.UDPAddr))(b, addr)
			continue
		}

		addr.IP = addr.IP.To4()
		select {
		case c.udpRecvCh <- udpReadResult{n: n, addr: addr}:
		case <-c.donec():
		}
		return
	}

}

func (c *Conn) ReceiveIPv4(b []byte) (n int, ep conn.Endpoint, addr *net.UDPAddr, err error) {
	// First, process any buffered packet from earlier.
	if addr := c.bufferedIPv4From; addr != nil {
		c.bufferedIPv4From = nil
		return copy(b, c.bufferedIPv4Packet), c.findEndpoint(addr), addr, nil
	}

	go c.awaitUDP4(b)

	// Once the above goroutine has started, it owns b until it writes
	// to udpRecvCh. The code below must not access b until it's
	// completed a successful receive on udpRecvCh.

	var addrSet *AddrSet

	select {
	case dm := <-c.derpRecvCh:
		// Cancel the pconn read goroutine
		c.pconn.SetReadDeadline(aLongTimeAgo)
		// Wait for the UDP-reading goroutine to be done, since it's currently
		// the owner of the b []byte buffer:
		select {
		case um := <-c.udpRecvCh:
			if um.err != nil {
				// The normal case. The SetReadDeadline interrupted
				// the read and we get an error which we now ignore.
			} else {
				// The pconn.ReadFrom succeeded and was about to send,
				// but DERP sent first. So now we have both ready.
				// Save the UDP packet away for use by the next
				// ReceiveIPv4 call.
				c.bufferedIPv4From = um.addr
				c.bufferedIPv4Packet = append(c.bufferedIPv4Packet[:0], b[:um.n]...)
			}
			c.pconn.SetReadDeadline(time.Time{})
		case <-c.donec():
			return 0, nil, nil, errors.New("Conn closed")
		}
		n, addr = dm.n, dm.derpAddr
		ncopy := dm.copyBuf(b)
		if ncopy != n {
			err = fmt.Errorf("received DERP packet of length %d that's too big for WireGuard ReceiveIPv4 buf size %d", n, ncopy)
			c.logf("magicsock: %v", err)
			return 0, nil, nil, err
		}

		c.addrsMu.Lock()
		addrSet = c.addrsByKey[dm.src]
		c.addrsMu.Unlock()

		if addrSet == nil {
			key := wgcfg.Key(dm.src)
			c.logf("magicsock: DERP packet from unknown key: %s", key.ShortString())
		}

	case um := <-c.udpRecvCh:
		if um.err != nil {
			return 0, nil, nil, err
		}
		n, addr = um.n, um.addr

	case <-c.donec():
		// Socket has been shut down. All the producers of packets
		// respond to the context cancellation and go away, so we have
		// to also unblock and return an error, to inform wireguard-go
		// that this socket has gone away.
		//
		// Specifically, wireguard-go depends on its bind.Conn having
		// the standard socket behavior, which is that a Close()
		// unblocks any concurrent Read()s. wireguard-go itself calls
		// Clos() on magicsock, and expects ReceiveIPv4 to unblock
		// with an error so it can clean up.
		return 0, nil, nil, errors.New("socket closed")
	}

	if addrSet != nil {
		ep = addrSet
	} else {
		ep = c.findEndpoint(addr)
	}
	return n, ep, addr, nil
}

func (c *Conn) ReceiveIPv6(buff []byte) (int, conn.Endpoint, *net.UDPAddr, error) {
	// TODO(crawshaw): IPv6 support
	return 0, nil, nil, syscall.EAFNOSUPPORT
}

// SetPrivateKey sets the connection's private key.
//
// This is only used to be able prove our identity when connecting to
// DERP servers.
//
// If the private key changes, any DERP connections are torn down &
// recreated when needed.
func (c *Conn) SetPrivateKey(privateKey wgcfg.PrivateKey) error {
	c.derpMu.Lock()
	defer c.derpMu.Unlock()

	oldKey, newKey := c.privateKey, key.Private(privateKey)
	if newKey == oldKey {
		return nil
	}
	c.privateKey = newKey
	if oldKey.IsZero() {
		// Initial configuration on start.
		return nil
	}

	// Key changed. Close any DERP connections.
	c.closeAllDerpLocked()

	return nil
}

// SetDERPEnabled controls whether DERP is used.
// New connections have it enabled by default.
func (c *Conn) SetDERPEnabled(wantDerp bool) {
	c.derpMu.Lock()
	defer c.derpMu.Unlock()

	c.wantDerp = wantDerp
	if !wantDerp {
		c.closeAllDerpLocked()
	}
}

// c.derpMu must be held.
func (c *Conn) closeAllDerpLocked() {
	for i := range c.activeDerp {
		c.closeDerpLocked(i)
	}
}

// c.derpMu must be held.
func (c *Conn) closeDerpLocked(node int) {
	if ad, ok := c.activeDerp[node]; ok {
		c.logf("closing connection to derp%v", node)
		go ad.c.Close()
		ad.cancel()
		delete(c.activeDerp, node)
	}
}

func (c *Conn) cleanStaleDerp() {
	c.derpMu.Lock()
	defer c.derpMu.Unlock()
	const inactivityTime = 60 * time.Second
	tooOld := time.Now().Add(-inactivityTime)
	for i, ad := range c.activeDerp {
		if i == c.myDerp {
			continue
		}
		if ad.lastWrite.Before(tooOld) {
			c.logf("closing stale DERP connection to derp%v", i)
			c.closeDerpLocked(i)
		}
	}
}

func (c *Conn) SetMark(value uint32) error { return nil }
func (c *Conn) LastMark() uint32           { return 0 }

func (c *Conn) Close() error {
	// TODO: make this safe for concurrent Close? it's safe now only if Close calls are serialized.
	select {
	case <-c.donec():
		return nil
	default:
	}
	c.connCtxCancel()

	c.derpMu.Lock()
	c.closeAllDerpLocked()
	c.derpMu.Unlock()

	err := c.pconn.Close()
	c.goroutines.Wait()
	return err
}

func (c *Conn) reSTUN() {
	select {
	case c.startEpUpdate <- struct{}{}:
	case <-c.donec():
	}
}

// LinkChange should be called whenever something changed with the
// network, no matter how minor. The LinkChange method then looks
// at the state of the network and decides whether the change from
// before is interesting enough to warrant taking action on.
func (c *Conn) LinkChange() {
	defer c.reSTUN()

	c.linkChangeMu.Lock()
	defer c.linkChangeMu.Unlock()

	cur, err := getLinkState()
	if err != nil {
		return
	}
	if c.linkState != nil && !cur.Equal(c.linkState) {
		c.linkState = cur
		c.rebind()
	}
}

func getLinkState() (*interfaces.State, error) {
	s, err := interfaces.GetState()
	if s != nil {
		s.RemoveTailscaleInterfaces()
	}
	return s, err
}

func (c *Conn) rebind() {
	if c.pconnPort != 0 {
		c.pconn.mu.Lock()
		if err := c.pconn.pconn.Close(); err != nil {
			c.logf("magicsock: link change close failed: %v", err)
		}
		packetConn, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", c.pconnPort))
		if err == nil {
			c.logf("magicsock: link change rebound port: %d", c.pconnPort)
			c.pconn.pconn = packetConn.(*net.UDPConn)
			c.pconn.mu.Unlock()
			return
		}
		c.logf("magicsock: link change unable to bind fixed port %d: %v, falling back to random port", c.pconnPort, err)
		c.pconn.mu.Unlock()
	}
	c.logf("magicsock: link change, binding new port")
	packetConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		c.logf("magicsock: link change failed to bind new port: %v", err)
		return
	}
	c.pconn.Reset(packetConn.(*net.UDPConn))
}

// AddrSet is a set of UDP addresses that implements wireguard/conn.Endpoint.
type AddrSet struct {
	publicKey key.Public // peer public key used for DERP communication

	// addrs is an ordered priority list provided by wgengine,
	// sorted from expensive+slow+reliable at the begnining to
	// fast+cheap at the end. More concretely, it's typically:
	//
	//     [DERP fakeip:node, Global IP:port, LAN ip:port]
	//
	// But there could be multiple or none of each.
	addrs []net.UDPAddr

	// clock, if non-nil, is used in tests instead of time.Now.
	clock func() time.Time
	Logf  logger.Logf // Logf, if non-nil, is used instead of log.Printf

	mu sync.Mutex // guards following fields

	// roamAddr is non-nil if/when we receive a correctly signed
	// WireGuard packet from an unexpected address. If so, we
	// remember it and send responses there in the future, but
	// this should hopefully never be used (or at least used
	// rarely) in the case that all the components of Tailscale
	// are correctly learning/sharing the network map details.
	roamAddr *net.UDPAddr

	// curAddr is an index into addrs of the highest-priority
	// address a valid packet has been received from so far.
	// If no valid packet from addrs has been received, curAddr is -1.
	curAddr int

	// stopSpray is the time after which we stop spraying packets.
	stopSpray time.Time

	// lastSpray is the lsat time we sprayed a packet.
	lastSpray time.Time
}

func (as *AddrSet) timeNow() time.Time {
	if as.clock != nil {
		return as.clock()
	}
	return time.Now()
}

func (as *AddrSet) logf(format string, args ...interface{}) {
	if as.Logf != nil {
		as.Logf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

var noAddr = &net.UDPAddr{
	IP:   net.ParseIP("127.127.127.127"),
	Port: 127,
}

func (a *AddrSet) dst() *net.UDPAddr {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.roamAddr != nil {
		return a.roamAddr
	}
	if len(a.addrs) == 0 {
		return noAddr
	}
	i := a.curAddr
	if i == -1 {
		i = 0
	}
	return &a.addrs[i]
}

// packUDPAddr packs a UDPAddr in the form wanted by WireGuard.
func packUDPAddr(ua *net.UDPAddr) []byte {
	ip := ua.IP.To4()
	if ip == nil {
		ip = ua.IP
	}
	b := make([]byte, 0, len(ip)+2)
	b = append(b, ip...)
	b = append(b, byte(ua.Port))
	b = append(b, byte(ua.Port>>8))
	return b
}

func (a *AddrSet) DstToBytes() []byte {
	return packUDPAddr(a.dst())
}
func (a *AddrSet) DstToString() string {
	dst := a.dst()
	return dst.String()
}
func (a *AddrSet) DstIP() net.IP {
	return a.dst().IP
}
func (a *AddrSet) SrcIP() net.IP       { return nil }
func (a *AddrSet) SrcToString() string { return "" }
func (a *AddrSet) ClearSrc()           {}

func (a *AddrSet) UpdateDst(new *net.UDPAddr) error {
	if new.IP.Equal(derpMagicIP) {
		// Never consider DERP addresses as a viable candidate for
		// either curAddr or roamAddr. It's only ever a last resort
		// choice, never a preferred choice.
		// This is a hot path for established connections.
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.roamAddr != nil && equalUDPAddr(new, a.roamAddr) {
		// Packet from the current roaming address, no logging.
		// This is a hot path for established connections.
		return nil
	}
	if a.roamAddr == nil && a.curAddr >= 0 && equalUDPAddr(new, &a.addrs[a.curAddr]) {
		// Packet from current-priority address, no logging.
		// This is a hot path for established connections.
		return nil
	}

	index := -1
	for i := range a.addrs {
		if equalUDPAddr(new, &a.addrs[i]) {
			index = i
			break
		}
	}

	publicKey := wgcfg.Key(a.publicKey)
	pk := publicKey.ShortString()
	old := "<none>"
	if a.curAddr >= 0 {
		old = a.addrs[a.curAddr].String()
	}

	switch {
	case index == -1:
		if a.roamAddr == nil {
			a.logf("magicsock: rx %s from roaming address %s, set as new priority", pk, new)
		} else {
			a.logf("magicsock: rx %s from roaming address %s, replaces roaming address %s", pk, new, a.roamAddr)
		}
		a.roamAddr = new

	case a.roamAddr != nil:
		a.logf("magicsock: rx %s from known %s (%d), replaces roaming address %s", pk, new, index, a.roamAddr)
		a.roamAddr = nil
		a.curAddr = index

	case a.curAddr == -1:
		a.logf("magicsock: rx %s from %s (%d/%d), set as new priority", pk, new, index, len(a.addrs))
		a.curAddr = index

	case index < a.curAddr:
		a.logf("magicsock: rx %s from low-pri %s (%d), keeping current %s (%d)", pk, new, index, old, a.curAddr)

	default: // index > a.curAddr
		a.logf("magicsock: rx %s from %s (%d/%d), replaces old priority %s", pk, new, index, len(a.addrs), old)
		a.curAddr = index
	}

	return nil
}

func equalUDPAddr(x, y *net.UDPAddr) bool {
	return x.Port == y.Port && x.IP.Equal(y.IP)
}

func (a *AddrSet) String() string {
	a.mu.Lock()
	defer a.mu.Unlock()

	buf := new(strings.Builder)
	buf.WriteByte('[')
	if a.roamAddr != nil {
		fmt.Fprintf(buf, "roam:%s:%d", a.roamAddr.IP, a.roamAddr.Port)
	}
	for i, addr := range a.addrs {
		if i > 0 || a.roamAddr != nil {
			buf.WriteString(", ")
		}
		fmt.Fprintf(buf, "%s:%d", addr.IP, addr.Port)
		if a.curAddr == i {
			buf.WriteByte('*')
		}
	}
	buf.WriteByte(']')

	return buf.String()
}

func (a *AddrSet) Addrs() []wgcfg.Endpoint {
	var eps []wgcfg.Endpoint
	for _, addr := range a.addrs {
		eps = append(eps, wgcfg.Endpoint{
			Host: addr.IP.String(),
			Port: uint16(addr.Port),
		})
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.roamAddr != nil {
		eps = append(eps, wgcfg.Endpoint{
			Host: a.roamAddr.IP.String(),
			Port: uint16(a.roamAddr.Port),
		})
	}
	return eps
}

// CreateBind is called by WireGuard to create a UDP binding.
func (c *Conn) CreateBind(uint16) (conn.Bind, uint16, error) {
	return c, c.LocalPort(), nil
}

// CreateEndpoint is called by WireGuard to connect to an endpoint.
// The key is the public key of the peer and addrs is a
// comma-separated list of UDP ip:ports.
func (c *Conn) CreateEndpoint(key [32]byte, addrs string) (conn.Endpoint, error) {
	pk := wgcfg.Key(key)
	c.logf("magicsock: CreateEndpoint: key=%s: %s", pk.ShortString(), addrs)
	a := &AddrSet{
		publicKey: key,
		curAddr:   -1,
	}

	if addrs != "" {
		for _, ep := range strings.Split(addrs, ",") {
			addr, err := net.ResolveUDPAddr("udp", ep)
			if err != nil {
				return nil, err
			}
			if ip4 := addr.IP.To4(); ip4 != nil {
				addr.IP = ip4
			}
			a.addrs = append(a.addrs, *addr)
		}
	}

	c.addrsMu.Lock()
	for _, addr := range a.addrs {
		if addr.IP.Equal(derpMagicIP) {
			continue
		}

		var epAddr udpAddr
		copy(epAddr.ip.Addr[:], addr.IP.To16())
		epAddr.port = uint16(addr.Port)
		c.addrsByUDP[epAddr] = a
	}
	c.addrsByKey[key] = a
	c.addrsMu.Unlock()

	return a, nil
}

type singleEndpoint net.UDPAddr

func (e *singleEndpoint) ClearSrc()           {}
func (e *singleEndpoint) DstIP() net.IP       { return (*net.UDPAddr)(e).IP }
func (e *singleEndpoint) SrcIP() net.IP       { return nil }
func (e *singleEndpoint) SrcToString() string { return "" }
func (e *singleEndpoint) DstToString() string { return (*net.UDPAddr)(e).String() }
func (e *singleEndpoint) DstToBytes() []byte  { return packUDPAddr((*net.UDPAddr)(e)) }
func (e *singleEndpoint) UpdateDst(dst *net.UDPAddr) error {
	return fmt.Errorf("magicsock.singleEndpoint(%s).UpdateDst(%s): should never be called", (*net.UDPAddr)(e), dst)
}
func (e *singleEndpoint) Addrs() []wgcfg.Endpoint {
	return []wgcfg.Endpoint{{
		Host: e.IP.String(),
		Port: uint16(e.Port),
	}}
}

// RebindingUDPConn is a UDP socket that can be re-bound.
// Unix has no notion of re-binding a socket, so we swap it out for a new one.
type RebindingUDPConn struct {
	mu    sync.Mutex
	pconn *net.UDPConn
}

func (c *RebindingUDPConn) Reset(pconn *net.UDPConn) {
	c.mu.Lock()
	old := c.pconn
	c.pconn = pconn
	c.mu.Unlock()

	if old != nil {
		old.Close()
	}
}

func (c *RebindingUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		pconn := c.pconn
		c.mu.Unlock()

		n, addr, err := pconn.ReadFrom(b)
		if err != nil {
			c.mu.Lock()
			pconn2 := c.pconn
			c.mu.Unlock()

			if pconn != pconn2 {
				continue
			}
		}
		return n, addr, err
	}
}

func (c *RebindingUDPConn) LocalAddr() *net.UDPAddr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pconn.LocalAddr().(*net.UDPAddr)
}

func (c *RebindingUDPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pconn.Close()
}

func (c *RebindingUDPConn) SetReadDeadline(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pconn.SetReadDeadline(t)
}

func (c *RebindingUDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	for {
		c.mu.Lock()
		pconn := c.pconn
		c.mu.Unlock()

		n, err := pconn.WriteToUDP(b, addr)
		if err != nil {
			c.mu.Lock()
			pconn2 := c.pconn
			c.mu.Unlock()

			if pconn != pconn2 {
				continue
			}
		}
		return n, err
	}
}

func (c *RebindingUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	for {
		c.mu.Lock()
		pconn := c.pconn
		c.mu.Unlock()

		n, err := pconn.WriteTo(b, addr)
		if err != nil {
			c.mu.Lock()
			pconn2 := c.pconn
			c.mu.Unlock()

			if pconn != pconn2 {
				continue
			}
		}
		return n, err
	}
}
