// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_tswg

package wgengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tailscale/netlink"
	"golang.org/x/sys/unix"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tstun"
	"tailscale.com/tsconst"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/tswg"
	"tailscale.com/wgengine/wgcfg"
)

// kernelDataplane drives the tswg kernel module, which does WireGuard in
// the kernel in place of wireguard-go; see
// https://github.com/tailscale/tailscale/issues/426.
//
// The kernel handles packets on direct UDP paths by itself, on UDP sockets
// it shares with magicsock (which still gets the disco and STUN traffic on
// them). Everything else goes through a loopback bridge: each peer gets an
// address in 127.0.0.0/8, and when the kernel should not send to a peer
// directly (its path is DERP or a peer relay, or not trusted yet), the
// peer's kernel endpoint is set to that address on the bridge's port. The
// bridge hands what the kernel sends there to magicsock to send, and
// injects the WireGuard packets magicsock receives over DERP or a peer
// relay into the kernel from the peer's loopback address.
//
// A reconcile loop keeps the kernel's peers in sync with magicsock's peers
// and the live per-peer config, points each peer at its direct path or the
// bridge, and feeds the kernel's per-peer traffic back to magicsock so
// that it keeps heartbeating active sessions.
type kernelDataplane struct {
	logf         logger.Logf
	ifname       string
	peerConfigFn *atomic.Pointer[func(key.NodePublic) (wgcfg.PeerConfig, bool)]
	kick         chan struct{} // buffered(1); wakes the reconcile loop

	ms      *magicsock.Conn // set by start
	bridge  *net.UDPConn    // set by start
	ipSocks *ipSockets      // set by start; see kerneldp_tsmp_linux.go

	// priorityMsgFn, if set, returns the message (a TSMP disco key
	// advertisement) to send to a peer when the kernel establishes a new
	// session with it, as wireguard-go does with its priority messages.
	priorityMsgFn atomic.Pointer[func(key.NodePublic) []byte]
	ctx           context.Context
	cancel        context.CancelFunc
	done          chan struct{} // closed when the reconcile loop exits

	// kernelPort is the kernel device's UDP listen port, which the bridge
	// sends injected packets to.
	kernelPort atomic.Uint32

	nlMu sync.Mutex // serializes use of nl
	nl   *tswg.Client

	mu           sync.Mutex
	privKey      key.NodePrivate                    // desired private key
	pushedPriv   key.NodePrivate                    // private key last pushed to the kernel
	pushed       map[key.NodePublic]kernelPeerState // peer state last pushed to the kernel
	loopAddr     map[key.NodePublic]netip.Addr      // peer's bridge address
	loopPeer     map[netip.Addr]key.NodePublic      // inverse of loopAddr
	nextLoop     uint32                             // next index for loopAddr
	counters     map[key.NodePublic][2]uint64       // last seen rx, tx bytes
	handshakes   map[key.NodePublic]time.Time       // last seen handshake times
	status       []ipnstate.PeerStatusLite          // from the last dump
	warnedHybrid map[key.NodePublic]bool
}

// kernelPeerState is the state of one kernel peer that the reconcile loop
// manages.
type kernelPeerState struct {
	endpoint   netip.AddrPort
	allowedIPs []netip.Prefix // sorted
	psk        [32]byte
}

func (s kernelPeerState) equal(o kernelPeerState) bool {
	return s.endpoint == o.endpoint && s.psk == o.psk && slices.Equal(s.allowedIPs, o.allowedIPs)
}

// kernelReconcileInterval is how often the reconcile loop runs when not
// kicked. It bounds how long the kernel keeps sending on a direct path
// after magicsock stops trusting it.
const kernelReconcileInterval = time.Second

// kernelMaxPeersPerMessage bounds the size of each netlink message.
const kernelMaxPeersPerMessage = 32

func newKernelDataplane(logf logger.Logf, ifname string, peerConfigFn *atomic.Pointer[func(key.NodePublic) (wgcfg.PeerConfig, bool)]) *kernelDataplane {
	return &kernelDataplane{
		logf:         logger.WithPrefix(logf, "tswg: "),
		ifname:       ifname,
		peerConfigFn: peerConfigFn,
		kick:         make(chan struct{}, 1),
		done:         make(chan struct{}),
		pushed:       map[key.NodePublic]kernelPeerState{},
		loopAddr:     map[key.NodePublic]netip.Addr{},
		loopPeer:     map[netip.Addr]key.NodePublic{},
		counters:     map[key.NodePublic][2]uint64{},
		handshakes:   map[key.NodePublic]time.Time{},
		warnedHybrid: map[key.NodePublic]bool{},
	}
}

// start opens the bridge, shares magicsock's sockets with the kernel,
// connects tun's injected and TSMP packets to the kernel device, and
// starts the bridge, TSMP and reconcile loops.
func (k *kernelDataplane) start(ms *magicsock.Conn, tun *tstun.Wrapper) error {
	k.ms = ms
	nl, err := tswg.Open()
	if err != nil {
		return err
	}
	k.nl = nl

	// Route the kernel's encrypted packets around Tailscale's own routes
	// (such as an exit node's default route), as magicsock's sockets do.
	mark := uint32(tsconst.LinuxBypassMarkNum)
	if err := nl.ConfigureDevice(k.ifname, tswg.Config{FirewallMark: &mark}); err != nil {
		nl.Close()
		return err
	}

	// The bridge listens on all of 127.0.0.0/8 (so it can tell peers
	// apart by destination address), on the loopback interface only.
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) {
				if serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "lo"); serr != nil {
					return
				}
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
			})
			return errors.Join(err, serr)
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		nl.Close()
		return fmt.Errorf("listening on loopback bridge: %w", err)
	}
	k.bridge = pc.(*net.UDPConn)
	k.kernelPort.Store(uint32(ms.LocalPort()))

	ms.SetKernelSocketHook(k.setSocket)

	link, err := netlink.LinkByName(k.ifname)
	if err == nil {
		err = netlink.LinkSetUp(link)
	}
	if err != nil {
		k.bridge.Close()
		nl.Close()
		return fmt.Errorf("bringing up %s: %w", k.ifname, err)
	}

	k.ipSocks, err = k.openIPSockets()
	if err != nil {
		k.bridge.Close()
		nl.Close()
		return err
	}
	tun.SetOutboundInjectHook(k.sendIPPacket)

	k.ctx, k.cancel = context.WithCancel(context.Background())
	go k.readBridge()
	go k.readTSMP4(tun)
	if k.ipSocks.recv6 != nil {
		go k.readTSMP6(tun)
	}
	go k.reconcileLoop()
	k.logf("kernel data plane on %s; loopback bridge on %v", k.ifname, k.bridge.LocalAddr())
	return nil
}

// Close stops the kernel data plane and deletes the kernel device.
func (k *kernelDataplane) Close() error {
	if k.cancel == nil {
		return nil // never started
	}
	k.cancel()
	k.bridge.Close()
	k.ipSocks.close()
	<-k.done
	k.nlMu.Lock()
	defer k.nlMu.Unlock()
	k.nl.Close()
	return tswg.DeleteLink(k.ifname)
}

// setSocket is magicsock's kernel socket hook: it shares magicsock's
// socket fd for network ("udp4" or "udp6") with the kernel.
func (k *kernelDataplane) setSocket(network string, fd uintptr) error {
	ifd := int(fd)
	var cfg tswg.Config
	switch network {
	case "udp4":
		cfg.SocketFD4 = &ifd
	case "udp6":
		cfg.SocketFD6 = &ifd
	default:
		return fmt.Errorf("unknown network %q", network)
	}
	k.nlMu.Lock()
	defer k.nlMu.Unlock()
	if err := k.nl.ConfigureDevice(k.ifname, cfg); err != nil {
		return err
	}
	if network == "udp4" {
		if sa, err := unix.Getsockname(ifd); err == nil {
			if sa4, ok := sa.(*unix.SockaddrInet4); ok {
				k.kernelPort.Store(uint32(sa4.Port))
			}
		}
	}
	k.logf("sharing magicsock %s socket with the kernel", network)
	return nil
}

// setPriorityMessageFunc sets the function that returns the message to send
// to a peer when the kernel establishes a new session with it.
func (k *kernelDataplane) setPriorityMessageFunc(fn func(key.NodePublic) []byte) {
	if fn == nil {
		k.priorityMsgFn.Store(nil)
		return
	}
	k.priorityMsgFn.Store(&fn)
}

// setPrivateKey sets the device's private key.
func (k *kernelDataplane) setPrivateKey(pk key.NodePrivate) {
	k.mu.Lock()
	k.privKey = pk
	k.mu.Unlock()
	k.kickReconcile()
}

// clearSession makes the kernel forget its session with the peer with key
// pk, so that the next packet to the peer starts a new handshake. It's the
// kernel equivalent of wireguard-go's ScheduleHandshakeOnUserSend, for when
// the peer restarted and lost its keys.
//
// It also updates the peer's kernel endpoint in the same step: the peer's
// path has likely just changed too (a restarted peer usually has a new
// port), and the new handshake should go out on the new path rather than
// waiting for the next reconcile.
func (k *kernelDataplane) clearSession(pk key.NodePublic) {
	path, _ := k.ms.KernelPeerPath(pk)
	k.mu.Lock()
	st, ok := k.pushed[pk]
	if !ok {
		k.mu.Unlock()
		return // not in the kernel; nothing to clear
	}
	st.endpoint = k.endpointLocked(pk, path.Direct)
	k.pushed[pk] = st
	k.mu.Unlock()
	err := k.configure(tswg.Config{Peers: []tswg.PeerConfig{{
		PublicKey:    pk,
		UpdateOnly:   true,
		ClearSession: true,
		Endpoint:     st.endpoint,
	}}})
	if err != nil {
		k.logf("clearing session with %v: %v", pk.ShortString(), err)
		return
	}
	k.logf("cleared session with %v", pk.ShortString())
}

// kickReconcile makes the reconcile loop run soon.
func (k *kernelDataplane) kickReconcile() {
	select {
	case k.kick <- struct{}{}:
	default:
	}
}

// endpointLocked returns the kernel endpoint for the peer with key pk:
// direct, if valid, else the peer's address on the loopback bridge. k.mu
// must be held.
func (k *kernelDataplane) endpointLocked(pk key.NodePublic, direct netip.AddrPort) netip.AddrPort {
	if direct.IsValid() {
		return direct
	}
	return netip.AddrPortFrom(k.loopAddrLocked(pk), uint16(k.bridge.LocalAddr().(*net.UDPAddr).Port))
}

// loopAddrLocked returns the bridge address of the peer with key pk,
// assigning one if needed. k.mu must be held.
func (k *kernelDataplane) loopAddrLocked(pk key.NodePublic) netip.Addr {
	if a, ok := k.loopAddr[pk]; ok {
		return a
	}
	// 127.0.0.2 upwards; 127.0.0.1 is for packets from unknown peers.
	k.nextLoop++
	n := k.nextLoop + 1
	a := netip.AddrFrom4([4]byte{127, byte(n >> 16), byte(n >> 8), byte(n)})
	k.loopAddr[pk] = a
	k.loopPeer[a] = pk
	return a
}

// injectFromMagicsock is magicsock's KernelWGRecv hook. It sends pkt, a
// WireGuard packet magicsock received from the peer with key src (or the
// zero key if unknown) over DERP or a peer relay, into the kernel, from
// the peer's bridge address.
func (k *kernelDataplane) injectFromMagicsock(src key.NodePublic, pkt []byte) {
	if k.bridge == nil {
		return
	}
	from := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	if !src.IsZero() {
		k.mu.Lock()
		from = k.loopAddrLocked(src)
		k.mu.Unlock()
	}
	oob := unix.PktInfo4(&unix.Inet4Pktinfo{Spec_dst: from.As4()})
	to := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(k.kernelPort.Load()))
	if _, _, err := k.bridge.WriteMsgUDPAddrPort(pkt, oob, to); err != nil {
		k.logf("injecting packet from %v: %v", src.ShortString(), err)
	}
}

// readBridge reads the packets the kernel sends to peers' bridge addresses
// and hands them to magicsock to send.
func (k *kernelDataplane) readBridge() {
	buf := make([]byte, 65535)
	oob := make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
	for {
		n, oobn, _, from, err := k.bridge.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if k.ctx.Err() == nil {
				k.logf("reading loopback bridge: %v", err)
			}
			return
		}
		if !from.Addr().IsLoopback() {
			continue
		}
		dst, ok := pktinfoDst(oob[:oobn])
		if !ok {
			continue
		}
		k.mu.Lock()
		pk, ok := k.loopPeer[dst]
		k.mu.Unlock()
		if !ok {
			continue
		}
		if err := k.ms.SendWireGuardFromKernel(pk, buf[:n]); err != nil {
			k.logf("sending packet for %v from the kernel: %v", pk.ShortString(), err)
		}
	}
}

// pktinfoDst returns the destination address from the IP_PKTINFO control
// message in oob.
func pktinfoDst(oob []byte) (netip.Addr, bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.Addr{}, false
	}
	for _, m := range msgs {
		if m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_PKTINFO && len(m.Data) >= unix.SizeofInet4Pktinfo {
			// struct in_pktinfo { int ifindex; in_addr spec_dst; in_addr addr; }
			return netip.AddrFrom4([4]byte(m.Data[8:12])), true
		}
	}
	return netip.Addr{}, false
}

func (k *kernelDataplane) reconcileLoop() {
	defer close(k.done)
	t := time.NewTicker(kernelReconcileInterval)
	defer t.Stop()
	for {
		if err := k.reconcile(); err != nil {
			k.logf("reconcile: %v", err)
		}
		select {
		case <-k.ctx.Done():
			return
		case <-t.C:
		case <-k.kick:
		}
	}
}

// reconcile pushes the desired private key and peers to the kernel, then
// reads back the kernel's per-peer traffic counters.
func (k *kernelDataplane) reconcile() error {
	fn := k.peerConfigFn.Load()
	if fn == nil {
		return nil // no config source yet
	}

	// Compute the desired peers without holding k.mu, since the config
	// source takes LocalBackend locks.
	paths := k.ms.KernelPeerPaths()
	type want struct {
		pk   key.NodePublic
		st   kernelPeerState
		conf wgcfg.PeerConfig
	}
	wants := make([]want, 0, len(paths))
	for _, p := range paths {
		conf, ok := (*fn)(p.Key)
		if !ok {
			continue
		}
		ips := slices.Clone(conf.AllowedIPs)
		slices.SortFunc(ips, func(a, b netip.Prefix) int {
			if c := a.Addr().Compare(b.Addr()); c != 0 {
				return c
			}
			return a.Bits() - b.Bits()
		})
		wants = append(wants, want{pk: p.Key, conf: conf, st: kernelPeerState{
			endpoint:   p.Direct,
			allowedIPs: ips,
			psk:        conf.PresharedKey,
		}})
	}

	k.mu.Lock()
	var cfg tswg.Config
	if !k.privKey.Equal(k.pushedPriv) {
		pk := k.privKey
		cfg.PrivateKey = &pk
	}
	desired := make(map[key.NodePublic]kernelPeerState, len(wants))
	var peers []tswg.PeerConfig
	noRoam := true
	for _, w := range wants {
		w.st.endpoint = k.endpointLocked(w.pk, w.st.endpoint)
		if w.conf.Hybrid && !k.warnedHybrid[w.pk] {
			k.warnedHybrid[w.pk] = true
			k.logf("[unexpected] peer %v wants a hybrid handshake, which tswg doesn't support; using a classic handshake", w.pk.ShortString())
		}
		desired[w.pk] = w.st
		old, ok := k.pushed[w.pk]
		if ok && old.equal(w.st) {
			continue
		}
		psk := w.st.psk
		peers = append(peers, tswg.PeerConfig{
			PublicKey:         w.pk,
			Endpoint:          w.st.endpoint,
			ReplaceAllowedIPs: true,
			AllowedIPs:        w.st.allowedIPs,
			PresharedKey:      &psk,
			NoRoam:            &noRoam,
		})
	}
	for pk := range k.pushed {
		if _, ok := desired[pk]; !ok {
			peers = append(peers, tswg.PeerConfig{PublicKey: pk, Remove: true})
		}
	}
	k.mu.Unlock()

	// Push the changes, in chunks.
	if cfg.PrivateKey != nil || len(peers) > 0 {
		for first := true; first || len(peers) > 0; first = false {
			n := min(len(peers), kernelMaxPeersPerMessage)
			cfg.Peers = peers[:n]
			peers = peers[n:]
			if err := k.configure(cfg); err != nil {
				return err
			}
			cfg.PrivateKey = nil
		}
		k.mu.Lock()
		k.pushedPriv = k.privKey
		k.pushed = desired
		k.mu.Unlock()
	}

	return k.readCounters()
}

func (k *kernelDataplane) configure(cfg tswg.Config) error {
	k.nlMu.Lock()
	defer k.nlMu.Unlock()
	return k.nl.ConfigureDevice(k.ifname, cfg)
}

// readCounters dumps the kernel device, records each peer's status, and
// tells magicsock about peers whose traffic counters moved.
func (k *kernelDataplane) readCounters() error {
	k.nlMu.Lock()
	d, err := k.nl.Device(k.ifname)
	k.nlMu.Unlock()
	if err != nil {
		return err
	}
	if d.ListenPort != 0 {
		k.kernelPort.Store(uint32(d.ListenPort))
	}
	type activity struct {
		pk     key.NodePublic
		tx, rx bool
	}
	var acts []activity
	var newSessions []key.NodePublic
	status := make([]ipnstate.PeerStatusLite, 0, len(d.Peers))
	k.mu.Lock()
	for _, p := range d.Peers {
		if p.LastHandshake.After(k.handshakes[p.PublicKey]) {
			k.handshakes[p.PublicKey] = p.LastHandshake
			newSessions = append(newSessions, p.PublicKey)
		}
		status = append(status, ipnstate.PeerStatusLite{
			NodeKey:       p.PublicKey,
			RxBytes:       int64(p.RxBytes),
			TxBytes:       int64(p.TxBytes),
			LastHandshake: p.LastHandshake,
		})
		last := k.counters[p.PublicKey]
		rx, tx := p.RxBytes != last[0], p.TxBytes != last[1]
		k.counters[p.PublicKey] = [2]uint64{p.RxBytes, p.TxBytes}
		// Only direct-path traffic bypasses magicsock; bridged traffic
		// already went through it.
		if (rx || tx) && !p.Endpoint.Addr().IsLoopback() {
			acts = append(acts, activity{p.PublicKey, tx, rx})
		}
	}
	k.status = status
	k.mu.Unlock()
	for _, a := range acts {
		k.ms.NoteKernelActivity(a.pk, a.tx, a.rx)
	}
	if fn := k.priorityMsgFn.Load(); fn != nil {
		for _, pk := range newSessions {
			if msg := (*fn)(pk); len(msg) > 0 {
				k.sendIPPacket(msg)
			}
		}
	}
	return nil
}

// peerStatuses returns the kernel's per-peer status as of the last
// reconcile.
func (k *kernelDataplane) peerStatuses() []ipnstate.PeerStatusLite {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.status)
}
