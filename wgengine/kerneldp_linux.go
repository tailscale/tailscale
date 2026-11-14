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

	"github.com/tailscale/netlink"
	"golang.org/x/sys/unix"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tstun"
	"tailscale.com/tsconst"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/set"
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
// Nothing polls. A single reconcile goroutine applies all changes to the
// kernel's peers, when kicked: a full sync of the peer set against
// magicsock's peers and the live per-peer config (on config and key
// changes), a peer's endpoint (when magicsock reports that its kernel path
// changed: direct and trusted, or not), and session clears (when a peer
// restarted). Peer events from the kernel (new sessions, and rate-limited
// traffic notices) drive the disco key advertisements that wireguard-go
// sends on new sessions, and feed direct-path traffic back to magicsock so
// that it keeps heartbeating active sessions.
type kernelDataplane struct {
	logf         logger.Logf
	ifname       string
	peerConfigFn *atomic.Pointer[func(key.NodePublic) (wgcfg.PeerConfig, bool)]
	peerByIPFn   atomic.Pointer[func(netip.Addr) (key.NodePublic, bool)] // see setPeerByIPFunc
	kick         chan struct{}                                           // buffered(1); wakes the reconcile loop
	ifindex      int                                                     // the device's interface index; set by start

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

	events *tswg.EventConn // set by start

	mu         sync.Mutex
	privKey    key.NodePrivate                    // desired private key
	pushedPriv key.NodePrivate                    // private key last pushed to the kernel
	pushed     map[key.NodePublic]kernelPeerState // peer state last pushed to the kernel
	ipOwner    map[netip.Addr]key.NodePublic      // the pushed peer with each pushed peer's addr; see peerAddr
	loopAddr   map[key.NodePublic]netip.Addr      // peer's bridge address
	loopPeer   map[netip.Addr]key.NodePublic      // inverse of loopAddr
	nextLoop   uint32                             // next index for loopAddr

	// Work for the reconcile loop, which clears these as it takes them.
	wantFullSync  bool
	dirtyPaths    set.Set[key.NodePublic] // peers whose kernel path may have changed
	dirtyConfigs  set.Set[key.NodePublic] // peers whose config may have changed; see syncPeer
	pendingClears set.Set[key.NodePublic] // peers whose sessions to clear
}

// kernelPeerState is the state of one kernel peer that the reconcile loop
// manages.
type kernelPeerState struct {
	endpoint   netip.AddrPort
	allowedIPs []netip.Prefix // sorted
	psk        [32]byte
	hybrid     bool // hybrid post-quantum handshakes; see wgcfg.PeerConfig.Hybrid
}

func (s kernelPeerState) equal(o kernelPeerState) bool {
	return s.endpoint == o.endpoint && s.psk == o.psk && s.hybrid == o.hybrid &&
		slices.Equal(s.allowedIPs, o.allowedIPs)
}

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
		ipOwner:      map[netip.Addr]key.NodePublic{},
		loopAddr:     map[key.NodePublic]netip.Addr{},
		loopPeer:     map[netip.Addr]key.NodePublic{},
		wantFullSync: true,
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
	k.ifindex = link.Attrs().Index

	k.events, err = tswg.OpenEvents()
	if err != nil {
		k.bridge.Close()
		nl.Close()
		return err
	}
	ms.SetKernelPathHook(k.notePathChange)

	k.ipSocks, err = k.openIPSockets()
	if err != nil {
		k.events.Close()
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
	go k.readEvents()
	go k.reconcileLoop()
	k.kickReconcile()
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
	k.events.Close()
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
	k.wantFullSync = true
	k.mu.Unlock()
	k.kickReconcile()
}

// syncPeers makes the reconcile loop sync the kernel's peers with
// magicsock's peers and the live per-peer config.
func (k *kernelDataplane) syncPeers() {
	k.mu.Lock()
	k.wantFullSync = true
	k.mu.Unlock()
	k.kickReconcile()
}

// setPeerByIPFunc sets the function that returns the peer that owns an IP
// address now, which syncPeerSet uses to turn a key rotation's removal of
// the old key into a rename.
func (k *kernelDataplane) setPeerByIPFunc(fn func(netip.Addr) (key.NodePublic, bool)) {
	if fn == nil {
		k.peerByIPFn.Store(nil)
		return
	}
	k.peerByIPFn.Store(&fn)
}

// peerAddr returns the first single address of st's allowed IPs, which for
// a Tailscale peer is its Tailscale IP: what stays the same when it rotates
// its key. ok is false if it has none.
func (st kernelPeerState) peerAddr() (_ netip.Addr, ok bool) {
	for _, p := range st.allowedIPs {
		if p.IsSingleIP() {
			return p.Addr(), true
		}
	}
	return netip.Addr{}, false
}

// setPushedLocked records st as pushed for pk, or with ok false, pk as
// removed, keeping k.ipOwner in step. k.mu must be held.
func (k *kernelDataplane) setPushedLocked(pk key.NodePublic, st kernelPeerState, ok bool) {
	if old, had := k.pushed[pk]; had {
		if a, ok := old.peerAddr(); ok && k.ipOwner[a] == pk {
			delete(k.ipOwner, a)
		}
	}
	if !ok {
		delete(k.pushed, pk)
		return
	}
	k.pushed[pk] = st
	if a, ok := st.peerAddr(); ok {
		k.ipOwner[a] = pk
	}
}

// syncPeer makes the reconcile loop sync just the peer with key pk: add,
// update or remove it in the kernel, as its live config and magicsock say.
// Netmap changes come as calls for each changed peer, so a full sync for
// each, walking every peer, was O(N^2) for a netmap of N changes.
func (k *kernelDataplane) syncPeer(pk key.NodePublic) {
	k.mu.Lock()
	k.dirtyConfigs.Make()
	k.dirtyConfigs.Add(pk)
	k.mu.Unlock()
	k.kickReconcile()
}

// notePathChange is magicsock's kernel path hook: the kernel path of the
// peer with key pk may have changed.
func (k *kernelDataplane) notePathChange(pk key.NodePublic) {
	k.mu.Lock()
	k.dirtyPaths.Make()
	k.dirtyPaths.Add(pk)
	k.mu.Unlock()
	k.kickReconcile()
}

// clearSession makes the kernel forget its session with the peer with key
// pk, so that the next packet to the peer starts a new handshake. It's the
// kernel equivalent of wireguard-go's ScheduleHandshakeOnUserSend, for when
// the peer restarted and lost its keys. It's applied asynchronously by the
// reconcile loop, since callers hold LocalBackend locks that a full sync
// needs.
func (k *kernelDataplane) clearSession(pk key.NodePublic) {
	k.mu.Lock()
	k.pendingClears.Make()
	k.pendingClears.Add(pk)
	k.mu.Unlock()
	k.kickReconcile()
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
	for {
		select {
		case <-k.ctx.Done():
			return
		case <-k.kick:
		}
		k.mu.Lock()
		full := k.wantFullSync
		dirty, clears, configs := k.dirtyPaths, k.pendingClears, k.dirtyConfigs
		k.wantFullSync, k.dirtyPaths, k.pendingClears, k.dirtyConfigs = false, nil, nil, nil
		k.mu.Unlock()

		if full {
			if err := k.fullSync(); err != nil {
				k.logf("syncing peers: %v", err)
			}
			dirty, configs = nil, nil // a full sync also updates every peer
		}
		if len(configs) > 0 {
			if err := k.syncPeerSet(configs); err != nil {
				k.logf("syncing peers: %v", err)
			}
		}
		if len(dirty) > 0 || len(clears) > 0 {
			if err := k.updatePeers(dirty, clears); err != nil {
				k.logf("updating peers: %v", err)
			}
		}
	}
}

// fullSync pushes the desired private key and peers to the kernel.
func (k *kernelDataplane) fullSync() error {
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
		wants = append(wants, want{pk: p.Key, conf: conf, st: wantKernelPeerState(p, conf)})
	}

	k.mu.Lock()
	var cfg tswg.Config
	// Remember the key we push, not k.privKey after: setPrivateKey can
	// change it while we push, and then it would look pushed when it isn't.
	pushPriv := k.privKey
	if !pushPriv.Equal(k.pushedPriv) {
		cfg.PrivateKey = &pushPriv
	}
	desired := make(map[key.NodePublic]kernelPeerState, len(wants))
	added := map[netip.Addr]key.NodePublic{} // new peers, by peerAddr
	var peers []tswg.PeerConfig
	for _, w := range wants {
		w.st.endpoint = k.endpointLocked(w.pk, w.st.endpoint)
		desired[w.pk] = w.st
		old, ok := k.pushed[w.pk]
		if ok && old.equal(w.st) {
			continue
		}
		if a, hasAddr := w.st.peerAddr(); !ok && hasAddr {
			added[a] = w.pk
		}
		peers = append(peers, w.st.peerConfig(w.pk))
	}
	// A removed peer whose Tailscale IP a new one has rotated its key:
	// rename it in the kernel rather than removing it and adding the new
	// one; see syncPeerSet.
	renamed := set.Set[key.NodePublic]{}
	var renames []tswg.PeerConfig
	for pk, st := range k.pushed {
		if _, ok := desired[pk]; ok {
			continue
		}
		if a, ok := st.peerAddr(); ok {
			if npk, ok := added[a]; ok {
				k.logf("peer %v rotated its key to %v", pk.ShortString(), npk.ShortString())
				pc := desired[npk].peerConfig(npk)
				pc.PublicKey, pc.UpdateOnly, pc.NewPublicKey = pk, true, &npk
				renames = append(renames, pc)
				renamed.Add(npk)
				continue
			}
		}
		peers = append(peers, tswg.PeerConfig{PublicKey: pk, Remove: true})
	}
	if len(renames) > 0 {
		peers = slices.DeleteFunc(peers, func(p tswg.PeerConfig) bool {
			return !p.Remove && renamed.Contains(p.PublicKey)
		})
		peers = append(renames, peers...)
	}
	k.mu.Unlock()

	if cfg.PrivateKey == nil && len(peers) == 0 {
		return nil
	}
	// Push the changes, in chunks.
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
	k.pushedPriv = pushPriv
	k.pushed = map[key.NodePublic]kernelPeerState{}
	k.ipOwner = map[netip.Addr]key.NodePublic{}
	for pk, st := range desired {
		k.setPushedLocked(pk, st, true)
	}
	k.mu.Unlock()
	return k.refreshListenPort()
}

// wantKernelPeerState returns the kernel state wanted for the peer with
// magicsock path p and config conf. Its endpoint is p's direct one, which
// the caller must still map with endpointLocked.
func wantKernelPeerState(p magicsock.KernelPeerPath, conf wgcfg.PeerConfig) kernelPeerState {
	ips := slices.Clone(conf.AllowedIPs)
	slices.SortFunc(ips, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return kernelPeerState{
		endpoint:   p.Direct,
		allowedIPs: ips,
		psk:        conf.PresharedKey,
		hybrid:     conf.Hybrid,
	}
}

// peerConfig returns the tswg config that sets peer pk to st.
func (st kernelPeerState) peerConfig(pk key.NodePublic) tswg.PeerConfig {
	psk, hybrid, noRoam := st.psk, st.hybrid, true
	return tswg.PeerConfig{
		PublicKey:         pk,
		Endpoint:          st.endpoint,
		ReplaceAllowedIPs: true,
		AllowedIPs:        st.allowedIPs,
		PresharedKey:      &psk,
		NoRoam:            &noRoam,
		Hybrid:            &hybrid,
	}
}

// syncPeerSet syncs just the peers in pks with the kernel, as fullSync does
// all of them: each is wanted in the kernel if magicsock has it and the
// config source has a config for it. Its work is O(1) per peer.
//
// A peer that rotated its key comes as the removal of the old key and the
// addition of the new, in either order, perhaps in different calls. Doing
// them as such would drop the peer's traffic in between, so they're one
// atomic rename in the kernel (tswg.PeerConfig.NewPublicKey) instead,
// matched by the peer's Tailscale IP (see peerAddr): an addition whose IP
// a no-longer-wanted peer has renames that one, and a removal whose IP a
// new peer has now (by peerByIPFn) renames it to that one.
func (k *kernelDataplane) syncPeerSet(pks set.Set[key.NodePublic]) error {
	fn := k.peerConfigFn.Load()
	if fn == nil {
		return nil
	}
	// wanted returns pk's wanted state, if it's wanted.
	wanted := func(pk key.NodePublic) (kernelPeerState, bool) {
		path, inMagicsock := k.ms.KernelPeerPath(pk)
		conf, ok := (*fn)(pk)
		if !inMagicsock || !ok {
			return kernelPeerState{}, false
		}
		return wantKernelPeerState(path, conf), true
	}
	byIP := k.peerByIPFn.Load()
	var peers []tswg.PeerConfig
	for pk := range pks {
		st, want := wanted(pk)
		// For a rename, the other key and its wanted state; found
		// without k.mu, since the config source takes other locks.
		var from, to key.NodePublic
		var toState kernelPeerState
		k.mu.Lock()
		_, pushed := k.pushed[pk]
		if a, ok := st.peerAddr(); want && !pushed && ok {
			if owner, ok := k.ipOwner[a]; ok && owner != pk {
				from = owner
			}
		}
		old := k.pushed[pk]
		k.mu.Unlock()
		if !from.IsZero() {
			if _, ok := wanted(from); ok {
				from = key.NodePublic{} // both wanted: not a rotation
			}
		}
		if !want && pushed && byIP != nil {
			if a, ok := old.peerAddr(); ok {
				if np, ok := (*byIP)(a); ok && np != pk {
					if s, ok := wanted(np); ok {
						to, toState = np, s
					}
				}
			}
		}

		k.mu.Lock()
		switch {
		case !from.IsZero(): // pk is the new key of pushed peer from
			if _, still := k.pushed[from]; !still {
				from = key.NodePublic{}
			}
		case !to.IsZero(): // pk is the old key of to, not yet pushed
			if _, already := k.pushed[to]; already {
				to = key.NodePublic{}
			}
		}
		switch {
		case !from.IsZero():
			st.endpoint = k.endpointLocked(pk, st.endpoint)
			k.logf("peer %v rotated its key to %v", from.ShortString(), pk.ShortString())
			pc := st.peerConfig(pk)
			pc.PublicKey, pc.UpdateOnly, pc.NewPublicKey = from, true, &pk
			peers = append(peers, pc)
			k.setPushedLocked(from, kernelPeerState{}, false)
			k.setPushedLocked(pk, st, true)
		case !to.IsZero():
			toState.endpoint = k.endpointLocked(to, toState.endpoint)
			k.logf("peer %v rotated its key to %v", pk.ShortString(), to.ShortString())
			pc := toState.peerConfig(to)
			pc.PublicKey, pc.UpdateOnly, pc.NewPublicKey = pk, true, &to
			peers = append(peers, pc)
			k.setPushedLocked(pk, kernelPeerState{}, false)
			k.setPushedLocked(to, toState, true)
		case want:
			st.endpoint = k.endpointLocked(pk, st.endpoint)
			if !pushed || !old.equal(st) {
				peers = append(peers, st.peerConfig(pk))
				k.setPushedLocked(pk, st, true)
			}
		case pushed:
			peers = append(peers, tswg.PeerConfig{PublicKey: pk, Remove: true})
			k.setPushedLocked(pk, kernelPeerState{}, false)
		}
		k.mu.Unlock()
	}
	for len(peers) > 0 {
		n := min(len(peers), kernelMaxPeersPerMessage)
		if err := k.configure(tswg.Config{Peers: peers[:n]}); err != nil {
			// The kernel may now differ from k.pushed; the next full
			// sync puts it right.
			k.mu.Lock()
			k.wantFullSync = true
			k.mu.Unlock()
			return err
		}
		peers = peers[n:]
	}
	return nil
}

// updatePeers updates the kernel endpoints of the peers in dirty and clears
// the sessions of the peers in clears (also updating their endpoints, since
// a restarted peer usually has a new port too, and its new handshake
// should go out on its new path).
func (k *kernelDataplane) updatePeers(dirty, clears set.Set[key.NodePublic]) error {
	var peers []tswg.PeerConfig
	var missing []key.NodePublic
	for pk := range set.Of(slices.Concat(dirty.Slice(), clears.Slice())...) {
		path, _ := k.ms.KernelPeerPath(pk)
		k.mu.Lock()
		st, ok := k.pushed[pk]
		if !ok {
			k.mu.Unlock()
			// Not in the kernel (yet): perhaps magicsock just added
			// it, after its SyncDevicePeer; sync its config.
			missing = append(missing, pk)
			continue
		}
		ep := k.endpointLocked(pk, path.Direct)
		changed := ep != st.endpoint
		st.endpoint = ep
		k.pushed[pk] = st
		k.mu.Unlock()
		clear := clears.Contains(pk)
		if !changed && !clear {
			continue
		}
		if changed {
			if path.Direct.IsValid() {
				k.logf("peer %v: kernel now sends directly to %v", pk.ShortString(), ep)
			} else {
				k.logf("peer %v: kernel now sends via the loopback bridge", pk.ShortString())
			}
		}
		if clear {
			k.logf("clearing session with %v", pk.ShortString())
		}
		peers = append(peers, tswg.PeerConfig{
			PublicKey:    pk,
			UpdateOnly:   true,
			Endpoint:     ep,
			ClearSession: clear,
		})
	}
	for len(peers) > 0 {
		n := min(len(peers), kernelMaxPeersPerMessage)
		if err := k.configure(tswg.Config{Peers: peers[:n]}); err != nil {
			return err
		}
		peers = peers[n:]
	}
	if len(missing) > 0 {
		return k.syncPeerSet(set.Of(missing...))
	}
	return nil
}

func (k *kernelDataplane) configure(cfg tswg.Config) error {
	k.nlMu.Lock()
	defer k.nlMu.Unlock()
	return k.nl.ConfigureDevice(k.ifname, cfg)
}

// refreshListenPort records the kernel device's listen port, which is
// where the bridge injects packets. It's normally the port of magicsock's
// shared socket (which setSocket records), but if magicsock has no UDP
// socket, the kernel opens its own on a random port.
func (k *kernelDataplane) refreshListenPort() error {
	k.nlMu.Lock()
	d, err := k.nl.Device(k.ifname)
	k.nlMu.Unlock()
	if err != nil {
		return err
	}
	if d.ListenPort != 0 {
		k.kernelPort.Store(uint32(d.ListenPort))
	}
	return nil
}

// readEvents handles the kernel's peer events.
func (k *kernelDataplane) readEvents() {
	for {
		evs, err := k.events.Receive()
		if err != nil {
			if k.ctx.Err() != nil {
				return
			}
			if errors.Is(err, unix.ENOBUFS) {
				// Events were lost. The ones that matter are
				// rate-limited traffic notices, which recur, and
				// new sessions, whose disco key advertisements are
				// an optimization.
				k.logf("kernel peer events overrun; some were lost")
				continue
			}
			k.logf("reading kernel peer events: %v", err)
			return
		}
		for _, ev := range evs {
			if ev.IfIndex == k.ifindex {
				k.handleEvent(ev)
			}
		}
	}
}

func (k *kernelDataplane) handleEvent(ev tswg.Event) {
	if ev.Session {
		if fn := k.priorityMsgFn.Load(); fn != nil {
			if msg := (*fn)(ev.PublicKey); len(msg) > 0 {
				k.sendIPPacket(msg)
			}
		}
	}
	if ev.TX || ev.RX {
		// Only direct-path traffic bypasses magicsock; bridged traffic
		// already went through it.
		k.mu.Lock()
		st, ok := k.pushed[ev.PublicKey]
		k.mu.Unlock()
		if ok && !st.endpoint.Addr().IsLoopback() {
			k.ms.NoteKernelActivity(ev.PublicKey, ev.TX, ev.RX)
		}
	}
}

// peerStatuses returns the kernel's per-peer status.
func (k *kernelDataplane) peerStatuses() []ipnstate.PeerStatusLite {
	k.nlMu.Lock()
	d, err := k.nl.Device(k.ifname)
	k.nlMu.Unlock()
	if err != nil {
		k.logf("getting peer status: %v", err)
		return nil
	}
	status := make([]ipnstate.PeerStatusLite, 0, len(d.Peers))
	for _, p := range d.Peers {
		status = append(status, ipnstate.PeerStatusLite{
			NodeKey:       p.PublicKey,
			RxBytes:       int64(p.RxBytes),
			TxBytes:       int64(p.TxBytes),
			LastHandshake: p.LastHandshake,
		})
	}
	return status
}
