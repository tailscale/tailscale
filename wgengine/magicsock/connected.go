// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/net/batching"
	"tailscale.com/net/netns"
	"tailscale.com/net/tstun"
	"tailscale.com/syncs"
	"tailscale.com/types/nettype"
	"tailscale.com/util/clientmetric"
)

var (
	metricSendUDPConnected = clientmetric.NewCounter("magicsock_send_udp_connected")
	metricRecvUDPConnected = clientmetric.NewCounter("magicsock_recv_udp_connected")
)

// useConnectedSockets reports whether direct UDP paths use per-peer connected sockets alongside pconn4 and pconn6. It needs pconn4 to be a real OS socket, which a simulated network's is not.
func (c *Conn) useConnectedSockets() bool {
	if !debugConnectedSockets() {
		return false
	}
	_, ok := c.pconn4.currentConn().(syscall.Conn)
	return ok
}

// sendConnected sends buffs to addr on its connected socket, reporting whether it did; false means send on pconn4 or pconn6 as usual. Peer relay paths are left alone, since their Geneve encapsulation belongs to the shared socket.
func (c *Conn) sendConnected(addr epAddr, buffs [][]byte, offset int) (bool, error) {
	if addr.vni.IsSet() {
		return false, nil
	}
	handled, err := c.connectedFor(addr.ap).Send(addr.ap, buffs, offset)
	if handled && err == nil {
		metricSendUDPConnected.Add(int64(len(buffs)))
	}
	return handled, err
}

// testConnectedOpenAfter, when non-zero, replaces conn.DefaultOpenAfter, so that tests exchanging a few packets see connected sockets open.
var testConnectedOpenAfter int

/*
localPairs opens connected sockets for the address pairs peers send to us on, not only the ones we send on.

The two ends of a path can pick different pairs: a peer may send from an address we do not send to, or to one of our addresses (IPv6 addresses are many and rotate) that our send socket is not bound to. That traffic reaches only pconn4 or pconn6 until a socket for its exact pair exists.

Only known peers count, and only while connected sockets are open. Packets are counted per run of one pair within a receive batch, so a pair that cannot open costs one lock per batch, not per packet.
*/
type localPairs struct {
	openSrc   netip.AddrPort // the last pair that opened
	openLocal netip.Addr

	src   netip.AddrPort // the run being counted
	local netip.Addr
	bytes int
}

// note counts p, which receiveIP attributed to ep, towards opening its pair.
func (lp *localPairs) note(c *Conn, p batching.ReceivedPacket, ep conn.Endpoint) {
	if !p.Local.IsValid() || (p.Source == lp.openSrc && p.Local == lp.openLocal) {
		return
	}
	if _, known := ep.(*endpoint); !known {
		return
	}
	if p.Source != lp.src || p.Local != lp.local {
		lp.flush(c)
		lp.src, lp.local = p.Source, p.Local
	}
	lp.bytes += p.Size
}

// flush passes the run counted so far to Dial. Call it at the end of every receive batch.
func (lp *localPairs) flush(c *Conn) {
	if lp.bytes == 0 {
		return
	}
	if cs := c.connectedFor(lp.src); cs != nil && cs.Dial(lp.src, lp.local, lp.bytes) {
		lp.openSrc, lp.openLocal = lp.src, lp.local // open: nothing more to count for this pair
	}
	lp.bytes = 0
}

// wantLocalAddr reports whether pconn4 and pconn6 should report each packet's local address: whenever connected sockets are on, since a connected socket only receives what is sent to the local address connect chose.
func wantLocalAddr() bool {
	return debugConnectedSockets()
}

// reportLocalAddr asks pc to report the local address of each packet it receives, when wantLocalAddr.
func reportLocalAddr(pc nettype.PacketConn, network string) {
	p, ok := pc.(net.PacketConn)
	if !ok || !wantLocalAddr() {
		return
	}
	if network == "udp4" {
		ipv4.NewPacketConn(p).SetControlMessage(ipv4.FlagDst, true)
	} else {
		ipv6.NewPacketConn(p).SetControlMessage(ipv6.FlagDst, true)
	}
}

// readOne reads one packet from pconn and, when wantLocalAddr, the local address it was sent to. It retries across a rebind, as readFromWithInitPconn does.
func (c *RebindingUDPConn) readOne(pconn nettype.PacketConn, b []byte) (int, netip.AddrPort, netip.Addr, error) {
	if !wantLocalAddr() {
		n, ap, err := c.readFromWithInitPconn(pconn, b)
		return n, ap, netip.Addr{}, err
	}
	if c.oob == nil {
		c.oob = make([]byte, 128)
	}
	for {
		n, ap, local, err := readWithLocalAddr(pconn, b, c.oob)
		if err != nil && pconn != c.currentConn() {
			pconn = *c.pconnAtomic.Load()
			continue
		}
		return n, ap, local, err
	}
}

// readWithLocalAddr reads one packet and, from its control message, the local address it was sent to.
func readWithLocalAddr(pconn nettype.PacketConn, b, oob []byte) (int, netip.AddrPort, netip.Addr, error) {
	uc, ok := pconn.(*net.UDPConn)
	if !ok {
		n, ap, err := pconn.ReadFromUDPAddrPort(b)
		return n, ap, netip.Addr{}, err
	}
	n, oobn, _, ap, err := uc.ReadMsgUDPAddrPort(b, oob)
	if err != nil || oobn == 0 {
		return n, ap, netip.Addr{}, err
	}
	var dst net.IP
	if ap.Addr().Unmap().Is4() {
		var cm ipv4.ControlMessage
		if cm.Parse(oob[:oobn]) == nil {
			dst = cm.Dst
		}
	} else {
		var cm ipv6.ControlMessage
		if cm.Parse(oob[:oobn]) == nil {
			dst = cm.Dst
		}
	}
	local, _ := netip.AddrFromSlice(dst)
	return n, ap, local.Unmap(), nil
}

// openConnected creates the per-family connected socket sets on pconn4's and pconn6's ports. Sockets are read by receive routines the device starts through connBind's starter; without one, connected sockets stay off.
func (c *Conn) openConnected() {
	start := c.connectedStarter
	if start == nil || !c.useConnectedSockets() {
		return
	}
	// The same netns Control as pconn4 and pconn6, so a connected socket routes like the shared socket (on darwin netns pins sockets to an interface). Test listeners get none.
	var base func(network, address string, c syscall.RawConn) error
	if c.testOnlyPacketListener == nil {
		base = netns.Listener(c.logf, c.netMon).Control
	}
	ctl := func(network, address string, rc syscall.RawConn) error {
		if base != nil {
			if err := base(network, address, rc); err != nil {
				return err
			}
		}
		return c.copyDontFragment(network, rc)
	}
	// With path MTU discovery on, start with slots large enough for its probes (up to a 9000-byte wire MTU) instead of dropping the first ones while the slots grow.
	maxDatagram := 0
	if c.ShouldPMTUD() {
		maxDatagram = int(tstun.WireMTUsToProbe[len(tstun.WireMTUsToProbe)-1])
	}
	for _, f := range []struct {
		ruc *RebindingUDPConn
		set *syncs.AtomicValue[*conn.ConnectedSockets]
		fn  func(batchReader) conn.ReceiveFunc
	}{
		{&c.pconn4, &c.connected4, c.receiveConnected4},
		{&c.pconn6, &c.connected6, c.receiveConnected6},
	} {
		// A family that is not bound yet has port 0, and its set takes nothing until a rebind binds the family and rebindConnected passes the port on.
		// The device runs a receive routine per socket, reading into its slabs through the same receiveIP path as the shared sockets.
		fn := f.fn
		cs := conn.NewConnectedSockets(conn.ConnectedConfig{Port: int(f.ruc.Port()), Control: ctl, MaxDatagram: maxDatagram, OpenAfter: testConnectedOpenAfter,
			Reader: func(read conn.ConnectedReadFunc, slabSize, batchSize int) bool {
				return start(fn(&connectedReader{read: read}), slabSize, batchSize)
			}})
		if cs == nil {
			return // unsupported on this platform
		}
		f.set.Store(cs)
	}
}

// closeConnected closes both sets, unblocking their ReceiveFuncs.
func (c *Conn) closeConnected() {
	for _, set := range []*syncs.AtomicValue[*conn.ConnectedSockets]{&c.connected4, &c.connected6} {
		if cs := set.Swap(nil); cs != nil {
			cs.Close()
		}
	}
}

// rebindConnected redials connected sockets after pconn4 and pconn6 are rebound, or after anything their Control copies has changed. An unbound family passes port 0, so its set takes nothing.
func (c *Conn) rebindConnected() {
	if cs := c.connected4.Load(); cs != nil {
		cs.Rebind(int(c.pconn4.Port()))
	}
	if cs := c.connected6.Load(); cs != nil {
		cs.Rebind(int(c.pconn6.Port()))
	}
}

// connectedFor returns the set for dst's address family, or nil.
func (c *Conn) connectedFor(dst netip.AddrPort) *conn.ConnectedSockets {
	if dst.Addr().Is4() {
		return c.connected4.Load()
	}
	return c.connected6.Load()
}

// reusePortControl lets pconn4 and pconn6 share their ports with the connected sockets.
func reusePortControl(base func(network, address string, c syscall.RawConn) error) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, rc syscall.RawConn) error {
		if base != nil {
			if err := base(network, address, rc); err != nil {
				return err
			}
		}
		return conn.ReusePortControl(network, address, rc)
	}
}

func (c *Conn) receiveConnected4(r batchReader) conn.ReceiveFunc {
	return c.mkReceiveFunc(r, nil,
		&c.metrics.inboundPacketsIPv4Total,
		&c.metrics.inboundPacketsPeerRelayIPv4Total,
		&c.metrics.inboundBytesIPv4Total,
		&c.metrics.inboundBytesPeerRelayIPv4Total,
	)
}

func (c *Conn) receiveConnected6(r batchReader) conn.ReceiveFunc {
	return c.mkReceiveFunc(r, nil,
		&c.metrics.inboundPacketsIPv6Total,
		&c.metrics.inboundPacketsPeerRelayIPv6Total,
		&c.metrics.inboundBytesIPv6Total,
		&c.metrics.inboundBytesPeerRelayIPv6Total,
	)
}

// batchReader is what mkReceiveFunc reads from: a RebindingUDPConn, or one connected socket through a connectedReader.
type batchReader interface {
	ReadBatch(slab []byte, packets []batching.ReceivedPacket) (int, error)
}

// SetReceiveFuncStarter implements [conn.ReceiveFuncStarter]. Connected sockets need it: each is read by a ReceiveFunc of its own that the device starts when the socket opens.
func (c *connBind) SetReceiveFuncStarter(start func(fn conn.ReceiveFunc, slabSize, batchSize int) bool) {
	c.mu.Lock()
	c.connectedStarter = start
	c.mu.Unlock()
}

// connectedReader adapts one connected socket's ConnectedReadFunc to the batch reader mkReceiveFunc reads from.
type connectedReader struct {
	read conn.ConnectedReadFunc
	pkts []conn.ConnectedPacket
}

func (r *connectedReader) ReadBatch(slab []byte, packets []batching.ReceivedPacket) (int, error) {
	if len(r.pkts) < len(packets) {
		r.pkts = make([]conn.ConnectedPacket, len(packets))
	}
	n, err := r.read(slab, r.pkts[:len(packets)])
	metricRecvUDPConnected.Add(int64(n))
	for i, p := range r.pkts[:n] {
		packets[i] = batching.ReceivedPacket{Offset: p.Offset, Size: p.Size, Source: p.Source}
	}
	return n, err
}
