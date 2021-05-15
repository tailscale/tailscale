// Copyright (c) 2019 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magicsock

import (
	"bytes"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/tai64n"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
	"inet.af/netaddr"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/wgkey"
	"tailscale.com/wgengine/wgcfg"
)

var (
	errNoDestinations = errors.New("magicsock: no destinations")
	errDisabled       = errors.New("magicsock: legacy networking disabled")
)

// createLegacyEndpointLocked creates a new wireguard-go endpoint for a legacy connection.
// pk is the public key of the remote peer. addrs is the ordered set of addresses for the remote peer.
// rawDest is the encoded wireguard-go endpoint string. It should be treated as a black box.
// It is provided so that addrSet.DstToString can return it when requested by wireguard-go.
func (c *Conn) createLegacyEndpointLocked(pk key.Public, addrs wgcfg.IPPortSet, rawDest string) (conn.Endpoint, error) {
	if c.disableLegacy {
		return nil, errDisabled
	}

	a := &addrSet{
		Logf:      c.logf,
		publicKey: pk,
		curAddr:   -1,
		rawdst:    rawDest,
	}
	a.ipPorts = append(a.ipPorts, addrs.IPPorts()...)

	// If this endpoint is being updated, remember its old set of
	// endpoints so we can remove any (from c.addrsByUDP) that are
	// not in the new set.
	var oldIPP []netaddr.IPPort
	if preva, ok := c.addrsByKey[pk]; ok {
		oldIPP = preva.ipPorts
	}
	c.addrsByKey[pk] = a

	// Add entries to c.addrsByUDP.
	for _, ipp := range a.ipPorts {
		if ipp.IP() == derpMagicIPAddr {
			continue
		}
		c.addrsByUDP[ipp] = a
	}

	// Remove previous c.addrsByUDP entries that are no longer in the new set.
	for _, ipp := range oldIPP {
		if ipp.IP() != derpMagicIPAddr && c.addrsByUDP[ipp] != a {
			delete(c.addrsByUDP, ipp)
		}
	}

	return a, nil
}

func (c *Conn) findLegacyEndpointLocked(ipp netaddr.IPPort, packet []byte) conn.Endpoint {
	if c.disableLegacy {
		return nil
	}

	// Pre-disco: look up their addrSet.
	if as, ok := c.addrsByUDP[ipp]; ok {
		as.updateDst(ipp)
		return as
	}

	// We don't know who this peer is. It's possible that it's one of
	// our legitimate peers and they've roamed to an address we don't
	// know. If this is a handshake packet, we can try to identify the
	// peer in question.
	if as := c.peerFromPacketLocked(packet); as != nil {
		as.updateDst(ipp)
		return as
	}

	// We have no idea who this is, drop the packet.
	//
	// In the past, when this magicsock implementation was the main
	// one, we tried harder to find a match here: we would pass the
	// packet into wireguard-go with a "singleEndpoint" implementation
	// that wrapped the UDPAddr. Then, a patch we added to
	// wireguard-go would call UpdateDst on that singleEndpoint after
	// decrypting the packet and identifying the peer (if any),
	// allowing us to update the relevant addrSet.
	//
	// This was a significant out of tree patch to wireguard-go, so we
	// got rid of it, and instead switched to this logic you're
	// reading now, which makes a best effort to identify sources for
	// handshake packets (because they're relatively easy to turn into
	// a peer public key statelessly), but otherwise drops packets
	// that come from "roaming" addresses that aren't known to
	// magicsock.
	//
	// The practical consequence of this is that some complex NAT
	// traversal cases will now fail between a very old Tailscale
	// client (0.96 and earlier) and a very new Tailscale
	// client. However, those scenarios were likely also failing on
	// all-old clients, because the probabilistic NAT opening didn't
	// work reliably. So, in practice, this simplification means
	// connectivity looks like this:
	//
	//  - old+old client: unchanged
	//  - old+new client (easy network topology): unchanged
	//  - old+new client (hard network topology): was bad, now a bit worse
	//  - new+new client: unchanged
	//
	// This degradation is acceptable in that it continues to support
	// the incremental upgrade of old clients that currently work
	// well, which is our primary goal for the <100 clients still left
	// on the oldest pre-DERP versions (as of 2021-01-12).
	return nil
}

func (c *Conn) resetAddrSetStatesLocked() {
	for _, as := range c.addrsByKey {
		as.curAddr = -1
		as.stopSpray = as.timeNow().Add(sprayPeriod)
	}
}

func (c *Conn) sendAddrSet(b []byte, as *addrSet) error {
	if c.disableLegacy {
		return errDisabled
	}

	var addrBuf [8]netaddr.IPPort
	dsts, roamAddr := as.appendDests(addrBuf[:0], b)

	if len(dsts) == 0 {
		return errNoDestinations
	}

	var success bool
	var ret error
	for _, addr := range dsts {
		sent, err := c.sendAddr(addr, as.publicKey, b)
		if sent {
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

// peerFromPacketLocked extracts returns the addrSet for the peer who sent
// packet, if derivable.
//
// The derived addrSet is a hint, not a cryptographically strong
// assertion. The returned value MUST NOT be used for any security
// critical function. Callers MUST assume that the addrset can be
// picked by a remote attacker.
func (c *Conn) peerFromPacketLocked(packet []byte) *addrSet {
	if len(packet) < 4 {
		return nil
	}
	msgType := binary.LittleEndian.Uint32(packet[:4])
	if msgType != messageInitiationType {
		// Can't get peer out of a non-handshake packet.
		return nil
	}

	var msg messageInitiation
	reader := bytes.NewReader(packet)
	err := binary.Read(reader, binary.LittleEndian, &msg)
	if err != nil {
		return nil
	}

	// Process just enough of the handshake to extract the long-term
	// peer public key. We don't verify the handshake all the way, so
	// this may be a spoofed packet. The extracted peer MUST NOT be
	// used for any security critical function. In our case, we use it
	// as a hint for roaming addresses.
	var (
		pub      = c.privateKey.Public()
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
		peerPK   key.Public
		boxKey   [chacha20poly1305.KeySize]byte
	)

	mixHash(&hash, &initialHash, pub[:])
	mixHash(&hash, &hash, msg.Ephemeral[:])
	mixKey(&chainKey, &initialChainKey, msg.Ephemeral[:])

	ss := c.privateKey.SharedSecret(key.Public(msg.Ephemeral))
	if isZero(ss[:]) {
		return nil
	}

	kdf2(&chainKey, &boxKey, chainKey[:], ss[:])
	aead, _ := chacha20poly1305.New(boxKey[:])
	_, err = aead.Open(peerPK[:0], zeroNonce[:], msg.Static[:], hash[:])
	if err != nil {
		return nil
	}

	return c.addrsByKey[peerPK]
}

func shouldSprayPacket(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	msgType := binary.LittleEndian.Uint32(b[:4])
	switch msgType {
	case messageInitiationType,
		messageResponseType,
		messageCookieReplyType: // TODO: necessary?
		return true
	}
	return false
}

const sprayPeriod = 3 * time.Second

// appendDests appends to dsts the destinations that b should be
// written to in order to reach as. Some of the returned IPPorts may
// be fake addrs representing DERP servers.
//
// It also returns as's current roamAddr, if any.
func (as *addrSet) appendDests(dsts []netaddr.IPPort, b []byte) (_ []netaddr.IPPort, roamAddr netaddr.IPPort) {
	spray := shouldSprayPacket(b) // true for handshakes
	now := as.timeNow()

	as.mu.Lock()
	defer as.mu.Unlock()

	as.lastSend = now

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
		for i := range as.ipPorts {
			dsts = append(dsts, as.ipPorts[i])
		}
		if as.roamAddr != nil {
			dsts = append(dsts, *as.roamAddr)
		}
	case as.roamAddr != nil:
		// We have a roaming address, prefer it over other addrs.
		// TODO(danderson): this is not correct, there's no reason
		// roamAddr should be special like this.
		dsts = append(dsts, *as.roamAddr)
	case as.curAddr != -1:
		if as.curAddr >= len(as.ipPorts) {
			as.Logf("[unexpected] magicsock bug: as.curAddr >= len(as.ipPorts): %d >= %d", as.curAddr, len(as.ipPorts))
			break
		}
		// No roaming addr, but we've seen packets from a known peer
		// addr, so keep using that one.
		dsts = append(dsts, as.ipPorts[as.curAddr])
	default:
		// We know nothing about how to reach this peer, and we're not
		// spraying. Use the first address in the array, which will
		// usually be a DERP address that guarantees connectivity.
		if len(as.ipPorts) > 0 {
			dsts = append(dsts, as.ipPorts[0])
		}
	}

	if logPacketDests {
		as.Logf("spray=%v; roam=%v; dests=%v", spray, as.roamAddr, dsts)
	}
	if as.roamAddr != nil {
		roamAddr = *as.roamAddr
	}
	return dsts, roamAddr
}

// addrSet is a set of UDP addresses that implements wireguard/conn.Endpoint.
//
// This is the legacy endpoint for peers that don't support discovery;
// it predates discoEndpoint.
type addrSet struct {
	publicKey key.Public // peer public key used for DERP communication

	// ipPorts is an ordered priority list provided by wgengine,
	// sorted from expensive+slow+reliable at the begnining to
	// fast+cheap at the end. More concretely, it's typically:
	//
	//     [DERP fakeip:node, Global IP:port, LAN ip:port]
	//
	// But there could be multiple or none of each.
	ipPorts []netaddr.IPPort

	// clock, if non-nil, is used in tests instead of time.Now.
	clock func() time.Time
	Logf  logger.Logf // must not be nil

	mu sync.Mutex // guards following fields

	lastSend time.Time

	// roamAddr is non-nil if/when we receive a correctly signed
	// WireGuard packet from an unexpected address. If so, we
	// remember it and send responses there in the future, but
	// this should hopefully never be used (or at least used
	// rarely) in the case that all the components of Tailscale
	// are correctly learning/sharing the network map details.
	roamAddr *netaddr.IPPort

	// curAddr is an index into addrs of the highest-priority
	// address a valid packet has been received from so far.
	// If no valid packet from addrs has been received, curAddr is -1.
	curAddr int

	// stopSpray is the time after which we stop spraying packets.
	stopSpray time.Time

	// lastSpray is the last time we sprayed a packet.
	lastSpray time.Time

	// loggedLogPriMask is a bit field of that tracks whether
	// we've already logged about receiving a packet from a low
	// priority ("low-pri") address when we already have curAddr
	// set to a better one. This is only to suppress some
	// redundant logs.
	loggedLogPriMask uint32

	// rawdst is the destination string from/for wireguard-go.
	rawdst string
}

// derpID returns this addrSet's home DERP node, or 0 if none is found.
func (as *addrSet) derpID() int {
	for _, ua := range as.ipPorts {
		if ua.IP() == derpMagicIPAddr {
			return int(ua.Port())
		}
	}
	return 0
}

func (as *addrSet) timeNow() time.Time {
	if as.clock != nil {
		return as.clock()
	}
	return time.Now()
}

var noAddr, _ = netaddr.FromStdAddr(net.ParseIP("127.127.127.127"), 127, "")

func (a *addrSet) dst() netaddr.IPPort {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.roamAddr != nil {
		return *a.roamAddr
	}
	if len(a.ipPorts) == 0 {
		return noAddr
	}
	i := a.curAddr
	if i == -1 {
		i = 0
	}
	return a.ipPorts[i]
}

func (a *addrSet) DstToBytes() []byte {
	return packIPPort(a.dst())
}
func (a *addrSet) DstToString() string {
	return a.rawdst
}
func (a *addrSet) DstIP() net.IP {
	return a.dst().IP().IPAddr().IP // TODO: add netaddr accessor to cut an alloc here?
}
func (a *addrSet) SrcIP() net.IP       { return nil }
func (a *addrSet) SrcToString() string { return "" }
func (a *addrSet) ClearSrc()           {}

// updateDst records receipt of a packet from new. This is used to
// potentially update the transmit address used for this addrSet.
func (a *addrSet) updateDst(new netaddr.IPPort) error {
	if new.IP() == derpMagicIPAddr {
		// Never consider DERP addresses as a viable candidate for
		// either curAddr or roamAddr. It's only ever a last resort
		// choice, never a preferred choice.
		// This is a hot path for established connections.
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.roamAddr != nil && new == *a.roamAddr {
		// Packet from the current roaming address, no logging.
		// This is a hot path for established connections.
		return nil
	}
	if a.roamAddr == nil && a.curAddr >= 0 && new == a.ipPorts[a.curAddr] {
		// Packet from current-priority address, no logging.
		// This is a hot path for established connections.
		return nil
	}

	index := -1
	for i := range a.ipPorts {
		if new == a.ipPorts[i] {
			index = i
			break
		}
	}

	publicKey := wgkey.Key(a.publicKey)
	pk := publicKey.ShortString()
	old := "<none>"
	if a.curAddr >= 0 {
		old = a.ipPorts[a.curAddr].String()
	}

	switch {
	case index == -1:
		if a.roamAddr == nil {
			a.Logf("[v1] magicsock: rx %s from roaming address %s, set as new priority", pk, new)
		} else {
			a.Logf("[v1] magicsock: rx %s from roaming address %s, replaces roaming address %s", pk, new, a.roamAddr)
		}
		a.roamAddr = &new

	case a.roamAddr != nil:
		a.Logf("[v1] magicsock: rx %s from known %s (%d), replaces roaming address %s", pk, new, index, a.roamAddr)
		a.roamAddr = nil
		a.curAddr = index
		a.loggedLogPriMask = 0

	case a.curAddr == -1:
		a.Logf("[v1] magicsock: rx %s from %s (%d/%d), set as new priority", pk, new, index, len(a.ipPorts))
		a.curAddr = index
		a.loggedLogPriMask = 0

	case index < a.curAddr:
		if 1 <= index && index <= 32 && (a.loggedLogPriMask&1<<(index-1)) == 0 {
			a.Logf("[v1] magicsock: rx %s from low-pri %s (%d), keeping current %s (%d)", pk, new, index, old, a.curAddr)
			a.loggedLogPriMask |= 1 << (index - 1)
		}

	default: // index > a.curAddr
		a.Logf("[v1] magicsock: rx %s from %s (%d/%d), replaces old priority %s", pk, new, index, len(a.ipPorts), old)
		a.curAddr = index
		a.loggedLogPriMask = 0
	}

	return nil
}

func (a *addrSet) String() string {
	a.mu.Lock()
	defer a.mu.Unlock()

	buf := new(strings.Builder)
	buf.WriteByte('[')
	if a.roamAddr != nil {
		buf.WriteString("roam:")
		sbPrintAddr(buf, *a.roamAddr)
	}
	for i, addr := range a.ipPorts {
		if i > 0 || a.roamAddr != nil {
			buf.WriteString(", ")
		}
		sbPrintAddr(buf, addr)
		if a.curAddr == i {
			buf.WriteByte('*')
		}
	}
	buf.WriteByte(']')

	return buf.String()
}

func (as *addrSet) populatePeerStatus(ps *ipnstate.PeerStatus) {
	as.mu.Lock()
	defer as.mu.Unlock()

	ps.LastWrite = as.lastSend
	for i, ua := range as.ipPorts {
		if ua.IP() == derpMagicIPAddr {
			continue
		}
		uaStr := ua.String()
		ps.Addrs = append(ps.Addrs, uaStr)
		if as.curAddr == i {
			ps.CurAddr = uaStr
		}
	}
	if as.roamAddr != nil {
		ps.CurAddr = ippDebugString(*as.roamAddr)
	}
}

// Message types copied from wireguard-go/device/noise-protocol.go
const (
	messageInitiationType  = 1
	messageResponseType    = 2
	messageCookieReplyType = 3
)

// Cryptographic constants copied from wireguard-go/device/noise-protocol.go
var (
	noiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	wgIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	initialChainKey   [blake2s.Size]byte
	initialHash       [blake2s.Size]byte
	zeroNonce         [chacha20poly1305.NonceSize]byte
)

func init() {
	initialChainKey = blake2s.Sum256([]byte(noiseConstruction))
	mixHash(&initialHash, &initialChainKey, []byte(wgIdentifier))
}

// messageInitiation is the same as wireguard-go's MessageInitiation,
// from wireguard-go/device/noise-protocol.go.
type messageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral wgkey.Key
	Static    [wgkey.Size + poly1305.TagSize]byte
	Timestamp [tai64n.TimestampSize + poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

func mixKey(dst *[blake2s.Size]byte, c *[blake2s.Size]byte, data []byte) {
	kdf1(dst, c[:], data)
}

func mixHash(dst *[blake2s.Size]byte, h *[blake2s.Size]byte, data []byte) {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
	hash.Reset()
}

func hmac1(sum *[blake2s.Size]byte, key, in0 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}

func hmac2(sum *[blake2s.Size]byte, key, in0, in1 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(sum[:0])
}

func kdf1(t0 *[blake2s.Size]byte, key, input []byte) {
	hmac1(t0, key, input)
	hmac1(t0, t0[:], []byte{0x1})
}

func kdf2(t0, t1 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	hmac1(&prk, key, input)
	hmac1(t0, prk[:], []byte{0x1})
	hmac2(t1, prk[:], t0[:], []byte{0x2})
	for i := range prk[:] {
		prk[i] = 0
	}
}

func isZero(val []byte) bool {
	acc := 1
	for _, b := range val {
		acc &= subtle.ConstantTimeByteEq(b, 0)
	}
	return acc == 1
}
