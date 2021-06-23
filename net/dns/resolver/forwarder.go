// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package resolver

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	dns "golang.org/x/net/dns/dnsmessage"
	"inet.af/netaddr"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine/monitor"
)

// headerBytes is the number of bytes in a DNS message header.
const headerBytes = 12

const (
	// responseTimeout is the maximal amount of time to wait for a DNS response.
	responseTimeout = 5 * time.Second
)

var errNoUpstreams = errors.New("upstream nameservers not set")

// txid identifies a DNS transaction.
//
// As the standard DNS Request ID is only 16 bits, we extend it:
// the lower 32 bits are the zero-extended bits of the DNS Request ID;
// the upper 32 bits are the CRC32 checksum of the first question in the request.
// This makes probability of txid collision negligible.
type txid uint64

// getTxID computes the txid of the given DNS packet.
func getTxID(packet []byte) txid {
	if len(packet) < headerBytes {
		return 0
	}

	dnsid := binary.BigEndian.Uint16(packet[0:2])
	qcount := binary.BigEndian.Uint16(packet[4:6])
	if qcount == 0 {
		return txid(dnsid)
	}

	offset := headerBytes
	for i := uint16(0); i < qcount; i++ {
		// Note: this relies on the fact that names are not compressed in questions,
		// so they are guaranteed to end with a NUL byte.
		//
		// Justification:
		// RFC 1035 doesn't seem to explicitly prohibit compressing names in questions,
		// but this is exceedingly unlikely to be done in practice. A DNS request
		// with multiple questions is ill-defined (which questions do the header flags apply to?)
		// and a single question would have to contain a pointer to an *answer*,
		// which would be excessively smart, pointless (an answer can just as well refer to the question)
		// and perhaps even prohibited: a draft RFC (draft-ietf-dnsind-local-compression-05) states:
		//
		// > It is important that these pointers always point backwards.
		//
		// This is said in summarizing RFC 1035, although that phrase does not appear in the original RFC.
		// Additionally, (https://cr.yp.to/djbdns/notes.html) states:
		//
		// > The precise rule is that a name can be compressed if it is a response owner name,
		// > the name in NS data, the name in CNAME data, the name in PTR data, the name in MX data,
		// > or one of the names in SOA data.
		namebytes := bytes.IndexByte(packet[offset:], 0)
		// ... | name | NUL | type | class
		//        ??     1      2      2
		offset = offset + namebytes + 5
		if len(packet) < offset {
			// Corrupt packet; don't crash.
			return txid(dnsid)
		}
	}

	hash := crc32.ChecksumIEEE(packet[headerBytes:offset])
	return (txid(hash) << 32) | txid(dnsid)
}

type route struct {
	Suffix    dnsname.FQDN
	Resolvers []netaddr.IPPort
}

// forwarder forwards DNS packets to a number of upstream nameservers.
type forwarder struct {
	logf    logger.Logf
	linkMon *monitor.Mon
	linkSel ForwardLinkSelector

	ctx       context.Context    // good until Close
	ctxCancel context.CancelFunc // closes ctx

	// responses is a channel by which responses are returned.
	responses chan packet

	mu sync.Mutex // guards following

	// routes are per-suffix resolvers to use, with
	// the most specific routes first.
	routes []route
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func newForwarder(logf logger.Logf, responses chan packet, linkMon *monitor.Mon, linkSel ForwardLinkSelector) *forwarder {
	f := &forwarder{
		logf:      logger.WithPrefix(logf, "forward: "),
		linkMon:   linkMon,
		linkSel:   linkSel,
		responses: responses,
	}
	f.ctx, f.ctxCancel = context.WithCancel(context.Background())
	return f
}

func (f *forwarder) Close() error {
	f.ctxCancel()
	return nil
}

func (f *forwarder) setRoutes(routes []route) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes = routes
}

var stdNetPacketListener packetListener = new(net.ListenConfig)

type packetListener interface {
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

func (f *forwarder) packetListener(ip netaddr.IP) (packetListener, error) {
	if f.linkSel == nil || initListenConfig == nil {
		return stdNetPacketListener, nil
	}
	linkName := f.linkSel.PickLink(ip)
	if linkName == "" {
		return stdNetPacketListener, nil
	}
	lc := new(net.ListenConfig)
	if err := initListenConfig(lc, f.linkMon, linkName); err != nil {
		return nil, err
	}
	return lc, nil
}

// send sends packet to dst. It is best effort.
//
// send expects the reply to have the same txid as txidOut.
//
// The provided closeOnCtxDone lets send register values to Close if
// the caller's ctx expires. This avoids send from allocating its own
// waiting goroutine to interrupt the ReadFrom, as memory is tight on
// iOS and we want the number of pending DNS lookups to be bursty
// without too much associated goroutine/memory cost.
func (f *forwarder) send(ctx context.Context, txidOut txid, closeOnCtxDone *closePool, packet []byte, dst netaddr.IPPort) ([]byte, error) {
	// TODO(bradfitz): if dst.IP is 8.8.8.8 or 8.8.4.4 or 1.1.1.1, etc, or
	// something dynamically probed earlier to support DoH or DoT,
	// do that here instead.

	ln, err := f.packetListener(dst.IP())
	if err != nil {
		return nil, err
	}
	conn, err := ln.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		f.logf("ListenPacket failed: %v", err)
		return nil, err
	}
	defer conn.Close()

	closeOnCtxDone.Add(conn)
	defer closeOnCtxDone.Remove(conn)

	if _, err := conn.WriteTo(packet, dst.UDPAddr()); err != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, err
	}

	// The 1 extra byte is to detect packet truncation.
	out := make([]byte, maxResponseBytes+1)
	n, _, err := conn.ReadFrom(out)
	if err != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if packetWasTruncated(err) {
			err = nil
		} else {
			return nil, err
		}
	}
	truncated := n > maxResponseBytes
	if truncated {
		n = maxResponseBytes
	}
	if n < headerBytes {
		f.logf("recv: packet too small (%d bytes)", n)
	}
	out = out[:n]
	txid := getTxID(out)
	if txid != txidOut {
		return nil, errors.New("txid doesn't match")
	}

	if truncated {
		const dnsFlagTruncated = 0x200
		flags := binary.BigEndian.Uint16(out[2:4])
		flags |= dnsFlagTruncated
		binary.BigEndian.PutUint16(out[2:4], flags)

		// TODO(#2067): Remove any incomplete records? RFC 1035 section 6.2
		// states that truncation should head drop so that the authority
		// section can be preserved if possible. However, the UDP read with
		// a too-small buffer has already dropped the end, so that's the
		// best we can do.
	}

	return out, nil
}

// resolvers returns the resolvers to use for domain.
func (f *forwarder) resolvers(domain dnsname.FQDN) []netaddr.IPPort {
	f.mu.Lock()
	routes := f.routes
	f.mu.Unlock()
	for _, route := range routes {
		if route.Suffix == "." || route.Suffix.Contains(domain) {
			return route.Resolvers
		}
	}
	return nil
}

// forward forwards the query to all upstream nameservers and returns the first response.
func (f *forwarder) forward(query packet) error {
	domain, err := nameFromQuery(query.bs)
	if err != nil {
		return err
	}

	txid := getTxID(query.bs)

	resolvers := f.resolvers(domain)
	if len(resolvers) == 0 {
		return errNoUpstreams
	}

	closeOnCtxDone := new(closePool)
	defer closeOnCtxDone.Close()

	ctx, cancel := context.WithTimeout(f.ctx, responseTimeout)
	defer cancel()

	resc := make(chan []byte, 1)
	var (
		mu       sync.Mutex
		firstErr error
	)

	for _, ipp := range resolvers {
		go func(ipp netaddr.IPPort) {
			resb, err := f.send(ctx, txid, closeOnCtxDone, query.bs, ipp)
			if err != nil {
				mu.Lock()
				defer mu.Unlock()
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			select {
			case resc <- resb:
			default:
			}
		}(ipp)
	}

	select {
	case v := <-resc:
		select {
		case <-ctx.Done():
			return ctx.Err()
		case f.responses <- packet{v, query.addr}:
			return nil
		}
	case <-ctx.Done():
		mu.Lock()
		defer mu.Unlock()
		if firstErr != nil {
			return firstErr
		}
		return ctx.Err()
	}
}

var initListenConfig func(_ *net.ListenConfig, _ *monitor.Mon, tunName string) error

// nameFromQuery extracts the normalized query name from bs.
func nameFromQuery(bs []byte) (dnsname.FQDN, error) {
	var parser dns.Parser

	hdr, err := parser.Start(bs)
	if err != nil {
		return "", err
	}
	if hdr.Response {
		return "", errNotQuery
	}

	q, err := parser.Question()
	if err != nil {
		return "", err
	}

	n := q.Name.Data[:q.Name.Length]
	return dnsname.ToFQDN(rawNameToLower(n))
}

// closePool is a dynamic set of io.Closers to close as a group.
// It's intended to be Closed at most once.
//
// The zero value is ready for use.
type closePool struct {
	mu     sync.Mutex
	m      map[io.Closer]bool
	closed bool
}

func (p *closePool) Add(c io.Closer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		c.Close()
		return
	}
	if p.m == nil {
		p.m = map[io.Closer]bool{}
	}
	p.m[c] = true
}

func (p *closePool) Remove(c io.Closer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	delete(p.m, c)
}

func (p *closePool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	for c := range p.m {
		c.Close()
	}
	return nil
}
