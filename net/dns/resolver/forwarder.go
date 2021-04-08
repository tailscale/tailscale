// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package resolver

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	dns "golang.org/x/net/dns/dnsmessage"
	"inet.af/netaddr"
	"tailscale.com/logtail/backoff"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
)

// headerBytes is the number of bytes in a DNS message header.
const headerBytes = 12

// connCount is the number of UDP connections to use for forwarding.
const connCount = 32

const (
	// cleanupInterval is the interval between purged of timed-out entries from txMap.
	cleanupInterval = 30 * time.Second
	// responseTimeout is the maximal amount of time to wait for a DNS response.
	responseTimeout = 5 * time.Second
)

var errNoUpstreams = errors.New("upstream nameservers not set")

var aLongTimeAgo = time.Unix(0, 1)

type forwardingRecord struct {
	src       netaddr.IPPort
	createdAt time.Time
}

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
	suffix    string
	resolvers []netaddr.IPPort
}

// forwarder forwards DNS packets to a number of upstream nameservers.
type forwarder struct {
	logf logger.Logf

	// responses is a channel by which responses are returned.
	responses chan packet
	// closed signals all goroutines to stop.
	closed chan struct{}
	// wg signals when all goroutines have stopped.
	wg sync.WaitGroup

	// conns are the UDP connections used for forwarding.
	// A random one is selected for each request, regardless of the target upstream.
	conns []*fwdConn

	mu sync.Mutex
	// routes are per-suffix resolvers to use.
	routes []route                   // most specific routes first
	txMap  map[txid]forwardingRecord // txids to in-flight requests
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func newForwarder(logf logger.Logf, responses chan packet) *forwarder {
	ret := &forwarder{
		logf:      logger.WithPrefix(logf, "forward: "),
		responses: responses,
		closed:    make(chan struct{}),
		conns:     make([]*fwdConn, connCount),
		txMap:     make(map[txid]forwardingRecord),
	}

	ret.wg.Add(connCount + 1)
	for idx := range ret.conns {
		ret.conns[idx] = newFwdConn(ret.logf, idx)
		go ret.recv(ret.conns[idx])
	}
	go ret.cleanMap()

	return ret
}

func (f *forwarder) Close() {
	select {
	case <-f.closed:
		return
	default:
		// continue
	}
	close(f.closed)

	for _, conn := range f.conns {
		conn.close()
	}

	f.wg.Wait()
}

func (f *forwarder) rebindFromNetworkChange() {
	for _, c := range f.conns {
		c.mu.Lock()
		c.reconnectLocked()
		c.mu.Unlock()
	}
}

func (f *forwarder) setRoutes(routes []route) {
	f.mu.Lock()
	f.routes = routes
	f.mu.Unlock()
}

// send sends packet to dst. It is best effort.
func (f *forwarder) send(packet []byte, dst netaddr.IPPort) {
	connIdx := rand.Intn(connCount)
	conn := f.conns[connIdx]
	conn.send(packet, dst)
}

func (f *forwarder) recv(conn *fwdConn) {
	defer f.wg.Done()

	for {
		select {
		case <-f.closed:
			return
		default:
		}
		out := make([]byte, maxResponseBytes)
		n := conn.read(out)
		if n == 0 {
			continue
		}
		if n < headerBytes {
			f.logf("recv: packet too small (%d bytes)", n)
		}

		out = out[:n]
		txid := getTxID(out)

		f.mu.Lock()

		record, found := f.txMap[txid]
		// At most one nameserver will return a response:
		// the first one to do so will delete txid from the map.
		if !found {
			f.mu.Unlock()
			continue
		}
		delete(f.txMap, txid)

		f.mu.Unlock()

		pkt := packet{out, record.src}
		select {
		case <-f.closed:
			return
		case f.responses <- pkt:
			// continue
		}
	}
}

// cleanMap periodically deletes timed-out forwarding records from f.txMap to bound growth.
func (f *forwarder) cleanMap() {
	defer f.wg.Done()

	t := time.NewTicker(cleanupInterval)
	defer t.Stop()

	var now time.Time
	for {
		select {
		case <-f.closed:
			return
		case now = <-t.C:
			// continue
		}

		f.mu.Lock()
		for k, v := range f.txMap {
			if now.Sub(v.createdAt) > responseTimeout {
				delete(f.txMap, k)
			}
		}
		f.mu.Unlock()
	}
}

// forward forwards the query to all upstream nameservers and returns the first response.
func (f *forwarder) forward(query packet) error {
	domain, err := nameFromQuery(query.bs)
	if err != nil {
		return err
	}

	txid := getTxID(query.bs)

	f.mu.Lock()
	routes := f.routes
	f.mu.Unlock()

	var resolvers []netaddr.IPPort
	for _, route := range routes {
		if route.suffix != "." && !dnsname.HasSuffix(domain, route.suffix) {
			continue
		}
		resolvers = route.resolvers
		break
	}
	if len(resolvers) == 0 {
		return errNoUpstreams
	}

	f.mu.Lock()
	f.txMap[txid] = forwardingRecord{
		src:       query.addr,
		createdAt: time.Now(),
	}
	f.mu.Unlock()

	for _, resolver := range resolvers {
		f.send(query.bs, resolver)
	}

	return nil
}

// A fwdConn manages a single connection used to forward DNS requests.
// Net link changes can cause a *net.UDPConn to become permanently unusable, particularly on macOS.
// fwdConn detects such situations and transparently creates new connections.
type fwdConn struct {
	// logf allows a fwdConn to log.
	logf logger.Logf

	// wg tracks the number of outstanding conn.Read and conn.Write calls.
	wg sync.WaitGroup
	// change allows calls to read to block until a the network connection has been replaced.
	change *sync.Cond

	// mu protects fields that follow it; it is also change's Locker.
	mu sync.Mutex
	// closed tracks whether fwdConn has been permanently closed.
	closed bool
	// conn is the current active connection.
	conn net.PacketConn
}

func newFwdConn(logf logger.Logf, idx int) *fwdConn {
	c := new(fwdConn)
	c.logf = logger.WithPrefix(logf, fmt.Sprintf("fwdConn %d: ", idx))
	c.change = sync.NewCond(&c.mu)
	// c.conn is created lazily in send
	return c
}

// send sends packet to dst using c's connection.
// It is best effort. It is UDP, after all. Failures are logged.
func (c *fwdConn) send(packet []byte, dst netaddr.IPPort) {
	var b *backoff.Backoff // lazily initialized, since it is not needed in the common case
	backOff := func(err error) {
		if b == nil {
			b = backoff.NewBackoff("dns-fwdConn-send", c.logf, 30*time.Second)
		}
		b.BackOff(context.Background(), err)
	}

	for {
		// Gather the current connection.
		// We can't hold the lock while we call WriteTo.
		c.mu.Lock()
		conn := c.conn
		closed := c.closed
		if closed {
			c.mu.Unlock()
			return
		}
		if conn == nil {
			c.reconnectLocked()
			c.mu.Unlock()
			continue
		}
		c.mu.Unlock()

		a := dst.UDPAddr()
		c.wg.Add(1)
		_, err := conn.WriteTo(packet, a)
		c.wg.Done()
		if err == nil {
			// Success
			return
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			// We intentionally closed this connection.
			// It has been replaced by a new connection. Try again.
			continue
		}
		// Something else went wrong.
		// We have three choices here: try again, give up, or create a new connection.
		var opErr *net.OpError
		if !errors.As(err, &opErr) {
			// Weird. All errors from the net package should be *net.OpError. Bail.
			c.logf("send: non-*net.OpErr %v (%T)", err, err)
			return
		}
		if opErr.Temporary() || opErr.Timeout() {
			// I doubt that either of these can happen (this is UDP),
			// but go ahead and try again.
			backOff(err)
			continue
		}
		if networkIsDown(err) {
			// Fail.
			c.logf("send: network is down")
			return
		}
		if networkIsUnreachable(err) {
			// This can be caused by a link change.
			// Replace the existing connection with a new one.
			c.mu.Lock()
			// It's possible that multiple senders discovered simultaneously
			// that the network is unreachable. Avoid reconnecting multiple times:
			// Only reconnect if the current connection is the one that we
			// discovered to be problematic.
			if c.conn == conn {
				backOff(err)
				c.reconnectLocked()
			}
			c.mu.Unlock()
			// Try again with our new network connection.
			continue
		}
		// Unrecognized error. Fail.
		c.logf("send: unrecognized error: %v", err)
		return
	}
}

// read waits for a response from c's connection.
// It returns the number of bytes read, which may be 0
// in case of an error or a closed connection.
func (c *fwdConn) read(out []byte) int {
	for {
		// Gather the current connection.
		// We can't hold the lock while we call ReadFrom.
		c.mu.Lock()
		conn := c.conn
		closed := c.closed
		if closed {
			c.mu.Unlock()
			return 0
		}
		if conn == nil {
			// There is no current connection.
			// Wait for the connection to change, then try again.
			c.change.Wait()
			c.mu.Unlock()
			continue
		}
		c.mu.Unlock()

		c.wg.Add(1)
		n, _, err := conn.ReadFrom(out)
		c.wg.Done()
		if err == nil {
			// Success.
			return n
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			// We intentionally closed this connection.
			// It has been replaced by a new connection. Try again.
			continue
		}

		c.logf("read: unrecognized error: %v", err)
		return 0
	}
}

// reconnectLocked replaces the current connection with a new one.
// c.mu must be locked.
func (c *fwdConn) reconnectLocked() {
	c.closeConnLocked()
	// Make a new connection.
	conn, err := net.ListenPacket("udp", "")
	if err != nil {
		c.logf("ListenPacket failed: %v", err)
	} else {
		c.conn = conn
	}
	// Broadcast that a new connection is available.
	c.change.Broadcast()
}

// closeCurrentConn closes the current connection.
// c.mu must be locked.
func (c *fwdConn) closeConnLocked() {
	if c.conn == nil {
		return
	}
	// Unblock all readers/writers, wait for them, close the connection.
	c.conn.SetDeadline(aLongTimeAgo)
	c.wg.Wait()
	c.conn.Close()
	c.conn = nil
}

// close permanently closes c.
func (c *fwdConn) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	c.closeConnLocked()
	// Unblock any remaining readers.
	c.change.Broadcast()
}

// nameFromQuery extracts the normalized query name from bs.
func nameFromQuery(bs []byte) (string, error) {
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
	return rawNameToLower(n), nil
}
