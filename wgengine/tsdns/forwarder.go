// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsdns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	"inet.af/netaddr"
	"tailscale.com/types/logger"
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

type forwardedPacket struct {
	payload []byte
	dst     net.Addr
}

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

// forwarder forwards DNS packets to a number of upstream nameservers.
type forwarder struct {
	logf logger.Logf

	// queue is the queue for delegated packets.
	queue chan forwardedPacket
	// responses is a channel by which responses are returned.
	responses chan Packet
	// closed signals all goroutines to stop.
	closed chan struct{}
	// wg signals when all goroutines have stopped.
	wg sync.WaitGroup

	// conns are the UDP connections used for forwarding.
	// A random one is selected for each request, regardless of the target upstream.
	conns []*net.UDPConn

	mu sync.Mutex
	// upstreams are the nameserver addresses that should be used for forwarding.
	upstreams []net.Addr
	// txMap maps DNS txids to active forwarding records.
	txMap map[txid]forwardingRecord
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func newForwarder(logf logger.Logf, responses chan Packet) *forwarder {
	return &forwarder{
		logf:      logger.WithPrefix(logf, "forward: "),
		responses: responses,
		closed:    make(chan struct{}),
		conns:     make([]*net.UDPConn, connCount),
		txMap:     make(map[txid]forwardingRecord),
	}
}

func (f *forwarder) Start() error {
	var err error

	for i := range f.conns {
		f.conns[i], err = net.ListenUDP("udp", nil)
		if err != nil {
			return err
		}
	}

	f.wg.Add(connCount + 1)
	for idx, conn := range f.conns {
		go f.recv(uint16(idx), conn)
	}
	go f.cleanMap()

	return nil
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
		conn.SetDeadline(aLongTimeAgo)
	}

	f.wg.Wait()

	for _, conn := range f.conns {
		conn.Close()
	}
}

func (f *forwarder) setUpstreams(upstreams []net.Addr) {
	f.mu.Lock()
	f.upstreams = upstreams
	f.mu.Unlock()
}

func (f *forwarder) send(packet []byte, dst net.Addr) {
	connIdx := rand.Intn(connCount)
	conn := f.conns[connIdx]
	_, err := conn.WriteTo(packet, dst)
	// Do not log errors due to expired deadline.
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		f.logf("send: %v", err)
	}
}

func (f *forwarder) recv(connIdx uint16, conn *net.UDPConn) {
	defer f.wg.Done()

	for {
		out := make([]byte, maxResponseBytes)
		n, err := conn.Read(out)

		if err != nil {
			// Do not log errors due to expired deadline.
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				f.logf("recv: %v", err)
			}
			return
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

		packet := Packet{
			Payload: out,
			Addr:    record.src,
		}
		select {
		case <-f.closed:
			return
		case f.responses <- packet:
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
func (f *forwarder) forward(query Packet) error {
	txid := getTxID(query.Payload)

	f.mu.Lock()

	upstreams := f.upstreams
	if len(upstreams) == 0 {
		f.mu.Unlock()
		return errNoUpstreams
	}
	f.txMap[txid] = forwardingRecord{
		src:       query.Addr,
		createdAt: time.Now(),
	}

	f.mu.Unlock()

	for _, upstream := range upstreams {
		f.send(query.Payload, upstream)
	}

	return nil
}
