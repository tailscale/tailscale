// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tunstats maintains statistics about connections
// flowing through a TUN device (which operate at the IP layer).
package tunstats

import (
	"encoding/binary"
	"hash/maphash"
	"math/bits"
	"net/netip"
	"sync"
	"sync/atomic"

	"tailscale.com/net/flowtrack"
	"tailscale.com/types/ipproto"
)

// Statistics maintains counters for every connection.
// All methods are safe for concurrent use.
// The zero value is ready for use.
type Statistics struct {
	v4 hashTable[addrsPortsV4]
	v6 hashTable[addrsPortsV6]
}

// Counts are statistics about a particular connection.
type Counts struct {
	TxPackets uint64 `json:"txPkts,omitempty"`
	TxBytes   uint64 `json:"txBytes,omitempty"`
	RxPackets uint64 `json:"rxPkts,omitempty"`
	RxBytes   uint64 `json:"rxBytes,omitempty"`
}

const (
	minTableLen = 8
	maxProbeLen = 64
)

// hashTable is a hash table that uses open addressing with probing.
// See https://en.wikipedia.org/wiki/Hash_table#Open_addressing.
// The primary table is in the active field and can be retrieved atomically.
// In the common case, this data structure is mostly lock free.
//
// If the current table is too small, a new table is allocated that
// replaces the current active table. The contents of the older table are
// NOT copied to the new table, but rather the older table is appended
// to a list of outgrown tables. Re-growth happens under a lock,
// but is expected to happen rarely as the table size grows exponentially.
//
// To reduce memory usage, the counters uses 32-bit unsigned integers,
// which carry the risk of overflowing. If an overflow is detected,
// we add the amount overflowed to the overflow map. This is a naive Go map
// protected by a sync.Mutex. Overflow is rare that contention is not a concern.
//
// To extract all counters, we replace the active table with a zeroed table,
// and clear out the outgrown and overflow tables.
// We take advantage of the fact that all the tables can be merged together
// by simply adding up all the counters for each connection.
type hashTable[AddrsPorts addrsPorts] struct {
	// TODO: Get rid of this. It is just an atomic update in the common case,
	// but contention updating the same word still incurs a 25% performance hit.
	mu sync.RWMutex // RLock held while updating, Lock held while extracting

	active  atomic.Pointer[countsTable[AddrsPorts]]
	inserts atomic.Uint32 // heuristic for next active table to allocate

	muGrow   sync.Mutex // muGrow.Lock implies that mu.RLock held
	outgrown []countsTable[AddrsPorts]

	muOverflow sync.Mutex // muOverflow.Lock implies that mu.RLock held
	overflow   map[flowtrack.Tuple]Counts
}

type countsTable[AddrsPorts addrsPorts] []counts[AddrsPorts]

func (t *countsTable[AddrsPorts]) len() int {
	if t == nil {
		return 0
	}
	return len(*t)
}

type counts[AddrsPorts addrsPorts] struct {
	// initProto is both an initialization flag and the IP protocol.
	// It is 0 if uninitialized, 1 if initializing, and
	// 2+ipproto.Proto if initialized.
	initProto atomic.Uint32

	addrsPorts AddrsPorts // only valid if initProto is initialized

	txPackets atomic.Uint32
	txBytes   atomic.Uint32
	rxPackets atomic.Uint32
	rxBytes   atomic.Uint32
}

// NOTE: There is some degree of duplicated code.
// For example, the functionality to swap the addrsPorts and compute the hash
// should be performed by hashTable.update rather than Statistics.update.
// However, Go generics cannot invoke pointer methods on addressable values.
// See https://go.googlesource.com/proposal/+/refs/heads/master/design/43651-type-parameters.md#no-way-to-require-pointer-methods

type addrsPorts interface {
	comparable
	asTuple(ipproto.Proto) flowtrack.Tuple
}

type addrsPortsV4 [4 + 4 + 2 + 2]byte

func (x *addrsPortsV4) addrs() *[8]byte { return (*[8]byte)(x[:]) }
func (x *addrsPortsV4) ports() *[4]byte { return (*[4]byte)(x[8:]) }
func (x *addrsPortsV4) swap() {
	*(*[4]byte)(x[0:]), *(*[4]byte)(x[4:]) = *(*[4]byte)(x[4:]), *(*[4]byte)(x[0:])
	*(*[2]byte)(x[8:]), *(*[2]byte)(x[10:]) = *(*[2]byte)(x[10:]), *(*[2]byte)(x[8:])
}
func (x addrsPortsV4) asTuple(proto ipproto.Proto) flowtrack.Tuple {
	return flowtrack.Tuple{Proto: proto,
		Src: netip.AddrPortFrom(netip.AddrFrom4(*(*[4]byte)(x[0:])), binary.BigEndian.Uint16(x[8:])),
		Dst: netip.AddrPortFrom(netip.AddrFrom4(*(*[4]byte)(x[4:])), binary.BigEndian.Uint16(x[10:])),
	}
}

type addrsPortsV6 [16 + 16 + 2 + 2]byte

func (x *addrsPortsV6) addrs() *[32]byte { return (*[32]byte)(x[:]) }
func (x *addrsPortsV6) ports() *[4]byte  { return (*[4]byte)(x[32:]) }
func (x *addrsPortsV6) swap() {
	*(*[16]byte)(x[0:]), *(*[16]byte)(x[16:]) = *(*[16]byte)(x[16:]), *(*[16]byte)(x[0:])
	*(*[2]byte)(x[32:]), *(*[2]byte)(x[34:]) = *(*[2]byte)(x[34:]), *(*[2]byte)(x[32:])
}
func (x addrsPortsV6) asTuple(proto ipproto.Proto) flowtrack.Tuple {
	return flowtrack.Tuple{Proto: proto,
		Src: netip.AddrPortFrom(netip.AddrFrom16(*(*[16]byte)(x[0:])), binary.BigEndian.Uint16(x[32:])),
		Dst: netip.AddrPortFrom(netip.AddrFrom16(*(*[16]byte)(x[16:])), binary.BigEndian.Uint16(x[34:])),
	}
}

// UpdateTx updates the statistics for a transmitted IP packet.
func (s *Statistics) UpdateTx(b []byte) {
	s.update(b, false)
}

// UpdateRx updates the statistics for a received IP packet.
func (s *Statistics) UpdateRx(b []byte) {
	s.update(b, true)
}

var seed = maphash.MakeSeed()

func (s *Statistics) update(b []byte, receive bool) {
	switch {
	case len(b) >= 20 && b[0]>>4 == 4: // IPv4
		proto := ipproto.Proto(b[9])
		hasPorts := proto == ipproto.TCP || proto == ipproto.UDP
		var addrsPorts addrsPortsV4
		if hdrLen := int(4 * (b[0] & 0xf)); hdrLen == 20 && len(b) >= 24 && hasPorts {
			addrsPorts = *(*addrsPortsV4)(b[12:]) // addresses and ports are contiguous
		} else {
			*addrsPorts.addrs() = *(*[8]byte)(b[12:])
			// May have IPv4 options in-between address and ports.
			if len(b) >= hdrLen+4 && hasPorts {
				*addrsPorts.ports() = *(*[4]byte)(b[hdrLen:])
			}
		}
		if receive {
			addrsPorts.swap()
		}
		hash := maphash.Bytes(seed, addrsPorts[:]) ^ uint64(proto) // TODO: Hash proto better?
		s.v4.update(receive, proto, &addrsPorts, hash, uint32(len(b)))
		return
	case len(b) >= 40 && b[0]>>4 == 6: // IPv6
		proto := ipproto.Proto(b[6])
		hasPorts := proto == ipproto.TCP || proto == ipproto.UDP
		var addrsPorts addrsPortsV6
		if len(b) >= 44 && hasPorts {
			addrsPorts = *(*addrsPortsV6)(b[8:]) // addresses and ports are contiguous
		} else {
			*addrsPorts.addrs() = *(*[32]byte)(b[8:])
			// TODO: Support IPv6 extension headers?
			if hdrLen := 40; len(b) > hdrLen+4 && hasPorts {
				*addrsPorts.ports() = *(*[4]byte)(b[hdrLen:])
			}
		}
		if receive {
			addrsPorts.swap()
		}
		hash := maphash.Bytes(seed, addrsPorts[:]) ^ uint64(proto) // TODO: Hash proto better?
		s.v6.update(receive, proto, &addrsPorts, hash, uint32(len(b)))
		return
	}
	// TODO: Track malformed packets?
}

func (h *hashTable[AddrsPorts]) update(receive bool, proto ipproto.Proto, addrsPorts *AddrsPorts, hash uint64, size uint32) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	table := h.active.Load()
	for {
		// Start with an initialized table.
		if table.len() == 0 {
			table = h.grow(table)
		}

		// Try to update an entry in the currently active table.
		for i := 0; i < len(*table) && i < maxProbeLen; i++ {
			probe := uint64(i) // linear probing for small tables
			if len(*table) > 2*maxProbeLen {
				probe *= probe // quadratic probing for large tables
			}
			entry := &(*table)[(hash+probe)%uint64(len(*table))]

			// Spin-lock waiting for the entry to be initialized,
			// which should be quick as it only stores the AddrsPort.
		retry:
			switch initProto := entry.initProto.Load(); initProto {
			case 0: // uninitialized
				if !entry.initProto.CompareAndSwap(0, 1) {
					goto retry // raced with another initialization attempt
				}
				entry.addrsPorts = *addrsPorts
				entry.initProto.Store(uint32(proto) + 2) // initialization done
				h.inserts.Add(1)
			case 1: // initializing
				goto retry
			default: // initialized
				if ipproto.Proto(initProto-2) != proto || entry.addrsPorts != *addrsPorts {
					continue // this entry is for a different connection; try next entry
				}
			}

			// Atomically update the counters for the connection entry.
			var overflowPackets, overflowBytes bool
			if receive {
				overflowPackets = entry.rxPackets.Add(1) < 1
				overflowBytes = entry.rxBytes.Add(size) < size
			} else {
				overflowPackets = entry.txPackets.Add(1) < 1
				overflowBytes = entry.txBytes.Add(size) < size
			}
			if overflowPackets || overflowBytes {
				h.updateOverflow(receive, proto, addrsPorts, overflowPackets, overflowBytes)
			}
			return
		}

		// Unable to update, so grow the table and try again.
		// TODO: Use overflow map instead if table utilization is too low.
		table = h.grow(table)
	}
}

// grow grows the table unless the active table is larger than oldTable.
func (h *hashTable[AddrsPorts]) grow(oldTable *countsTable[AddrsPorts]) (newTable *countsTable[AddrsPorts]) {
	h.muGrow.Lock()
	defer h.muGrow.Unlock()

	if newTable = h.active.Load(); newTable.len() > oldTable.len() {
		return newTable // raced with another grow
	}
	newTable = new(countsTable[AddrsPorts])
	if oldTable.len() == 0 {
		*newTable = make(countsTable[AddrsPorts], minTableLen)
	} else {
		*newTable = make(countsTable[AddrsPorts], 2*len(*oldTable))
		h.outgrown = append(h.outgrown, *oldTable)
	}
	h.active.Store(newTable)
	return newTable
}

// updateOverflow updates the overflow map for counters that overflowed.
// Using 32-bit counters, this condition happens rarely as it only triggers
// after every 4 GiB of unidirectional network traffic on the same connection.
func (h *hashTable[AddrsPorts]) updateOverflow(receive bool, proto ipproto.Proto, addrsPorts *AddrsPorts, overflowPackets, overflowBytes bool) {
	h.muOverflow.Lock()
	defer h.muOverflow.Unlock()
	if h.overflow == nil {
		h.overflow = make(map[flowtrack.Tuple]Counts)
	}
	tuple := (*addrsPorts).asTuple(proto)
	cnts := h.overflow[tuple]
	if overflowPackets {
		if receive {
			cnts.RxPackets += 1 << 32
		} else {
			cnts.TxPackets += 1 << 32
		}
	}
	if overflowBytes {
		if receive {
			cnts.RxBytes += 1 << 32
		} else {
			cnts.TxBytes += 1 << 32
		}
	}
	h.overflow[tuple] = cnts
}

func (h *hashTable[AddrsPorts]) extractInto(out map[flowtrack.Tuple]Counts) {
	// Allocate a new table based on previous usage.
	var newTable *countsTable[AddrsPorts]
	if numInserts := h.inserts.Load(); numInserts > 0 {
		newLen := 1 << bits.Len(uint(4*numInserts/3)|uint(minTableLen-1))
		newTable = new(countsTable[AddrsPorts])
		*newTable = make(countsTable[AddrsPorts], newLen)
	}

	// Swap out the old tables for new tables.
	// We do not need to lock h.muGrow or h.muOverflow since holding h.mu
	// implies that nothing else could be holding those locks.
	h.mu.Lock()
	oldTable := h.active.Swap(newTable)
	oldOutgrown := h.outgrown
	oldOverflow := h.overflow
	h.outgrown = nil
	h.overflow = nil
	h.inserts.Store(0)
	h.mu.Unlock()

	// Merge tables into output.
	if oldTable != nil {
		mergeTable(out, *oldTable)
	}
	for _, table := range oldOutgrown {
		mergeTable(out, table)
	}
	mergeMap(out, oldOverflow)
}

// Extract extracts and resets the counters for all active connections.
// It must be called periodically otherwise the memory used is unbounded.
func (s *Statistics) Extract() map[flowtrack.Tuple]Counts {
	out := make(map[flowtrack.Tuple]Counts)
	s.v4.extractInto(out)
	s.v6.extractInto(out)
	return out
}

func mergeTable[AddrsPorts addrsPorts](dst map[flowtrack.Tuple]Counts, src countsTable[AddrsPorts]) {
	for i := range src {
		entry := &src[i]
		if initProto := entry.initProto.Load(); initProto > 0 {
			tuple := entry.addrsPorts.asTuple(ipproto.Proto(initProto - 2))
			cnts := dst[tuple]
			cnts.TxPackets += uint64(entry.txPackets.Load())
			cnts.TxBytes += uint64(entry.txBytes.Load())
			cnts.RxPackets += uint64(entry.rxPackets.Load())
			cnts.RxBytes += uint64(entry.rxBytes.Load())
			dst[tuple] = cnts
		}
	}
}

func mergeMap(dst, src map[flowtrack.Tuple]Counts) {
	for tuple, cntsSrc := range src {
		cntsDst := dst[tuple]
		cntsDst.TxPackets += cntsSrc.TxPackets
		cntsDst.TxBytes += cntsSrc.TxBytes
		cntsDst.RxPackets += cntsSrc.RxPackets
		cntsDst.RxBytes += cntsSrc.RxBytes
		dst[tuple] = cntsDst
	}
}
