// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tunstats

import (
	"encoding/binary"
	"fmt"
	"hash/maphash"
	"math"
	"runtime"
	"sync"
	"testing"

	qt "github.com/frankban/quicktest"
	"tailscale.com/net/flowtrack"
	"tailscale.com/types/ipproto"
)

type SimpleStatistics struct {
	mu sync.Mutex
	m  map[flowtrack.Tuple]Counts
}

func (s *SimpleStatistics) UpdateTx(b []byte) {
	s.update(b, false)
}
func (s *SimpleStatistics) UpdateRx(b []byte) {
	s.update(b, true)
}
func (s *SimpleStatistics) update(b []byte, receive bool) {
	var tuple flowtrack.Tuple
	var size uint64
	if len(b) >= 1 {
		// This logic is mostly copied from Statistics.update.
		switch v := b[0] >> 4; {
		case v == 4 && len(b) >= 20: // IPv4
			proto := ipproto.Proto(b[9])
			size = uint64(binary.BigEndian.Uint16(b[2:]))
			var addrsPorts addrsPortsV4
			*(*[8]byte)(addrsPorts[0:]) = *(*[8]byte)(b[12:])
			if hdrLen := int(4 * (b[0] & 0xf)); len(b) >= hdrLen+4 && (proto == ipproto.TCP || proto == ipproto.UDP) {
				*(*[4]byte)(addrsPorts[8:]) = *(*[4]byte)(b[hdrLen:])
			}
			if receive {
				addrsPorts.swap()
			}
			tuple = addrsPorts.asTuple(proto)
		case v == 6 && len(b) >= 40: // IPv6
			proto := ipproto.Proto(b[6])
			size = uint64(binary.BigEndian.Uint16(b[4:]))
			var addrsPorts addrsPortsV6
			*(*[32]byte)(addrsPorts[0:]) = *(*[32]byte)(b[8:])
			if hdrLen := 40; len(b) > hdrLen+4 && (proto == ipproto.TCP || proto == ipproto.UDP) {
				*(*[4]byte)(addrsPorts[32:]) = *(*[4]byte)(b[hdrLen:])
			}
			if receive {
				addrsPorts.swap()
			}
			tuple = addrsPorts.asTuple(proto)
		default:
			return // non-IP packet
		}
	} else {
		return // invalid packet
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = make(map[flowtrack.Tuple]Counts)
	}
	cnts := s.m[tuple]
	if receive {
		cnts.RxPackets++
		cnts.RxBytes += size
	} else {
		cnts.TxPackets++
		cnts.TxBytes += size
	}
	s.m[tuple] = cnts
}

func TestEmpty(t *testing.T) {
	c := qt.New(t)
	var s Statistics
	c.Assert(s.Extract(), qt.DeepEquals, map[flowtrack.Tuple]Counts{})
	c.Assert(s.Extract(), qt.DeepEquals, map[flowtrack.Tuple]Counts{})
}

func TestOverflow(t *testing.T) {
	c := qt.New(t)
	var s Statistics
	var cnts Counts

	a := &addrsPortsV4{192, 168, 0, 1, 192, 168, 0, 2, 12, 34, 56, 78}
	h := maphash.Bytes(seed, a[:])

	cnts.TxPackets++
	cnts.TxBytes += math.MaxUint32
	s.v4.update(false, ipproto.UDP, a, h, math.MaxUint32)
	for i := 0; i < 1e6; i++ {
		cnts.TxPackets++
		cnts.TxBytes += uint64(i)
		s.v4.update(false, ipproto.UDP, a, h, uint32(i))
	}
	c.Assert(s.Extract(), qt.DeepEquals, map[flowtrack.Tuple]Counts{a.asTuple(ipproto.UDP): cnts})
	c.Assert(s.Extract(), qt.DeepEquals, map[flowtrack.Tuple]Counts{})
}

func FuzzParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		var s Statistics
		s.UpdateRx(b) // must not panic
		s.UpdateTx(b) // must not panic
		s.Extract()   // must not panic
	})
}

var testV4 = func() (b [24]byte) {
	b[0] = 4<<4 | 5                               // version and header length
	binary.BigEndian.PutUint16(b[2:], 1234)       // size
	b[9] = byte(ipproto.UDP)                      // protocol
	*(*[4]byte)(b[12:]) = [4]byte{192, 168, 0, 1} // src addr
	*(*[4]byte)(b[16:]) = [4]byte{192, 168, 0, 2} // dst addr
	binary.BigEndian.PutUint16(b[20:], 456)       // src port
	binary.BigEndian.PutUint16(b[22:], 789)       // dst port
	return b
}()

/*
func BenchmarkA(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var s Statistics
		for j := 0; j < 1e3; j++ {
			s.UpdateTx(testV4[:])
		}
	}
}

func BenchmarkB(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var s SimpleStatistics
		for j := 0; j < 1e3; j++ {
			s.UpdateTx(testV4[:])
		}
	}
}

func BenchmarkC(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var s Statistics
		var group sync.WaitGroup
		for k := 0; k < runtime.NumCPU(); k++ {
			group.Add(1)
			go func(k int) {
				defer group.Done()
				b := testV4
				for j := 0; j < 1e3; j++ {
					binary.LittleEndian.PutUint32(b[12:], uint32(k))
					binary.LittleEndian.PutUint32(b[16:], uint32(j))
					s.UpdateTx(b[:])
				}
			}(k)
		}
		group.Wait()
	}
}

func BenchmarkD(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var s SimpleStatistics
		var group sync.WaitGroup
		for k := 0; k < runtime.NumCPU(); k++ {
			group.Add(1)
			go func(k int) {
				defer group.Done()
				b := testV4
				for j := 0; j < 1e3; j++ {
					binary.LittleEndian.PutUint32(b[12:], uint32(k))
					binary.LittleEndian.PutUint32(b[16:], uint32(j))
					s.UpdateTx(b[:])
				}
			}(k)
		}
		group.Wait()
	}
}
*/

// FUZZ
// Benchmark:
//	IPv4 vs IPv6
//	single vs all cores
//	same vs unique addresses

/*
linear probing

	1   => 115595714 ns/op   859003746 B/op
	2   =>   9355585 ns/op    46454947 B/op
	4   =>   3301663 ns/op     8706967 B/op
	8   =>   2775162 ns/op     4176433 B/op
	16  =>   2517899 ns/op     2099434 B/op
	32  =>   2397939 ns/op     2098986 B/op
	64  =>   2118390 ns/op     1197352 B/op
	128 =>   2029255 ns/op     1046729 B/op
	256 =>   2069939 ns/op     1042577 B/op

quadratic probing

	1    => 111134367 ns/op  825962200 B/op
	2    =>   8061189 ns/op   45106117 B/op
	4    =>   3216728 ns/op    8079556 B/op
	8    =>   2576443 ns/op    2355890 B/op
	16   =>   2471713 ns/op    2097196 B/op
	32   =>   2108294 ns/op    1050225 B/op
	64   =>   1964441 ns/op    1048736 B/op
	128  =>   2118538 ns/op    1046663 B/op
	256  =>   1968353 ns/op    1042568 B/op
	512  =>   2049336 ns/op    1034306 B/op
	1024 =>   2001605 ns/op    1017786 B/op
	2048 =>   2046972 ns/op     984988 B/op
	4096 =>   2108753 ns/op     919105 B/op
*/

func testPacketV4(proto ipproto.Proto, srcAddr, dstAddr [4]byte, srcPort, dstPort, size uint16) (out []byte) {
	var ipHdr [20]byte
	ipHdr[0] = 4<<4 | 5
	binary.BigEndian.PutUint16(ipHdr[2:], size)
	ipHdr[9] = byte(proto)
	*(*[4]byte)(ipHdr[12:]) = srcAddr
	*(*[4]byte)(ipHdr[16:]) = dstAddr
	out = append(out, ipHdr[:]...)
	switch proto {
	case ipproto.TCP:
		var tcpHdr [20]byte
		binary.BigEndian.PutUint16(tcpHdr[0:], srcPort)
		binary.BigEndian.PutUint16(tcpHdr[2:], dstPort)
		out = append(out, tcpHdr[:]...)
	case ipproto.UDP:
		var udpHdr [8]byte
		binary.BigEndian.PutUint16(udpHdr[0:], srcPort)
		binary.BigEndian.PutUint16(udpHdr[2:], dstPort)
		out = append(out, udpHdr[:]...)
	default:
		panic(fmt.Sprintf("unknown proto: %d", proto))
	}
	return append(out, make([]byte, int(size)-len(out))...)
}

func Benchmark(b *testing.B) {
	b.Run("SingleRoutine/SameConn", func(b *testing.B) {
		p := testPacketV4(ipproto.UDP, [4]byte{192, 168, 0, 1}, [4]byte{192, 168, 0, 2}, 123, 456, 789)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var s Statistics
			for j := 0; j < 1e3; j++ {
				s.UpdateTx(p)
			}
		}
	})
	b.Run("SingleRoutine/UniqueConns", func(b *testing.B) {
		p := testPacketV4(ipproto.UDP, [4]byte{}, [4]byte{}, 0, 0, 789)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var s Statistics
			for j := 0; j < 1e3; j++ {
				binary.BigEndian.PutUint32(p[20:], uint32(j)) // unique port combination
				s.UpdateTx(p)
			}
		}
	})
	b.Run("MultiRoutine/SameConn", func(b *testing.B) {
		p := testPacketV4(ipproto.UDP, [4]byte{192, 168, 0, 1}, [4]byte{192, 168, 0, 2}, 123, 456, 789)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var s Statistics
			var group sync.WaitGroup
			for j := 0; j < runtime.NumCPU(); j++ {
				group.Add(1)
				go func() {
					defer group.Done()
					for k := 0; k < 1e3; k++ {
						s.UpdateTx(p)
					}
				}()
			}
			group.Wait()
		}
	})
	b.Run("MultiRoutine/UniqueConns", func(b *testing.B) {
		ps := make([][]byte, runtime.NumCPU())
		for i := range ps {
			ps[i] = testPacketV4(ipproto.UDP, [4]byte{192, 168, 0, 1}, [4]byte{192, 168, 0, 2}, 0, 0, 789)
		}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var s Statistics
			var group sync.WaitGroup
			for j := 0; j < runtime.NumCPU(); j++ {
				group.Add(1)
				go func(j int) {
					defer group.Done()
					p := ps[j]
					j *= 1e3
					for k := 0; k < 1e3; k++ {
						binary.BigEndian.PutUint32(p[20:], uint32(j+k)) // unique port combination
						s.UpdateTx(p)
					}
				}(j)
			}
			group.Wait()
		}
	})
}
