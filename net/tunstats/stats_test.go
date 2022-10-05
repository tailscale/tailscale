// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tunstats

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"tailscale.com/net/flowtrack"
	"tailscale.com/types/ipproto"
)

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

func TestConcurrent(t *testing.T) {
	c := qt.New(t)

	var stats Statistics
	var wants []map[flowtrack.Tuple]Counts
	gots := make([]map[flowtrack.Tuple]Counts, runtime.NumCPU())
	var group sync.WaitGroup
	for i := range gots {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			gots[i] = make(map[flowtrack.Tuple]Counts)
			rn := rand.New(rand.NewSource(time.Now().UnixNano()))
			var p []byte
			var t flowtrack.Tuple
			for j := 0; j < 1000; j++ {
				delay := rn.Intn(10000)
				if p == nil || rn.Intn(64) == 0 {
					proto := ipproto.TCP
					if rn.Intn(2) == 0 {
						proto = ipproto.UDP
					}
					srcAddr := netip.AddrFrom4([4]byte{192, 168, 0, byte(rand.Intn(16))})
					dstAddr := netip.AddrFrom4([4]byte{192, 168, 0, byte(rand.Intn(16))})
					srcPort := uint16(rand.Intn(16))
					dstPort := uint16(rand.Intn(16))
					size := uint16(64 + rand.Intn(1024))
					p = testPacketV4(proto, srcAddr.As4(), dstAddr.As4(), srcPort, dstPort, size)
					t = flowtrack.Tuple{Proto: proto, Src: netip.AddrPortFrom(srcAddr, srcPort), Dst: netip.AddrPortFrom(dstAddr, dstPort)}
				}
				t2 := t
				receive := rn.Intn(2) == 0
				if receive {
					t2.Src, t2.Dst = t2.Dst, t2.Src
				}

				cnts := gots[i][t2]
				if receive {
					stats.UpdateRx(p)
					cnts.RxPackets++
					cnts.RxBytes += uint64(len(p))
				} else {
					cnts.TxPackets++
					cnts.TxBytes += uint64(len(p))
					stats.UpdateTx(p)
				}
				gots[i][t2] = cnts
				time.Sleep(time.Duration(rn.Intn(1 + delay)))
			}
		}(i)
	}
	for range gots {
		wants = append(wants, stats.Extract())
		time.Sleep(time.Millisecond)
	}
	group.Wait()
	wants = append(wants, stats.Extract())

	got := make(map[flowtrack.Tuple]Counts)
	want := make(map[flowtrack.Tuple]Counts)
	mergeMaps(got, gots...)
	mergeMaps(want, wants...)
	c.Assert(got, qt.DeepEquals, want)
}

func mergeMaps(dst map[flowtrack.Tuple]Counts, srcs ...map[flowtrack.Tuple]Counts) {
	for _, src := range srcs {
		for tuple, cnts := range src {
			dst[tuple] = dst[tuple].Add(cnts)
		}
	}
}

func Benchmark(b *testing.B) {
	// TODO: Test IPv6 packets?
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
