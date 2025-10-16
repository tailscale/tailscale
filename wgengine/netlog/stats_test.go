// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netlog

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"tailscale.com/cmd/testwrapper/flakytest"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/netlogtype"
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

// TestInterval ensures that we receive at least one call to `dump` using only
// maxPeriod.
func TestInterval(t *testing.T) {
	c := qt.New(t)

	const maxPeriod = 10 * time.Millisecond
	const maxConns = 2048

	gotDump := make(chan struct{}, 1)
	stats := newStatistics(maxPeriod, maxConns, func(_, _ time.Time, _, _ map[netlogtype.Connection]netlogtype.Counts) {
		select {
		case gotDump <- struct{}{}:
		default:
		}
	})
	defer stats.Shutdown(context.Background())

	srcAddr := netip.AddrFrom4([4]byte{192, 168, 0, byte(rand.Intn(16))})
	dstAddr := netip.AddrFrom4([4]byte{192, 168, 0, byte(rand.Intn(16))})
	srcPort := uint16(rand.Intn(16))
	dstPort := uint16(rand.Intn(16))
	size := uint16(64 + rand.Intn(1024))
	p := testPacketV4(ipproto.TCP, srcAddr.As4(), dstAddr.As4(), srcPort, dstPort, size)
	stats.UpdateRxVirtual(p)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	select {
	case <-ctx.Done():
		c.Fatal("didn't receive dump within context deadline")
	case <-gotDump:
	}
}

func TestConcurrent(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/7030")
	c := qt.New(t)

	const maxPeriod = 10 * time.Millisecond
	const maxConns = 10
	virtualAggregate := make(map[netlogtype.Connection]netlogtype.Counts)
	stats := newStatistics(maxPeriod, maxConns, func(start, end time.Time, virtual, physical map[netlogtype.Connection]netlogtype.Counts) {
		c.Assert(start.IsZero(), qt.IsFalse)
		c.Assert(end.IsZero(), qt.IsFalse)
		c.Assert(end.Before(start), qt.IsFalse)
		c.Assert(len(virtual) > 0 && len(virtual) <= maxConns, qt.IsTrue)
		c.Assert(len(physical) == 0, qt.IsTrue)
		for conn, cnts := range virtual {
			virtualAggregate[conn] = virtualAggregate[conn].Add(cnts)
		}
	})
	defer stats.Shutdown(context.Background())
	var wants []map[netlogtype.Connection]netlogtype.Counts
	gots := make([]map[netlogtype.Connection]netlogtype.Counts, runtime.NumCPU())
	var group sync.WaitGroup
	for i := range gots {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			gots[i] = make(map[netlogtype.Connection]netlogtype.Counts)
			rn := rand.New(rand.NewSource(time.Now().UnixNano()))
			var p []byte
			var t netlogtype.Connection
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
					t = netlogtype.Connection{Proto: proto, Src: netip.AddrPortFrom(srcAddr, srcPort), Dst: netip.AddrPortFrom(dstAddr, dstPort)}
				}
				t2 := t
				receive := rn.Intn(2) == 0
				if receive {
					t2.Src, t2.Dst = t2.Dst, t2.Src
				}

				cnts := gots[i][t2]
				if receive {
					stats.UpdateRxVirtual(p)
					cnts.RxPackets++
					cnts.RxBytes += uint64(len(p))
				} else {
					cnts.TxPackets++
					cnts.TxBytes += uint64(len(p))
					stats.UpdateTxVirtual(p)
				}
				gots[i][t2] = cnts
				time.Sleep(time.Duration(rn.Intn(1 + delay)))
			}
		}(i)
	}
	group.Wait()
	c.Assert(stats.Shutdown(context.Background()), qt.IsNil)
	wants = append(wants, virtualAggregate)

	got := make(map[netlogtype.Connection]netlogtype.Counts)
	want := make(map[netlogtype.Connection]netlogtype.Counts)
	mergeMaps(got, gots...)
	mergeMaps(want, wants...)
	c.Assert(got, qt.DeepEquals, want)
}

func mergeMaps(dst map[netlogtype.Connection]netlogtype.Counts, srcs ...map[netlogtype.Connection]netlogtype.Counts) {
	for _, src := range srcs {
		for conn, cnts := range src {
			dst[conn] = dst[conn].Add(cnts)
		}
	}
}

func Benchmark(b *testing.B) {
	// TODO: Test IPv6 packets?
	b.Run("SingleRoutine/SameConn", func(b *testing.B) {
		p := testPacketV4(ipproto.UDP, [4]byte{192, 168, 0, 1}, [4]byte{192, 168, 0, 2}, 123, 456, 789)
		b.ResetTimer()
		b.ReportAllocs()
		for range b.N {
			s := newStatistics(0, 0, nil)
			for j := 0; j < 1e3; j++ {
				s.UpdateTxVirtual(p)
			}
		}
	})
	b.Run("SingleRoutine/UniqueConns", func(b *testing.B) {
		p := testPacketV4(ipproto.UDP, [4]byte{}, [4]byte{}, 0, 0, 789)
		b.ResetTimer()
		b.ReportAllocs()
		for range b.N {
			s := newStatistics(0, 0, nil)
			for j := 0; j < 1e3; j++ {
				binary.BigEndian.PutUint32(p[20:], uint32(j)) // unique port combination
				s.UpdateTxVirtual(p)
			}
		}
	})
	b.Run("MultiRoutine/SameConn", func(b *testing.B) {
		p := testPacketV4(ipproto.UDP, [4]byte{192, 168, 0, 1}, [4]byte{192, 168, 0, 2}, 123, 456, 789)
		b.ResetTimer()
		b.ReportAllocs()
		for range b.N {
			s := newStatistics(0, 0, nil)
			var group sync.WaitGroup
			for j := 0; j < runtime.NumCPU(); j++ {
				group.Add(1)
				go func() {
					defer group.Done()
					for k := 0; k < 1e3; k++ {
						s.UpdateTxVirtual(p)
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
		for range b.N {
			s := newStatistics(0, 0, nil)
			var group sync.WaitGroup
			for j := 0; j < runtime.NumCPU(); j++ {
				group.Add(1)
				go func(j int) {
					defer group.Done()
					p := ps[j]
					j *= 1e3
					for k := 0; k < 1e3; k++ {
						binary.BigEndian.PutUint32(p[20:], uint32(j+k)) // unique port combination
						s.UpdateTxVirtual(p)
					}
				}(j)
			}
			group.Wait()
		}
	})
}
