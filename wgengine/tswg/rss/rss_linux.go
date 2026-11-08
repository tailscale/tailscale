// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package rss balances a NIC's receive queues by rewriting its RSS
// indirection table, for hosts receiving from few, fast, long-lived flows,
// such as the tswg kernel data plane's tunnels.
//
// A NIC spreads received packets over its queues (and so CPUs) by a hash
// of each packet's addresses and ports, looked up in an indirection table
// of, typically, 128 entries. With many flows, that evens out; with a few
// dozen, it's luck: 37 WireGuard peers' UDP flows to a host with 32 queues
// landed on 11 of them on one boot and 23 on the next, and the busiest
// queues, at the NIC's packet rate limit, capped the host's throughput.
// The hash isn't always reproducible from what the NIC reports (EC2's ENA
// computes it in the Nitro card), so Balance measures instead: it learns
// what each busy queue's table entries carry by pointing them at idle
// queues for a moment, then bin-packs the entries onto the queues by
// load. A table can only move whole entries, and few flows share entries
// too (37 flows in 128 entries shared 19 of them), so first, if allowed,
// Balance tries a few random hash keys, keeping the one that spreads the
// flows best. Moving a flow between queues can reorder a few of its
// packets.
package rss

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"
	"unsafe"

	"github.com/safchain/ethtool"
	"golang.org/x/sys/unix"
)

// Result describes what Balance did.
type Result struct {
	Queues   int       // receive queues in the table
	Before   []float64 // each queue's packets per second, before
	After    []float64 // and after
	Probed   int       // table entries whose load was measured
	Changed  int       // table entries moved
	Balanced bool      // whether it was already balanced, so nothing changed
	NewKey   bool      // whether it changed the hash key
}

// MaxOverMean returns the busiest queue's rate over the mean, for rates.
func MaxOverMean(rates []float64) float64 {
	var sum, max float64
	for _, r := range rates {
		sum += r
		if r > max {
			max = r
		}
	}
	if sum == 0 {
		return 1
	}
	return max / (sum / float64(len(rates)))
}

// Options are Balance's tunables; the zero value is the defaults.
type Options struct {
	// Sample is how long to count packets for each measurement
	// (default 300ms).
	Sample time.Duration
	// Tolerance is how much busier than the mean the busiest queue may
	// be before Balance acts (default 1.25).
	Tolerance float64
	// Keys is how many random hash keys to try, if the NIC allows setting
	// it (default 0, none).
	Keys int
}

// Balance rebalances dev's RSS indirection table from its queues' current
// load; see the package doc. It takes a few Samples.
func Balance(ctx context.Context, dev string, opts Options) (*Result, error) {
	sample := cmp.Or(opts.Sample, 300*time.Millisecond)
	tolerance := cmp.Or(opts.Tolerance, 1.25)

	et, err := ethtool.NewEthtool()
	if err != nil {
		return nil, err
	}
	defer et.Close()

	table, err := getIndir(dev)
	if err != nil {
		return nil, fmt.Errorf("reading %s's RSS table: %w", dev, err)
	}
	// The queues, by their counters: the table may not name them all.
	nq, err := numQueues(et, dev)
	if err != nil {
		return nil, err
	}
	nq = max(nq, int(slices.Max(table))+1)
	measure := func() ([]float64, error) {
		if err := sleep(ctx, 0); err != nil {
			return nil, err
		}
		a, err := queueCounts(et, dev, nq)
		if err != nil {
			return nil, err
		}
		start := time.Now()
		if err := sleep(ctx, sample); err != nil {
			return nil, err
		}
		b, err := queueCounts(et, dev, nq)
		if err != nil {
			return nil, err
		}
		secs := time.Since(start).Seconds()
		rates := make([]float64, nq)
		for q := range rates {
			rates[q] = float64(b[q]-a[q]) / secs
		}
		return rates, nil
	}

	res := &Result{Queues: nq}
	if res.Before, err = measure(); err != nil {
		return nil, err
	}
	var total float64
	for _, r := range res.Before {
		total += r
	}

	// If the traffic goes away while we measure, what we learned is
	// wrong: put the table and key back.
	origTable := slices.Clone(table)
	origKey, _ := getKey(dev)
	restore := func(err error) (*Result, error) {
		if origKey != nil {
			setKey(dev, origKey)
		}
		setIndir(dev, origTable)
		return nil, err
	}
	measureLive := func() ([]float64, error) {
		r, err := measure()
		if err != nil {
			return nil, err
		}
		var sum float64
		for _, v := range r {
			sum += v
		}
		if sum < total/2 {
			return nil, fmt.Errorf("rss: %s's traffic fell from %.0f to %.0f packets/s while measuring", dev, total, sum)
		}
		return r, nil
	}
	if total == 0 || MaxOverMean(res.Before) <= tolerance {
		res.After, res.Balanced = res.Before, true
		return res, nil
	}

	// Try keys, with an even table, so that a key's score is how evenly
	// it spreads the flows over the entries.
	before := res.Before
	if opts.Keys > 0 {
		if key, err := getKey(dev); err == nil {
			even := make([]uint32, len(table))
			for e := range even {
				even[e] = uint32(e % nq)
			}
			if err := setIndir(dev, even); err != nil {
				return nil, fmt.Errorf("writing %s's RSS table: %w", dev, err)
			}
			r, err := measureLive()
			if err != nil {
				return restore(err)
			}
			best, bestKey := slices.Max(r), key
			before = r
			for range opts.Keys {
				k := make([]byte, len(key))
				rand.Read(k)
				if err := setKey(dev, k); err != nil {
					break
				}
				r, err := measureLive()
				if err != nil {
					return restore(err)
				}
				if m := slices.Max(r); m < best {
					best, bestKey, before = m, k, r
				}
			}
			setKey(dev, bestKey)
			res.NewKey = !bytes.Equal(bestKey, key)
			table = even
		}
	}

	// Learn each busy queue's entries' loads, by moving them to idle
	// queues, a busy queue's worth at a time per idle queue.
	load := make([]float64, len(table)) // per table entry; 0 if idle
	idleBelow := total / float64(nq) / 20
	byQueue := make([][]int, nq)
	for e, q := range table {
		byQueue[q] = append(byQueue[q], e)
	}
	var busy, idle []int
	for q, r := range before {
		if r > idleBelow {
			busy = append(busy, q)
		} else {
			idle = append(idle, q)
		}
	}
	slices.SortFunc(busy, func(a, b int) int { return cmp.Compare(before[b], before[a]) })
	if len(idle) == 0 {
		return nil, errors.New("rss: no idle queue to measure with")
	}
	probe := slices.Clone(table)
	for len(busy) > 0 {
		var moved [][2]int // entry, idle queue
		used := 0
		for len(busy) > 0 {
			ents := byQueue[busy[0]]
			if used+len(ents) > len(idle) {
				if used == 0 { // more entries than idle queues: take what fits
					ents = ents[:len(idle)]
				} else {
					break
				}
			}
			for _, e := range ents {
				moved = append(moved, [2]int{e, idle[used]})
				used++
			}
			busy = busy[1:]
		}
		copy(probe, table)
		for _, m := range moved {
			probe[m[0]] = uint32(m[1])
		}
		if err := setIndir(dev, probe); err != nil {
			return nil, fmt.Errorf("writing %s's RSS table: %w", dev, err)
		}
		rates, err := measureLive()
		if err != nil {
			return restore(err)
		}
		for _, m := range moved {
			load[m[0]] = max(rates[m[1]]-before[m[1]], 0)
			res.Probed++
		}
	}

	// Bin-pack: the busiest entries first, each to the least loaded
	// queue, preferring its own; then the idle entries round robin, so
	// that each queue keeps a share of the table for flows to come.
	ents := make([]int, len(table))
	for e := range ents {
		ents[e] = e
	}
	slices.SortStableFunc(ents, func(a, b int) int { return cmp.Compare(load[b], load[a]) })
	assigned := make([]float64, nq)
	count := make([]int, nq)
	next := slices.Clone(table)
	rr := 0
	for _, e := range ents {
		if load[e] > 0 {
			best := int(table[e])
			for q := range nq {
				if assigned[q] < assigned[best] {
					best = q
				}
			}
			next[e] = uint32(best)
			assigned[best] += load[e]
			count[best]++
			continue
		}
		// Idle: to the queue with the fewest entries, from a rotating start.
		best := rr % nq
		for k := range nq {
			q := (rr + k) % nq
			if count[q] < count[best] {
				best = q
			}
		}
		rr++
		next[e] = uint32(best)
		count[best]++
	}
	for e := range next {
		if next[e] != table[e] {
			res.Changed++
		}
	}
	if err := setIndir(dev, next); err != nil {
		return nil, fmt.Errorf("writing %s's RSS table: %w", dev, err)
	}
	if res.After, err = measure(); err != nil {
		return nil, err
	}
	return res, nil
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// queueStatRx matches drivers' per-queue received packet counters, as in
// ethtool -S: ENA's, mlx5's, and Intel's and virtio's.
var queueStatRx = regexp.MustCompile(`^(?:queue_(\d+)_rx_cnt|rx(\d+)_packets|rx_queue_(\d+)_packets)$`)

// numQueues returns how many receive queues dev has counters for.
func numQueues(et *ethtool.Ethtool, dev string) (int, error) {
	stats, err := et.Stats(dev)
	if err != nil {
		return 0, err
	}
	n := 0
	for name := range stats {
		if m := queueStatRx.FindStringSubmatch(name); m != nil {
			q, _ := strconv.Atoi(m[1] + m[2] + m[3])
			n = max(n, q+1)
		}
	}
	if n == 0 {
		return 0, fmt.Errorf("rss: no per-queue receive counters in %s's ethtool stats", dev)
	}
	return n, nil
}

// queueCounts returns dev's per-queue received packet counts.
func queueCounts(et *ethtool.Ethtool, dev string, nq int) ([]uint64, error) {
	stats, err := et.Stats(dev)
	if err != nil {
		return nil, err
	}
	counts := make([]uint64, nq)
	found := false
	for name, v := range stats {
		m := queueStatRx.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		q, _ := strconv.Atoi(m[1] + m[2] + m[3])
		if q < nq {
			counts[q] = v
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("rss: no per-queue receive counters in %s's ethtool stats", dev)
	}
	return counts, nil
}

// maxIndir bounds the RSS tables we handle.
const maxIndir = 1024

// rxfhIndir is struct ethtool_rxfh_indir, with room for maxIndir entries.
type rxfhIndir struct {
	cmd, size uint32
	ring      [maxIndir]uint32
}

// ifreqData is struct ifreq with ifr_data.
type ifreqData struct {
	name [unix.IFNAMSIZ]byte
	data uintptr
	_    [16]byte
}

func ethtoolIoctl(dev string, data unsafe.Pointer) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var ifr ifreqData
	if len(dev) >= len(ifr.name) {
		return fmt.Errorf("rss: device name %q too long", dev)
	}
	copy(ifr.name[:], dev)
	ifr.data = uintptr(data)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&ifr))); e != 0 {
		return e
	}
	return nil
}

func getIndir(dev string) ([]uint32, error) {
	var in rxfhIndir
	in.cmd = unix.ETHTOOL_GRXFHINDIR
	if err := ethtoolIoctl(dev, unsafe.Pointer(&in)); err != nil {
		return nil, err
	}
	if in.size == 0 || in.size > maxIndir {
		return nil, fmt.Errorf("rss: %s's RSS table has %d entries", dev, in.size)
	}
	if err := ethtoolIoctl(dev, unsafe.Pointer(&in)); err != nil {
		return nil, err
	}
	return slices.Clone(in.ring[:in.size]), nil
}

// rxfh is struct ethtool_rxfh, with room for a key of up to maxKey bytes.
type rxfh struct {
	cmd, rssContext, indirSize, keySize uint32
	hfunc, inputXfrm                    uint8
	_                                   [2]uint8
	_                                   uint32
	key                                 [maxKey]byte
}

const (
	maxKey            = 256
	rxfhIndirNoChange = 0xffffffff // ETH_RXFH_INDIR_NO_CHANGE
)

func getKey(dev string) ([]byte, error) {
	var r rxfh
	r.cmd = unix.ETHTOOL_GRSSH
	if err := ethtoolIoctl(dev, unsafe.Pointer(&r)); err != nil {
		return nil, err
	}
	if r.keySize == 0 || r.keySize > maxKey {
		return nil, fmt.Errorf("rss: %s's RSS key is %d bytes", dev, r.keySize)
	}
	r.indirSize = 0 // just the key
	if err := ethtoolIoctl(dev, unsafe.Pointer(&r)); err != nil {
		return nil, err
	}
	return slices.Clone(r.key[:r.keySize]), nil
}

func setKey(dev string, key []byte) error {
	var r rxfh
	r.cmd = unix.ETHTOOL_SRSSH
	r.indirSize = rxfhIndirNoChange
	r.keySize = uint32(len(key))
	copy(r.key[:], key)
	return ethtoolIoctl(dev, unsafe.Pointer(&r))
}

func setIndir(dev string, table []uint32) error {
	var in rxfhIndir
	in.cmd = unix.ETHTOOL_SRXFHINDIR
	in.size = uint32(len(table))
	copy(in.ring[:], table)
	return ethtoolIoctl(dev, unsafe.Pointer(&in))
}
