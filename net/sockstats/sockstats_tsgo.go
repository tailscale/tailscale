// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build tailscale_go && (darwin || ios || android)

package sockstats

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"tailscale.com/net/interfaces"
	"tailscale.com/util/clientmetric"
)

const IsAvailable = true

type sockStatCounters struct {
	txBytes, rxBytes                       atomic.Uint64
	rxBytesByInterface, txBytesByInterface map[int]*atomic.Uint64

	txBytesMetric, rxBytesMetric, txBytesCellularMetric, rxBytesCellularMetric *clientmetric.Metric

	// Validate counts for TCP sockets by using the TCP_CONNECTION_INFO
	// getsockopt. We get current counts, as well as save final values when
	// sockets are closed.
	validationConn                       atomic.Pointer[syscall.RawConn]
	validationTxBytes, validationRxBytes atomic.Uint64
}

var sockStats = struct {
	// mu protects fields in this group (but not the fields within
	// sockStatCounters). It should not be held in the per-read/write
	// callbacks.
	mu              sync.Mutex
	countersByLabel map[Label]*sockStatCounters
	knownInterfaces map[int]string // interface index -> name
	usedInterfaces  map[int]int    // set of interface indexes

	// Separate atomic since the current interface is accessed in the per-read/
	// write callbacks.
	currentInterface         atomic.Uint32
	currentInterfaceCellular atomic.Bool

	txBytesMetric, rxBytesMetric, txBytesCellularMetric, rxBytesCellularMetric *clientmetric.Metric
}{
	countersByLabel:       make(map[Label]*sockStatCounters),
	knownInterfaces:       make(map[int]string),
	usedInterfaces:        make(map[int]int),
	txBytesMetric:         clientmetric.NewCounter("sockstats_tx_bytes"),
	rxBytesMetric:         clientmetric.NewCounter("sockstats_rx_bytes"),
	txBytesCellularMetric: clientmetric.NewCounter("sockstats_tx_bytes_cellular"),
	rxBytesCellularMetric: clientmetric.NewCounter("sockstats_rx_bytes_cellular"),
}

func withSockStats(ctx context.Context, label Label) context.Context {
	sockStats.mu.Lock()
	defer sockStats.mu.Unlock()
	counters, ok := sockStats.countersByLabel[label]
	if !ok {
		counters = &sockStatCounters{
			rxBytesByInterface:    make(map[int]*atomic.Uint64),
			txBytesByInterface:    make(map[int]*atomic.Uint64),
			txBytesMetric:         clientmetric.NewCounter(fmt.Sprintf("sockstats_tx_bytes_%s", label)),
			rxBytesMetric:         clientmetric.NewCounter(fmt.Sprintf("sockstats_rx_bytes_%s", label)),
			txBytesCellularMetric: clientmetric.NewCounter(fmt.Sprintf("sockstats_tx_bytes_cellular_%s", label)),
			rxBytesCellularMetric: clientmetric.NewCounter(fmt.Sprintf("sockstats_rx_bytes_cellular_%s", label)),
		}

		// We might be called before setLinkMonitor has been called (and we've
		// had a chance to populate knownInterfaces). In that case, we'll have
		// to get the list of interfaces ourselves.
		if len(sockStats.knownInterfaces) == 0 {
			if ifaces, err := interfaces.GetList(); err == nil {
				for _, iface := range ifaces {
					counters.rxBytesByInterface[iface.Index] = &atomic.Uint64{}
					counters.txBytesByInterface[iface.Index] = &atomic.Uint64{}
				}
			}
		} else {
			for iface := range sockStats.knownInterfaces {
				counters.rxBytesByInterface[iface] = &atomic.Uint64{}
				counters.txBytesByInterface[iface] = &atomic.Uint64{}
			}
		}
		sockStats.countersByLabel[label] = counters
	}

	didCreateTCPConn := func(c syscall.RawConn) {
		counters.validationConn.Store(&c)
	}

	willCloseTCPConn := func(c syscall.RawConn) {
		tx, rx := tcpConnStats(c)
		counters.validationTxBytes.Add(tx)
		counters.validationRxBytes.Add(rx)
		counters.validationConn.Store(nil)
	}

	// Don't bother adding these hooks if we can't get stats that they end up
	// collecting.
	if tcpConnStats == nil {
		willCloseTCPConn = nil
		didCreateTCPConn = nil
	}

	didRead := func(n int) {
		counters.rxBytes.Add(uint64(n))
		counters.rxBytesMetric.Add(int64(n))
		sockStats.rxBytesMetric.Add(int64(n))
		if currentInterface := int(sockStats.currentInterface.Load()); currentInterface != 0 {
			if a := counters.rxBytesByInterface[currentInterface]; a != nil {
				a.Add(uint64(n))
			}
		}
		if sockStats.currentInterfaceCellular.Load() {
			sockStats.rxBytesCellularMetric.Add(int64(n))
			counters.rxBytesCellularMetric.Add(int64(n))
		}
	}
	didWrite := func(n int) {
		counters.txBytes.Add(uint64(n))
		counters.txBytesMetric.Add(int64(n))
		sockStats.txBytesMetric.Add(int64(n))
		if currentInterface := int(sockStats.currentInterface.Load()); currentInterface != 0 {
			if a := counters.txBytesByInterface[currentInterface]; a != nil {
				a.Add(uint64(n))
			}
		}
		if sockStats.currentInterfaceCellular.Load() {
			sockStats.txBytesCellularMetric.Add(int64(n))
			counters.txBytesCellularMetric.Add(int64(n))
		}
	}
	willOverwrite := func(trace *net.SockTrace) {
		log.Printf("sockstats: trace %q was overwritten by another", label)
	}

	return net.WithSockTrace(ctx, &net.SockTrace{
		DidCreateTCPConn: didCreateTCPConn,
		DidRead:          didRead,
		DidWrite:         didWrite,
		WillOverwrite:    willOverwrite,
		WillCloseTCPConn: willCloseTCPConn,
	})
}

// tcpConnStats returns the number of bytes sent and received on the
// given TCP socket. Its implementation is platform-dependent (or it may not
// be available at all).
var tcpConnStats func(c syscall.RawConn) (tx, rx uint64)

func get() *SockStats {
	sockStats.mu.Lock()
	defer sockStats.mu.Unlock()

	r := &SockStats{
		Stats:                    make(map[Label]SockStat),
		Interfaces:               make([]string, 0, len(sockStats.usedInterfaces)),
		CurrentInterfaceCellular: sockStats.currentInterfaceCellular.Load(),
	}
	for iface := range sockStats.usedInterfaces {
		r.Interfaces = append(r.Interfaces, sockStats.knownInterfaces[iface])
	}

	for label, counters := range sockStats.countersByLabel {
		s := SockStat{
			TxBytes:            counters.txBytes.Load(),
			RxBytes:            counters.rxBytes.Load(),
			TxBytesByInterface: make(map[string]uint64),
			RxBytesByInterface: make(map[string]uint64),
		}
		for iface, a := range counters.rxBytesByInterface {
			ifName := sockStats.knownInterfaces[iface]
			s.RxBytesByInterface[ifName] = a.Load()
		}
		for iface, a := range counters.txBytesByInterface {
			ifName := sockStats.knownInterfaces[iface]
			s.TxBytesByInterface[ifName] = a.Load()
		}
		r.Stats[label] = s
	}

	return r
}

func getValidation() *ValidationSockStats {
	sockStats.mu.Lock()
	defer sockStats.mu.Unlock()

	r := &ValidationSockStats{
		Stats: make(map[Label]ValidationSockStat),
	}

	for label, counters := range sockStats.countersByLabel {
		s := ValidationSockStat{
			TxBytes: counters.validationTxBytes.Load(),
			RxBytes: counters.validationRxBytes.Load(),
		}
		if c := counters.validationConn.Load(); c != nil && tcpConnStats != nil {
			tx, rx := tcpConnStats(*c)
			s.TxBytes += tx
			s.RxBytes += rx
		}
		r.Stats[label] = s
	}

	return r
}

func setLinkMonitor(lm LinkMonitor) {
	sockStats.mu.Lock()
	defer sockStats.mu.Unlock()

	// We intentionally populate all known interfaces now, so that we can
	// increment stats for them without holding mu.
	state := lm.InterfaceState()
	for ifName, iface := range state.Interface {
		sockStats.knownInterfaces[iface.Index] = ifName
	}
	if ifName := state.DefaultRouteInterface; ifName != "" {
		ifIndex := state.Interface[ifName].Index
		sockStats.currentInterface.Store(uint32(ifIndex))
		sockStats.currentInterfaceCellular.Store(isLikelyCellularInterface(ifName))
		sockStats.usedInterfaces[ifIndex] = 1
	}

	lm.RegisterChangeCallback(func(changed bool, state *interfaces.State) {
		if changed {
			if ifName := state.DefaultRouteInterface; ifName != "" {
				ifIndex := state.Interface[ifName].Index
				sockStats.mu.Lock()
				defer sockStats.mu.Unlock()
				// Ignore changes to unknown interfaces -- it would require
				// updating the tx/rxBytesByInterface maps and thus
				// additional locking for every read/write. Most of the time
				// the set of interfaces is static.
				if _, ok := sockStats.knownInterfaces[ifIndex]; ok {
					sockStats.currentInterface.Store(uint32(ifIndex))
					sockStats.usedInterfaces[ifIndex] = 1
					sockStats.currentInterfaceCellular.Store(isLikelyCellularInterface(ifName))
				} else {
					sockStats.currentInterface.Store(0)
					sockStats.currentInterfaceCellular.Store(false)
				}
			}
		}
	})
}

func isLikelyCellularInterface(ifName string) bool {
	return strings.HasPrefix(ifName, "rmnet") || // Android
		strings.HasPrefix(ifName, "ww") || // systemd naming scheme for WWAN
		strings.HasPrefix(ifName, "pdp") // iOS
}
