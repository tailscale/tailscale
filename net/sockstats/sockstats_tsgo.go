// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build tailscale_go && (darwin || ios || android || ts_enable_sockstats)

package sockstats

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
	"tailscale.com/version"
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
	radioHighMetric                                                            *clientmetric.Metric
}{
	countersByLabel:       make(map[Label]*sockStatCounters),
	knownInterfaces:       make(map[int]string),
	usedInterfaces:        make(map[int]int),
	txBytesMetric:         clientmetric.NewCounter("sockstats_tx_bytes"),
	rxBytesMetric:         clientmetric.NewCounter("sockstats_rx_bytes"),
	txBytesCellularMetric: clientmetric.NewCounter("sockstats_tx_bytes_cellular"),
	rxBytesCellularMetric: clientmetric.NewCounter("sockstats_rx_bytes_cellular"),
	radioHighMetric:       clientmetric.NewGaugeFunc("sockstats_cellular_radio_high_fraction", radio.radioHighPercent),
}

func init() {
	// Deltas are not useful for this gauge metric, we want the collector to be
	// able to get current values without having to wait for the 4 hour
	// metricLogNameFrequency interval (by which point the cell radio state may
	// be very different).
	sockStats.radioHighMetric.DisableDeltas()
}

func withSockStats(ctx context.Context, label Label, logf logger.Logf) context.Context {
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

		// We might be called before setNetMon has been called (and we've
		// had a chance to populate knownInterfaces). In that case, we'll have
		// to get the list of interfaces ourselves.
		if len(sockStats.knownInterfaces) == 0 {
			if ifaces, err := netmon.GetInterfaceList(); err == nil {
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
			if n > 0 {
				radio.active()
			}
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
			if n > 0 {
				radio.active()
			}
		}
	}
	willOverwrite := func(trace *net.SockTrace) {
		if version.IsUnstableBuild() {
			// Only spam about this in dev builds.
			// See https://github.com/tailscale/tailscale/issues/13731 for known problems.
			logf("sockstats: trace %q was overwritten by another", label)
		}
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
		Stats:                    make(map[Label]SockStat, len(sockStats.countersByLabel)),
		CurrentInterfaceCellular: sockStats.currentInterfaceCellular.Load(),
	}

	for label, counters := range sockStats.countersByLabel {
		r.Stats[label] = SockStat{
			TxBytes: counters.txBytes.Load(),
			RxBytes: counters.rxBytes.Load(),
		}
	}

	return r
}

func getInterfaces() *InterfaceSockStats {
	sockStats.mu.Lock()
	defer sockStats.mu.Unlock()

	interfaceCount := len(sockStats.usedInterfaces)
	r := &InterfaceSockStats{
		Stats:      make(map[Label]InterfaceSockStat, len(sockStats.countersByLabel)),
		Interfaces: make([]string, 0, interfaceCount),
	}
	for iface := range sockStats.usedInterfaces {
		r.Interfaces = append(r.Interfaces, sockStats.knownInterfaces[iface])
	}

	for label, counters := range sockStats.countersByLabel {
		s := InterfaceSockStat{
			TxBytesByInterface: make(map[string]uint64, interfaceCount),
			RxBytesByInterface: make(map[string]uint64, interfaceCount),
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

func setNetMon(netMon *netmon.Monitor) {
	sockStats.mu.Lock()
	defer sockStats.mu.Unlock()

	// We intentionally populate all known interfaces now, so that we can
	// increment stats for them without holding mu.
	state := netMon.InterfaceState()
	for ifName, iface := range state.Interface {
		sockStats.knownInterfaces[iface.Index] = ifName
	}
	if ifName := state.DefaultRouteInterface; ifName != "" {
		ifIndex := state.Interface[ifName].Index
		sockStats.currentInterface.Store(uint32(ifIndex))
		sockStats.currentInterfaceCellular.Store(isLikelyCellularInterface(ifName))
		sockStats.usedInterfaces[ifIndex] = 1
	}

	netMon.RegisterChangeCallback(func(delta *netmon.ChangeDelta) {
		if !delta.Major {
			return
		}
		state := delta.New
		ifName := state.DefaultRouteInterface
		if ifName == "" {
			return
		}
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
	})
}

func debugInfo() string {
	var b strings.Builder
	fmt.Fprintf(&b, "radio high percent: %d\n", radio.radioHighPercent())
	fmt.Fprintf(&b, "radio activity for the last hour (one minute per line):\n")
	for i, a := range radio.radioActive() {
		fmt.Fprintf(&b, "%d", a)
		if i%60 == 59 {
			fmt.Fprintf(&b, "\n")
		}
	}
	return b.String()
}

func isLikelyCellularInterface(ifName string) bool {
	return strings.HasPrefix(ifName, "rmnet") || // Android
		strings.HasPrefix(ifName, "ww") || // systemd naming scheme for WWAN
		strings.HasPrefix(ifName, "pdp") // iOS
}

// radioMonitor tracks usage of the cellular radio, approximates the power state transitions,
// and reports the percentage of time the radio was on.
type radioMonitor struct {
	// usage tracks the last time (as unix timestamp) the radio was used over the last hour.
	// Values are indexed by the number of seconds since the beginning of the current hour.
	usage [radioSampleSize]int64

	// startTime is the time we started tracking radio usage.
	startTime int64

	now func() time.Time
}

// radioSampleSize is the number of samples to store and report for cellular radio usage.
// Usage is measured once per second, so this is the number of seconds of history to track.
const radioSampleSize = 3600 // 1 hour

// initStallPeriod is the minimum amount of time in seconds to collect data before reporting.
// Otherwise, all clients will report 100% radio usage on startup.
var initStallPeriod int64 = 120 // 2 minutes

var radio = &radioMonitor{
	now:       time.Now,
	startTime: time.Now().Unix(),
}

// radioActivity should be called whenever network activity occurs on a cellular network interface.
func (rm *radioMonitor) active() {
	t := rm.now().Unix()
	rm.usage[t%radioSampleSize] = t
}

// Timings for radio power state transitions taken from
// https://developer.android.com/training/connectivity/network-access-optimization#radio-state
// Even though that documents a typical 3G radio and newer radios are much more efficient,
// it provides worst-case timings to use for analysis.
const (
	radioHighIdle = 5  // seconds radio idles in high power state before transitioning to low
	radioLowIdle  = 12 // seconds radio idles in low power state before transitioning to off
)

// radioActive returns a slice of 1s samples (one per second) for the past hour
// indicating whether the radio was active (1) or idle (0).
func (rm *radioMonitor) radioActive() (active [radioSampleSize]int64) {
	rm.forEachSample(func(c int, isActive bool) {
		if isActive {
			active[c] = 1
		}
	})
	return
}

// radioHighPercent returns the percentage of time (as an int from 0 to 100)
// that the cellular radio was in high power mode during the past hour.
// If the radio has been monitored for less than an hour,
// the percentage is calculated based on the time monitored.
func (rm *radioMonitor) radioHighPercent() int64 {
	var highPowerSec int64 // total seconds radio was in high power (active or idle)
	lastActive := -1       // counter when radio was last active

	periodLength := rm.forEachSample(func(c int, isActive bool) {
		if isActive {
			// radio on and active
			highPowerSec++
			lastActive = c
		} else if lastActive != -1 && c-lastActive < radioHighIdle {
			// radio on but idle
			highPowerSec++
		}
	})

	if periodLength < initStallPeriod {
		return 0
	}

	if highPowerSec == 0 {
		return 0
	}
	return highPowerSec * 100 / periodLength
}

// forEachSample calls f for each sample in the past hour (or less if less time
// has passed -- the evaluated period is returned, measured in seconds)
func (rm *radioMonitor) forEachSample(f func(c int, isActive bool)) (periodLength int64) {
	now := rm.now().Unix()
	periodLength = radioSampleSize
	if t := now - rm.startTime; t < periodLength {
		if t <= 0 {
			return 0
		}
		periodLength = t + 1 // we want an inclusive range (with the current second)
	}
	periodStart := now - periodLength // start of current reporting period

	// split into slices of radio usage, with values in chronological order.
	// split at now+1 so that the current second is in the second slice.
	split := (now + 1) % radioSampleSize
	slices := [2][]int64{
		rm.usage[split:],
		rm.usage[:split],
	}

	var c int // counter
	for _, slice := range slices {
		for _, v := range slice {
			f(c, v >= periodStart)
			c++
		}
	}

	return periodLength
}
