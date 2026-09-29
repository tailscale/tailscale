// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"bytes"
	"context"
	"expvar"
	"fmt"
	"log"
	"net"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/derp/derpserver"
)

// maxSavedSynRate is the rate above which TCP_SAVE_SYN is disabled.
const maxSavedSynRate = 100_000

var (
	savedSynRate     = expvar.NewFloat("gauge_tcp_syn_rate")
	savedSynDisabled = expvar.NewInt("counter_tcp_save_syn_disabled_listeners")
)

// newTCPSaveSynListener disables TCP_SAVE_SYN when the estimated SYN rate exceeds
// maxSavedSynRate or the rate cannot be read. The option stays off until
// restart. Disabling the option also stops MSS collection on s.
// Closing the returned listener stops monitoring.
func newTCPSaveSynListener(ln net.Listener, s *derpserver.Server) net.Listener {
	if !*tcpSaveSyn {
		return ln
	}
	raw, err := ln.(*net.TCPListener).SyscallConn()
	if err != nil {
		log.Printf("derper: cannot monitor TCP_SAVE_SYN: %v", err)
		return ln
	}
	ctx, cancel := context.WithCancel(context.Background())
	sln := &savedSynListener{Listener: ln, server: s, rawConn: raw, cancel: cancel}
	go sln.watchSYNRate(ctx)
	return sln
}

// incomingSYNs estimates incoming SYNs across all listeners in the network
// namespace, including IPv6, using PassiveOpens, SyncookiesSent, and ListenDrops.
// Incomplete handshakes below the SYN backlog limit are not counted; drops,
// retransmissions, and completed cookie handshakes can be counted more than once.
func incomingSYNs(buf []byte) (float64, error) {
	opens, err := readProcNetCounters("/proc/net/snmp", buf, "Tcp:", "PassiveOpens")
	if err != nil {
		return 0, err
	}
	overflow, err := readProcNetCounters("/proc/net/netstat", buf, "TcpExt:", "SyncookiesSent", "ListenDrops")
	if err != nil {
		return 0, err
	}
	return float64(opens) + float64(overflow), nil
}

// readProcNetCounters reads a bounded procfs snapshot into buf.
func readProcNetCounters(path string, buf []byte, protocol string, names ...string) (uint64, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	var n int
	for {
		if n == len(buf) {
			return 0, fmt.Errorf("%s exceeds %d bytes", path, len(buf))
		}
		nr, err := unix.Read(fd, buf[n:])
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if nr == 0 {
			return parseProcNetCounters(buf[:n], protocol, names...)
		}
		n += nr
	}
}

// parseProcNetCounters parses only the named counters from a header/value pair.
func parseProcNetCounters(data []byte, protocol string, names ...string) (uint64, error) {
	indices := [3]int{-1, -1, -1}
	if len(names) == 0 || len(names) > len(indices) {
		return 0, fmt.Errorf("invalid counter count %d", len(names))
	}
	var headerFields int
	for len(data) != 0 {
		var line []byte
		line, data, _ = bytes.Cut(data, []byte{'\n'})
		if !bytes.HasPrefix(line, []byte(protocol)) {
			if headerFields != 0 {
				return 0, fmt.Errorf("missing %s values", protocol)
			}
			continue
		}
		var fields int
		var total uint64
		for len(line) != 0 {
			var field []byte
			field, line = nextProcNetField(line)
			if len(field) == 0 {
				break
			}
			if fields == 0 {
				if string(field) != protocol {
					return 0, fmt.Errorf("bad procfs protocol, want %s", protocol)
				}
			} else {
				for i, name := range names {
					if headerFields == 0 {
						if string(field) == name {
							if indices[i] != -1 {
								return 0, fmt.Errorf("duplicate %s counter %s", protocol, name)
							}
							indices[i] = fields
						}
					} else if fields == indices[i] {
						v, err := strconv.ParseUint(string(field), 10, 64)
						if err != nil {
							return 0, fmt.Errorf("bad %s counter %s: %w", protocol, name, err)
						}
						if v > ^uint64(0)-total {
							return 0, fmt.Errorf("%s counter sum overflows", protocol)
						}
						total += v
					}
				}
			}
			fields++
		}
		if headerFields != 0 {
			if fields != headerFields {
				return 0, fmt.Errorf("%s header/value field count mismatch", protocol)
			}
			return total, nil
		}
		for i, name := range names {
			if indices[i] == -1 {
				return 0, fmt.Errorf("missing %s counter %s", protocol, name)
			}
		}
		headerFields = fields
	}
	return 0, fmt.Errorf("missing %s counters", protocol)
}

func nextProcNetField(line []byte) (field, rest []byte) {
	line = bytes.TrimLeft(line, " \t\r")
	if end := bytes.IndexAny(line, " \t\r"); end >= 0 {
		return line[:end], line[end+1:]
	}
	return line, nil
}

type savedSynListener struct {
	net.Listener
	server  *derpserver.Server
	rawConn syscall.RawConn
	cancel  context.CancelFunc
}

func (ln *savedSynListener) disableTCPSaveSyn(reason error) error {
	var err error
	if e := ln.rawConn.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_SAVE_SYN, 0)
	}); e != nil {
		return e
	}
	if err != nil {
		return err
	}
	ln.server.SetTCPSaveSyn(false)
	log.Printf("derper: disabled TCP_SAVE_SYN: %v", reason)
	return nil
}

func (ln *savedSynListener) Close() error {
	ln.cancel()
	return ln.Listener.Close()
}

// synRateMeasurement computes a rate from counter deltas and elapsed time.
// Counter resets start a new baseline.
type synRateMeasurement struct {
	time  time.Time
	total float64
}

func (m *synRateMeasurement) update(now time.Time, total float64) float64 {
	var rate float64
	if !m.time.IsZero() && now.After(m.time) && total >= m.total {
		rate = (total - m.total) / now.Sub(m.time).Seconds()
	}
	m.time, m.total = now, total
	return rate
}

type synRateMonitor struct {
	measurement   synRateMeasurement
	disableReason error
	disabled      bool
	lastErrorLog  time.Time
}

func (ln *savedSynListener) watchSYNRate(ctx context.Context) {
	var monitor synRateMonitor
	var synBuf [64 << 10]byte
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		var total float64
		var err error
		if monitor.disableReason == nil || monitor.disabled {
			total, err = incomingSYNs(synBuf[:])
		}
		monitor.update(ln, time.Now(), total, err)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *synRateMonitor) update(ln *savedSynListener, now time.Time, total float64, readErr error) {
	if m.disableReason == nil || m.disabled {
		if readErr != nil {
			if !m.disabled {
				m.disableReason = fmt.Errorf("reading SYN rate: %w", readErr)
			}
		} else {
			rate := m.measurement.update(now, total)
			savedSynRate.Set(rate)
			if rate > maxSavedSynRate && !m.disabled {
				m.disableReason = fmt.Errorf("estimated SYN rate %.0f/s exceeds %d/s", rate, maxSavedSynRate)
			}
		}
	}
	if m.disableReason == nil || m.disabled {
		return
	}
	if err := ln.disableTCPSaveSyn(m.disableReason); err != nil {
		if m.lastErrorLog.IsZero() || now.Sub(m.lastErrorLog) >= 10*time.Minute {
			m.lastErrorLog = now
			log.Printf("derper: disabling TCP_SAVE_SYN (%v): %v", m.disableReason, err)
		}
		return
	}
	m.disabled = true
	savedSynDisabled.Add(1)
}
