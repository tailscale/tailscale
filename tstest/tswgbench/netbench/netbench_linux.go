// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netbench

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// Register registers the benchmark endpoints on mux under prefix (such as
// "/bench/"):
//
//   - POST serve?port=N starts (once) a TCP sink and a UDP sink and echo
//     server on port N.
//   - GET stats returns the server's counters ([Stats]).
//   - GET cpu returns the node's CPU time ([CPU]).
//   - GET tcp?addr=IP:PORT&dur=D&streams=N sends to a TCP sink for D over
//     N streams ([Result]). With netns=NAME, it connects from the network
//     namespace /run/netns/NAME.
//   - GET udp?addr=IP:PORT&dur=D&size=N floods a UDP sink with N-byte
//     datagrams for D ([Result]). With gso=M, each write of N bytes is
//     a UDP GSO (UDP_SEGMENT) batch of M-byte datagrams.
//   - GET rtt?addr=IP:PORT&n=N&interval=D measures N UDP round trips to an
//     echo server, D apart ([RTT]).
func Register(mux *http.ServeMux, prefix string) {
	mux.HandleFunc("POST "+prefix+"serve", benchServe)
	mux.HandleFunc("GET "+prefix+"stats", benchStats)
	mux.HandleFunc("GET "+prefix+"cpu", benchCPU)
	mux.HandleFunc("GET "+prefix+"tcp", benchTCP)
	mux.HandleFunc("GET "+prefix+"udp", benchUDP)
	mux.HandleFunc("GET "+prefix+"rtt", benchRTT)
}

// Benchmark server counters.
var (
	benchServeOnce  sync.Once
	benchServeErr   error
	benchTCPBytes   atomic.Int64
	benchUDPPackets atomic.Int64
	benchUDPBytes   atomic.Int64
)

// The first byte of benchmark UDP datagrams says what to do with them.
const (
	benchUDPSink = 'S' // count it
	benchUDPEcho = 'E' // send it back
)

// benchServe starts (once) the benchmark server on the port query
// parameter: a TCP sink, and a UDP sink and echo server.
func benchServe(w http.ResponseWriter, r *http.Request) {
	port := r.URL.Query().Get("port")
	benchServeOnce.Do(func() {
		ln, err := net.Listen("tcp", ":"+port)
		if err != nil {
			benchServeErr = err
			return
		}
		uc, err := net.ListenPacket("udp", ":"+port)
		if err != nil {
			ln.Close()
			benchServeErr = err
			return
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					buf := make([]byte, 256<<10)
					for {
						n, err := c.Read(buf)
						benchTCPBytes.Add(int64(n))
						if err != nil {
							return
						}
					}
				}()
			}
		}()
		go func() {
			buf := make([]byte, 65535)
			for {
				n, from, err := uc.ReadFrom(buf)
				if err != nil {
					return
				}
				if n > 0 && buf[0] == benchUDPEcho {
					uc.WriteTo(buf[:n], from)
					continue
				}
				benchUDPPackets.Add(1)
				benchUDPBytes.Add(int64(n))
			}
		}()
	})
	if benchServeErr != nil {
		http.Error(w, benchServeErr.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, "OK\n")
}

func benchStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, Stats{
		TCPBytes:   benchTCPBytes.Load(),
		UDPPackets: benchUDPPackets.Load(),
		UDPBytes:   benchUDPBytes.Load(),
	})
}

// benchCPU reports the node's CPU time from /proc/stat.
func benchCPU(w http.ResponseWriter, r *http.Request) {
	if c, ok := cpuidleCPU(); ok {
		writeJSON(w, c)
		return
	}
	f, err := os.Open("/proc/stat")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		// user nice system idle iowait irq softirq steal guest guest_nice
		var c CPU
		for i, s := range fields[1:] {
			v, _ := strconv.ParseInt(s, 10, 64)
			if i >= 7 {
				// Steal is time the hypervisor took from us, and
				// guest time is already in user time.
				break
			}
			c.Total += v
			if i != 3 && i != 4 { // not idle or iowait
				c.Busy += v
			}
		}
		c.NumCPU = runtime.NumCPU()
		writeJSON(w, c)
		return
	}
	http.Error(w, "no cpu line in /proc/stat", http.StatusInternalServerError)
}

func benchParams(r *http.Request) (addr string, dur time.Duration, err error) {
	q := r.URL.Query()
	addr = q.Get("addr")
	if addr == "" {
		return "", 0, errors.New("missing addr")
	}
	dur, err = time.ParseDuration(q.Get("dur"))
	if err != nil {
		return "", 0, fmt.Errorf("dur: %w", err)
	}
	return addr, dur, nil
}

// benchTCP sends as fast as it can to the TCP sink at addr for dur, over
// the given number of streams.
func benchTCP(w http.ResponseWriter, r *http.Request) {
	addr, dur, err := benchParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	streams, _ := strconv.Atoi(r.URL.Query().Get("streams"))
	streams = max(streams, 1)
	netns := r.URL.Query().Get("netns")
	var conns []net.Conn
	for range streams {
		c, err := dialTCPIn(netns, addr)
		if err != nil {
			for _, c := range conns {
				c.Close()
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		conns = append(conns, c)
	}
	var total atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	deadline := start.Add(dur)
	for _, c := range conns {
		wg.Go(func() {
			defer c.Close()
			c.SetWriteDeadline(deadline)
			buf := make([]byte, 128<<10)
			for {
				n, err := c.Write(buf)
				total.Add(int64(n))
				if err != nil {
					return
				}
			}
		})
	}
	wg.Wait()
	writeJSON(w, Result{Bytes: total.Load(), Seconds: time.Since(start).Seconds()})
}

// dialTCPIn connects to addr over TCP from the network namespace
// /run/netns/netns, or the current one if netns is empty.
func dialTCPIn(netns, addr string) (net.Conn, error) {
	if netns == "" {
		return net.DialTimeout("tcp", addr, 10*time.Second)
	}
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		// Sockets belong to the namespace of the thread that makes them.
		// This thread never unlocks, so it exits with the goroutine
		// rather than going back to the scheduler in the other namespace.
		runtime.LockOSThread()
		f, err := os.Open("/run/netns/" + netns)
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer f.Close()
		if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
			ch <- result{err: fmt.Errorf("setns %s: %w", netns, err)}
			return
		}
		c, err := net.DialTimeout("tcp", addr, 10*time.Second)
		ch <- result{c, err}
	}()
	r := <-ch
	return r.c, r.err
}

// benchUDP sends size-byte datagrams as fast as it can to the UDP sink at
// addr for dur.
func benchUDP(w http.ResponseWriter, r *http.Request) {
	addr, dur, err := benchParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	size, _ := strconv.Atoi(r.URL.Query().Get("size"))
	size = min(max(size, 1), 65000)
	gso, _ := strconv.Atoi(r.URL.Query().Get("gso"))
	c, err := net.Dial("udp", addr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer c.Close()
	buf := make([]byte, size)
	buf[0] = benchUDPSink
	perWrite := 1 // datagrams per write
	if gso > 0 {
		rc, err := c.(*net.UDPConn).SyscallConn()
		if err == nil {
			rc.Control(func(fd uintptr) {
				err = unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_SEGMENT, gso)
			})
		}
		if err != nil {
			http.Error(w, "UDP_SEGMENT: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Each datagram the sink receives must start with benchUDPSink.
		for i := 0; i < size; i += gso {
			buf[i] = benchUDPSink
		}
		perWrite = (size + gso - 1) / gso
	}
	var res Result
	start := time.Now()
	deadline := start.Add(dur)
	for i := 0; ; i++ {
		if i%64 == 0 && time.Now().After(deadline) {
			break
		}
		if _, err := c.Write(buf); err != nil {
			// ENOBUFS and the like: back off briefly and keep going.
			time.Sleep(100 * time.Microsecond)
			continue
		}
		res.Packets += int64(perWrite)
		res.Bytes += int64(size)
	}
	res.Seconds = time.Since(start).Seconds()
	writeJSON(w, res)
}

// benchRTT measures UDP round trips to the echo server at addr: n probes,
// interval apart.
func benchRTT(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	addr := q.Get("addr")
	n, _ := strconv.Atoi(q.Get("n"))
	n = max(n, 1)
	interval, err := time.ParseDuration(q.Get("interval"))
	if err != nil {
		interval = 10 * time.Millisecond
	}
	c, err := net.Dial("udp", addr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer c.Close()
	var rtts []float64
	var res RTT
	buf := make([]byte, 64)
	in := make([]byte, 64)
	for i := range n {
		buf[0] = benchUDPEcho
		buf[1] = byte(i)
		buf[2] = byte(i >> 8)
		t0 := time.Now()
		c.SetDeadline(t0.Add(time.Second))
		if _, err := c.Write(buf); err != nil {
			res.Lost++
			continue
		}
		for {
			m, err := c.Read(in)
			if err != nil {
				res.Lost++
				break
			}
			if m >= 3 && in[1] == buf[1] && in[2] == buf[2] {
				rtts = append(rtts, float64(time.Since(t0).Microseconds())/1000)
				break
			}
			// A late reply to an earlier probe; keep waiting.
		}
		time.Sleep(interval)
	}
	res.Samples = len(rtts)
	if len(rtts) > 0 {
		slices.Sort(rtts)
		pct := func(p float64) float64 { return rtts[min(len(rtts)-1, int(p*float64(len(rtts))))] }
		res.P50, res.P90, res.P99, res.Max = pct(0.50), pct(0.90), pct(0.99), rtts[len(rtts)-1]
		var sum float64
		for _, v := range rtts {
			sum += v
		}
		res.Mean = sum / float64(len(rtts))
	}
	writeJSON(w, res)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// cpuidleCPU returns the CPU's busy time as wall time less the time the
// online CPUs spent idle, from their cpuidle state residencies, where the
// kernel has them. /proc/stat can't be trusted for interrupt-heavy loads:
// without CONFIG_IRQ_TIME_ACCOUNTING (as in Ubuntu's AWS kernels),
// interrupt and softirq work done on an otherwise idle CPU is counted as
// idle, which made a router forwarding 9M packets per second look 1%
// busy. Busy and Total are in USER_HZ ticks, as from /proc/stat, but only
// differences between snapshots (with the same CPUs online) mean anything.
func cpuidleCPU() (c CPU, ok bool) {
	b, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return c, false
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return c, false
	}
	nowUsec := ts.Nano() / 1000
	var idleUsec, n int64
	for r := range strings.SplitSeq(strings.TrimSpace(string(b)), ",") {
		lo, hi, isRange := strings.Cut(r, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return c, false
		}
		z := a
		if isRange {
			if z, err = strconv.Atoi(hi); err != nil {
				return c, false
			}
		}
		for cpu := a; cpu <= z; cpu++ {
			states, _ := filepath.Glob(fmt.Sprintf("/sys/devices/system/cpu/cpu%d/cpuidle/state*/time", cpu))
			if len(states) == 0 {
				return c, false
			}
			for _, st := range states {
				v, err := os.ReadFile(st)
				if err != nil {
					return c, false
				}
				us, _ := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64)
				idleUsec += us
			}
			n++
		}
	}
	const usecPerTick = 1e6 / userHZ
	c.Total = nowUsec * n / usecPerTick
	c.Busy = c.Total - idleUsec/usecPerTick
	c.NumCPU = int(n)
	return c, true
}
