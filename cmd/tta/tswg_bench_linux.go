// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

// This file has tta's /tswg/bench/ endpoints, a minimal iperf-like toolkit
// for comparing data planes (tswg kernel mode versus wireguard-go) on
// natlab VMs, which have no benchmarking tools of their own.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

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

// BenchStats are the benchmark server's cumulative counters.
type BenchStats struct {
	TCPBytes   int64
	UDPPackets int64
	UDPBytes   int64
}

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
	writeJSON(w, BenchStats{
		TCPBytes:   benchTCPBytes.Load(),
		UDPPackets: benchUDPPackets.Load(),
		UDPBytes:   benchUDPBytes.Load(),
	})
}

// BenchCPU is a snapshot of the node's CPU time, in USER_HZ ticks, summed
// over all CPUs.
type BenchCPU struct {
	Busy, Total int64
	NumCPU      int
}

// benchCPU reports the node's CPU time from /proc/stat.
func benchCPU(w http.ResponseWriter, r *http.Request) {
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
		var c BenchCPU
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

// BenchResult is the result of a benchmark client run.
type BenchResult struct {
	Bytes   int64
	Packets int64
	Seconds float64
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
	var conns []net.Conn
	for range streams {
		c, err := net.DialTimeout("tcp", addr, 10*time.Second)
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
	writeJSON(w, BenchResult{Bytes: total.Load(), Seconds: time.Since(start).Seconds()})
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
	c, err := net.Dial("udp", addr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer c.Close()
	buf := make([]byte, size)
	buf[0] = benchUDPSink
	var res BenchResult
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
		res.Packets++
		res.Bytes += int64(size)
	}
	res.Seconds = time.Since(start).Seconds()
	writeJSON(w, res)
}

// BenchRTT is the result of an RTT run, in milliseconds.
type BenchRTT struct {
	Samples  int
	Lost     int
	P50, P90 float64
	P99, Max float64
	Mean     float64
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
	var res BenchRTT
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
