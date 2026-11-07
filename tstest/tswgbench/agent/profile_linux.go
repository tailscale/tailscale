// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

// This file has a minimal sampling profiler (perf_event_open with CPU-clock
// sampling on every CPU, with callchains), since the VMs have no perf.
// Kernel addresses (including modules such as tswg) resolve through
// /proc/kallsyms, and the agent's own addresses (wireguard-go, in wggo
// mode) through its ELF symbol table.

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ProfileSym is a symbol's share of the profile's samples.
type ProfileSym struct {
	Sym       string
	Self      int     // samples with the symbol at the top of the stack
	Inclusive int     // samples with the symbol anywhere on the stack
	SelfPct   float64 // of all non-idle samples
	InclPct   float64 // likewise
}

// ProfileCPU is one CPU's share of a profile.
type ProfileCPU struct {
	CPU     int
	Samples int
	Busy    float64 // fraction of samples not in the idle loop
	Top     []ProfileSym
}

// ProfileStack is a call stack's share of the samples, for the focus
// symbol of /profile.
type ProfileStack struct {
	Stack   []string // from the focus symbol outward, to its callers
	Samples int
	Pct     float64 // of all non-idle samples
}

// Profile is the result of /profile.
type Profile struct {
	Seconds float64
	Samples int // all, including idle
	Busy    int // non-idle
	Top     []ProfileSym
	CPUs    []ProfileCPU
	Focus   []ProfileStack // if requested, the focus symbol's callers
}

// handleProfile profiles all CPUs for the dur query parameter (default
// 5s) and returns the top symbols (top, default 40) as JSON.
func handleProfile(w http.ResponseWriter, r *http.Request) {
	dur, err := time.ParseDuration(r.URL.Query().Get("dur"))
	if err != nil {
		dur = 5 * time.Second
	}
	top, _ := strconv.Atoi(r.URL.Query().Get("top"))
	focus := r.URL.Query().Get("focus")
	if top <= 0 {
		top = 40
	}
	p, err := profile(dur, top, focus)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

const (
	perfSampleHz     = 4999
	perfMmapPages    = 256               // data pages per CPU; must be a power of two
	perfContextMax   = ^uint64(4095) + 1 // -4095: callchain context markers are above this
	perfRecordSample = 9
)

// perfCPU is the sampling event on one CPU.
type perfCPU struct {
	cpu  int
	fd   int
	mem  []byte
	data []byte
}

// focusDepth is how many frames of the focus symbol's stacks to report.
const focusDepth = 8

func openPerfCPU(cpu int) (*perfCPU, error) {
	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_SOFTWARE,
		Config:      unix.PERF_COUNT_SW_CPU_CLOCK,
		Sample:      perfSampleHz,
		Sample_type: unix.PERF_SAMPLE_IP | unix.PERF_SAMPLE_TID | unix.PERF_SAMPLE_CPU | unix.PERF_SAMPLE_CALLCHAIN,
		Bits:        unix.PerfBitFreq | unix.PerfBitDisabled,
	}
	attr.Size = uint32(unsafe.Sizeof(attr))
	fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("perf_event_open on CPU %d: %w", cpu, err)
	}
	page := os.Getpagesize()
	mem, err := unix.Mmap(fd, 0, (1+perfMmapPages)*page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("mmap perf buffer: %w", err)
	}
	return &perfCPU{cpu: cpu, fd: fd, mem: mem, data: mem[page:]}, nil
}

func (p *perfCPU) close() {
	unix.Munmap(p.mem)
	unix.Close(p.fd)
}

// sample is one profile sample.
type sample struct {
	cpu   int
	pid   uint32
	stack []uint64 // leaf first; no context markers
}

// drain reads the samples in p's ring buffer.
func (p *perfCPU) drain(out []sample) []sample {
	// struct perf_event_mmap_page: data_head at 1024, data_tail at 1032.
	head := atomicLoad64(&p.mem[1024])
	tail := binary.NativeEndian.Uint64(p.mem[1032:])
	size := uint64(len(p.data))
	read := func(off uint64, n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = p.data[(off+uint64(i))%size]
		}
		return b
	}
	for tail < head {
		hdr := read(tail, 8)
		typ := binary.NativeEndian.Uint32(hdr[0:])
		recSize := uint64(binary.NativeEndian.Uint16(hdr[6:]))
		if recSize == 0 {
			break
		}
		if typ == perfRecordSample {
			rec := read(tail+8, int(recSize)-8)
			// IP, then TID (pid, tid), then CPU (cpu, res), then callchain.
			if len(rec) >= 32 {
				s := sample{
					pid: binary.NativeEndian.Uint32(rec[8:]),
					cpu: int(binary.NativeEndian.Uint32(rec[16:])),
				}
				nr := int(binary.NativeEndian.Uint64(rec[24:]))
				for i := 0; i < nr && 32+8*i+8 <= len(rec); i++ {
					ip := binary.NativeEndian.Uint64(rec[32+8*i:])
					if ip >= perfContextMax {
						continue
					}
					s.stack = append(s.stack, ip)
				}
				if len(s.stack) == 0 {
					s.stack = []uint64{binary.NativeEndian.Uint64(rec[0:])}
				}
				out = append(out, s)
			}
		}
		tail += recSize
	}
	binary.NativeEndian.PutUint64(p.mem[1032:], tail)
	return out
}

func atomicLoad64(b *byte) uint64 {
	return *(*uint64)(unsafe.Pointer(b)) // the kernel writes it; good enough on amd64
}

func profile(dur time.Duration, top int, focus string) (*Profile, error) {
	cpus, err := onlineCPUs()
	if err != nil {
		return nil, err
	}
	syms, err := loadSymbols()
	if err != nil {
		return nil, err
	}
	var pcs []*perfCPU
	defer func() {
		for _, p := range pcs {
			p.close()
		}
	}()
	for _, cpu := range cpus {
		p, err := openPerfCPU(cpu)
		if err != nil {
			return nil, err
		}
		pcs = append(pcs, p)
	}
	for _, p := range pcs {
		unix.IoctlSetInt(p.fd, unix.PERF_EVENT_IOC_ENABLE, 0)
	}
	var samples []sample
	start := time.Now()
	for time.Since(start) < dur {
		time.Sleep(20 * time.Millisecond)
		for _, p := range pcs {
			samples = p.drain(samples)
		}
	}
	for _, p := range pcs {
		unix.IoctlSetInt(p.fd, unix.PERF_EVENT_IOC_DISABLE, 0)
		samples = p.drain(samples)
	}

	prof := &Profile{Seconds: time.Since(start).Seconds(), Samples: len(samples)}
	type counts struct{ self, incl map[string]int }
	newCounts := func() counts { return counts{map[string]int{}, map[string]int{}} }
	all := newCounts()
	perCPU := map[int]counts{}
	focusStacks := map[string]int{}
	cpuSamples := map[int]int{}
	cpuBusy := map[int]int{}
	pid := uint32(os.Getpid())
	for _, s := range samples {
		cpuSamples[s.cpu]++
		names := make([]string, len(s.stack))
		for i, ip := range s.stack {
			names[i] = syms.lookup(ip, s.pid == pid)
		}
		if isIdle(names[0]) {
			continue
		}
		prof.Busy++
		cpuBusy[s.cpu]++
		if focus != "" {
			if i := slices.Index(names, focus); i >= 0 {
				callers := names[i:min(len(names), i+focusDepth)]
				focusStacks[strings.Join(callers, "\x00")]++
			}
		}
		c, ok := perCPU[s.cpu]
		if !ok {
			c = newCounts()
			perCPU[s.cpu] = c
		}
		for _, cc := range []counts{all, c} {
			cc.self[names[0]]++
			seen := map[string]bool{}
			for _, n := range names {
				if !seen[n] {
					seen[n] = true
					cc.incl[n]++
				}
			}
		}
	}
	topSyms := func(c counts, busy, n int) []ProfileSym {
		var out []ProfileSym
		for sym, incl := range c.incl {
			out = append(out, ProfileSym{Sym: sym, Self: c.self[sym], Inclusive: incl})
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Self != out[j].Self {
				return out[i].Self > out[j].Self
			}
			return out[i].Inclusive > out[j].Inclusive
		})
		if len(out) > n {
			out = out[:n]
		}
		for i := range out {
			if busy > 0 {
				out[i].SelfPct = 100 * float64(out[i].Self) / float64(busy)
				out[i].InclPct = 100 * float64(out[i].Inclusive) / float64(busy)
			}
		}
		return out
	}
	prof.Top = topSyms(all, prof.Busy, top)
	for st, n := range focusStacks {
		prof.Focus = append(prof.Focus, ProfileStack{
			Stack:   strings.Split(st, "\x00"),
			Samples: n,
			Pct:     100 * float64(n) / float64(max(prof.Busy, 1)),
		})
	}
	sort.Slice(prof.Focus, func(i, j int) bool { return prof.Focus[i].Samples > prof.Focus[j].Samples })
	if len(prof.Focus) > 10 {
		prof.Focus = prof.Focus[:10]
	}
	for _, cpu := range cpus {
		pc := ProfileCPU{CPU: cpu, Samples: cpuSamples[cpu]}
		if pc.Samples > 0 {
			pc.Busy = float64(cpuBusy[cpu]) / float64(pc.Samples)
		}
		if c, ok := perCPU[cpu]; ok {
			pc.Top = topSyms(c, cpuBusy[cpu], 8)
		}
		prof.CPUs = append(prof.CPUs, pc)
	}
	return prof, nil
}

// isIdle reports whether sym is part of the idle loop.
func isIdle(sym string) bool {
	return strings.Contains(sym, "idle") || strings.Contains(sym, "safe_halt") ||
		strings.HasPrefix(sym, "mwait") || sym == "halt"
}

// symTable maps addresses to names.
type symTable struct {
	kernel []symEntry // sorted by addr
	user   []symEntry // the agent's own symbols, sorted by addr
}

type symEntry struct {
	addr uint64
	name string
}

var (
	symsOnce sync.Once
	symsVal  *symTable
	symsErr  error
)

func loadSymbols() (*symTable, error) {
	symsOnce.Do(func() {
		t := &symTable{}
		f, err := os.Open("/proc/kallsyms")
		if err != nil {
			symsErr = err
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 3 {
				continue
			}
			typ := fields[1]
			if typ != "t" && typ != "T" && typ != "w" && typ != "W" {
				continue
			}
			addr, err := strconv.ParseUint(fields[0], 16, 64)
			if err != nil || addr == 0 {
				continue
			}
			name := fields[2]
			if len(fields) >= 4 { // module symbol: "name [module]"
				name += " " + fields[3]
			}
			t.kernel = append(t.kernel, symEntry{addr, name})
		}
		if len(t.kernel) == 0 {
			symsErr = errors.New("no symbols in /proc/kallsyms (kptr_restrict?)")
			return
		}
		slices.SortFunc(t.kernel, func(a, b symEntry) int { return compareU64(a.addr, b.addr) })
		if ef, err := elf.Open("/proc/self/exe"); err == nil {
			if ss, err := ef.Symbols(); err == nil {
				for _, s := range ss {
					if elf.ST_TYPE(s.Info) == elf.STT_FUNC && s.Value != 0 {
						t.user = append(t.user, symEntry{s.Value, s.Name})
					}
				}
			}
			ef.Close()
			slices.SortFunc(t.user, func(a, b symEntry) int { return compareU64(a.addr, b.addr) })
		}
		symsVal = t
	})
	return symsVal, symsErr
}

func compareU64(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (t *symTable) lookup(ip uint64, ours bool) string {
	tab := t.kernel
	if ip < 1<<63 { // user address
		if !ours {
			return "[user]"
		}
		tab = t.user
	}
	i := sort.Search(len(tab), func(i int) bool { return tab[i].addr > ip }) - 1
	if i < 0 {
		return fmt.Sprintf("%#x", ip)
	}
	return tab[i].name
}

// onlineCPUs returns the online CPUs' numbers, from
// /sys/devices/system/cpu/online (such as "0-3,8"). runtime.NumCPU counts
// CPUs taken offline after the process started, too.
func onlineCPUs() ([]int, error) {
	b, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return nil, err
	}
	var cpus []int
	for r := range strings.SplitSeq(strings.TrimSpace(string(b)), ",") {
		lo, hi, isRange := strings.Cut(r, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil, fmt.Errorf("parsing online CPUs %q: %w", b, err)
		}
		z := a
		if isRange {
			if z, err = strconv.Atoi(hi); err != nil {
				return nil, fmt.Errorf("parsing online CPUs %q: %w", b, err)
			}
		}
		for c := a; c <= z; c++ {
			cpus = append(cpus, c)
		}
	}
	return cpus, nil
}
