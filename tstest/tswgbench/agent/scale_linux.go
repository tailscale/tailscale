// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"tailscale.com/types/key"
	"tailscale.com/wgengine/tswg"
)

// ScaleResult is what POST /scale reports.
type ScaleResult struct {
	Peers int
	// Steps are the measurements after each batch of peers added.
	Steps []ScaleStep
	// Op times, in microseconds, at the full peer count: the median of
	// a few of each.
	UpdateEndpointUS float64 // change one peer's endpoint
	ReplaceIPsUS     float64 // replace one peer's allowed IPs
	AddUS            float64 // add one peer
	RemoveUS         float64 // remove one peer
	RenameUS         float64 // change one peer's public key, keeping the rest
	DumpMS           float64 // dump the device with all its peers
	TeardownMS       float64 // delete the device
	TeardownMemKB    int64   // memory the teardown gave back (MemAvailable)
}

// ScaleStep is one measurement of POST /scale.
type ScaleStep struct {
	Peers   int
	AddMS   float64 // to add the batch
	MemKB   map[string]int64
	PerPeer map[string]float64 // bytes per peer added since the start
}

// scaleMeminfo are the /proc/meminfo fields POST /scale reports.
var scaleMeminfo = []string{"MemAvailable", "Slab", "SUnreclaim", "Percpu", "VmallocUsed"}

func readMeminfo() map[string]int64 {
	m := map[string]int64{}
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
		m[k] = n
	}
	return m
}

// handleScale (POST /scale?peers=N&batch=B) measures the tswg module with
// many peers: on a new device, wg1, it adds N peers (default 50000), B at a
// time (default 1000), each with an endpoint and an IPv4 and IPv6 allowed
// IP, measuring time and kernel memory after each batch, then times
// single-peer operations at that size, and deletes the device. The
// module must be loaded (by a tswg /setup).
func handleScale(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	n, _ := strconv.Atoi(q.Get("peers"))
	if n <= 0 {
		n = 50000
	}
	batch, _ := strconv.Atoi(q.Get("batch"))
	if batch <= 0 {
		batch = 1000
	}
	res, err := runScale(n, batch)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

const scaleDev = "wg1"

func runScale(n, batch int) (*ScaleResult, error) {
	tswg.DeleteLink(scaleDev)
	if err := tswg.AddLink(scaleDev); err != nil {
		return nil, err
	}
	defer tswg.DeleteLink(scaleDev)
	c, err := tswg.Open()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	priv := key.NewNode()
	port := uint16(0)
	if err := c.ConfigureDevice(scaleDev, tswg.Config{PrivateKey: &priv, ListenPort: &port}); err != nil {
		return nil, err
	}

	// Peer i gets 100.64.0.0/10's i'th address, fd7a:115c:a1e0::/48's, and
	// an endpoint in 198.18.0.0/15.
	ip4 := func(i int) netip.Addr {
		v := uint32(100<<24|64<<16) + uint32(i) + 1
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	ip6 := func(i int) netip.Addr {
		b := [16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0}
		v := uint32(i) + 1
		b[12], b[13], b[14], b[15] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
		return netip.AddrFrom16(b)
	}
	ep := func(i int) netip.AddrPort {
		v := uint32(198<<24|18<<16) + uint32(i)
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), 41641)
	}
	keys := make([]key.NodePublic, n+16)
	for i := range keys {
		keys[i] = key.NewNode().Public()
	}
	peer := func(i int) tswg.PeerConfig {
		return tswg.PeerConfig{
			PublicKey:         keys[i],
			Endpoint:          ep(i),
			ReplaceAllowedIPs: true,
			AllowedIPs:        []netip.Prefix{netip.PrefixFrom(ip4(i), 32), netip.PrefixFrom(ip6(i), 128)},
		}
	}
	// Netlink messages are bounded; tailscaled sends 32 peers in each.
	const perMsg = 32
	configure := func(peers []tswg.PeerConfig) error {
		for len(peers) > 0 {
			k := min(len(peers), perMsg)
			if err := c.ConfigureDevice(scaleDev, tswg.Config{Peers: peers[:k]}); err != nil {
				return err
			}
			peers = peers[k:]
		}
		return nil
	}

	res := &ScaleResult{Peers: n}
	base := readMeminfo()
	for done := 0; done < n; {
		k := min(batch, n-done)
		peers := make([]tswg.PeerConfig, k)
		for j := range peers {
			peers[j] = peer(done + j)
		}
		start := time.Now()
		if err := configure(peers); err != nil {
			return nil, fmt.Errorf("adding peers %d-%d: %w", done, done+k, err)
		}
		el := time.Since(start)
		done += k
		m := readMeminfo()
		st := ScaleStep{Peers: done, AddMS: float64(el.Microseconds()) / 1000, MemKB: map[string]int64{}, PerPeer: map[string]float64{}}
		for _, f := range scaleMeminfo {
			st.MemKB[f] = m[f]
			d := m[f] - base[f]
			if f == "MemAvailable" {
				d = -d
			}
			st.PerPeer[f] = float64(d) * 1024 / float64(done)
		}
		res.Steps = append(res.Steps, st)
	}

	median := func(f func(i int) error) (float64, error) {
		var ts []float64
		for i := range 9 {
			start := time.Now()
			if err := f(i); err != nil {
				return 0, err
			}
			ts = append(ts, float64(time.Since(start).Nanoseconds())/1000)
		}
		for i := range ts { // insertion sort; 9 of them
			for j := i; j > 0 && ts[j] < ts[j-1]; j-- {
				ts[j], ts[j-1] = ts[j-1], ts[j]
			}
		}
		return ts[len(ts)/2], nil
	}
	if res.UpdateEndpointUS, err = median(func(i int) error {
		return c.ConfigureDevice(scaleDev, tswg.Config{Peers: []tswg.PeerConfig{{
			PublicKey: keys[i*997%n], UpdateOnly: true, Endpoint: ep(n + i)}}})
	}); err != nil {
		return nil, err
	}
	if res.ReplaceIPsUS, err = median(func(i int) error {
		j := i * 991 % n
		return c.ConfigureDevice(scaleDev, tswg.Config{Peers: []tswg.PeerConfig{{
			PublicKey: keys[j], UpdateOnly: true, ReplaceAllowedIPs: true,
			AllowedIPs: []netip.Prefix{netip.PrefixFrom(ip4(j), 32), netip.PrefixFrom(ip6(j), 128)}}}})
	}); err != nil {
		return nil, err
	}
	if res.AddUS, err = median(func(i int) error {
		return c.ConfigureDevice(scaleDev, tswg.Config{Peers: []tswg.PeerConfig{peer(n + i)}})
	}); err != nil {
		return nil, err
	}
	if res.RemoveUS, err = median(func(i int) error {
		return c.ConfigureDevice(scaleDev, tswg.Config{Peers: []tswg.PeerConfig{{PublicKey: keys[n+i], Remove: true}}})
	}); err != nil {
		return nil, err
	}
	// Rename 9 peers to new keys; renaming one to an existing key fails.
	renamed := map[key.NodePublic]int{} // new key -> peer index
	if res.RenameUS, err = median(func(i int) error {
		j := i * 983 % n
		nk := key.NewNode().Public()
		renamed[nk] = j
		err := c.ConfigureDevice(scaleDev, tswg.Config{Peers: []tswg.PeerConfig{{
			PublicKey: keys[j], UpdateOnly: true, NewPublicKey: &nk}}})
		keys[j] = nk
		return err
	}); err != nil {
		return nil, fmt.Errorf("renaming: %w", err)
	}
	dup := keys[1]
	if err := c.ConfigureDevice(scaleDev, tswg.Config{Peers: []tswg.PeerConfig{{
		PublicKey: keys[0], UpdateOnly: true, NewPublicKey: &dup}}}); err == nil {
		return nil, fmt.Errorf("renaming a peer to another's key succeeded")
	}

	start := time.Now()
	d, err := c.Device(scaleDev)
	if err != nil {
		return nil, err
	}
	res.DumpMS = float64(time.Since(start).Microseconds()) / 1000
	if len(d.Peers) != n {
		return nil, fmt.Errorf("dumped %d peers, want %d", len(d.Peers), n)
	}
	found := 0
	for _, p := range d.Peers {
		j, ok := renamed[p.PublicKey]
		if !ok {
			continue
		}
		found++
		want := []netip.Prefix{netip.PrefixFrom(ip4(j), 32), netip.PrefixFrom(ip6(j), 128)}
		if len(p.AllowedIPs) != 2 || !slices.Contains(p.AllowedIPs, want[0]) || !slices.Contains(p.AllowedIPs, want[1]) {
			return nil, fmt.Errorf("renamed peer %d has allowed IPs %v, want %v", j, p.AllowedIPs, want)
		}
		if !p.Endpoint.IsValid() {
			return nil, fmt.Errorf("renamed peer %d lost its endpoint", j)
		}
	}
	if found != len(renamed) {
		return nil, fmt.Errorf("found %d renamed peers, want %d", found, len(renamed))
	}

	before := readMeminfo()
	start = time.Now()
	if err := tswg.DeleteLink(scaleDev); err != nil {
		return nil, err
	}
	res.TeardownMS = float64(time.Since(start).Microseconds()) / 1000
	time.Sleep(2 * time.Second) // RCU frees
	res.TeardownMemKB = readMeminfo()["MemAvailable"] - before["MemAvailable"]
	return res, nil
}
