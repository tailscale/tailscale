// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package tswgbench

import (
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/tstest/tswgbench/netbench"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/tswg/rss"
)

// TestLeanSubnetRouter benchmarks a Tailscale subnet router: many clients,
// each a peer of the router, with many TCP flows each to a backend on the
// router's LAN that isn't on the tailnet. The router forwards between its
// tunnel and the LAN, masquerading the clients (as Tailscale does by
// default, --snat-subnet-routes). It runs only in remote mode, with at
// least three hosts: the router is the first, the backend the second, and
// the clients the rest.
//
// TSWG_LEAN_SUBNET lists the router's data planes to compare (such as
// "tswg,wggo,kernelwg,plain"; plain routes the clients' traffic through the
// router without a tunnel, for the ceiling; tskernel and tstun run real
// tailscaled, in kernel and TUN mode, as in subnet_tailscaled_test.go). The clients use
// TSWG_SUBNET_CLIENT_MODE (default tswg), so as not to be the bottleneck.
// Other settings:
//
//	TSWG_SUBNET_CLIENTS      clients to use (default all)
//	TSWG_SUBNET_STREAMS      TCP flows per client (default 16)
//	TSWG_SUBNET_LOAD         "upload" (the default: the clients send to the
//	                         backend), "fetch" (as HTTP: the clients make
//	                         requests, one at a time per flow, which the
//	                         backend answers with big responses), "serve"
//	                         (fetch, but from the router itself, as a big
//	                         server on the tailnet), or "crawl" (the router
//	                         fetches from all the clients at once, as a
//	                         crawler does)
//	TSWG_SUBNET_FETCH_SIZE   for fetch, the response size (default 1 MiB)
//	TSWG_SUBNET_FETCH_REQ    for fetch, the request size (default 500 bytes)
//	TSWG_SUBNET_ROUTER_CPUS  CPUs to leave online on the router (default all)
//	TSWG_SUBNET_MTU          tunnel MTU (default 1280, Tailscale's; within an
//	                         EC2 VPC, up to 8920 fits the 9001-byte underlay)
//	TSWG_SUBNET_PLAIN_MTU    MTU of the plain mode's client routes (default:
//	                         the underlay's), such as 1280 to send the same
//	                         size packets as through a tunnel of that MTU
//	TSWG_SUBNET_PROFILE      modes whose router to profile during the last run
//	                         (comma-separated), with TSWG_PROFILE_FOCUS as in
//	                         TestLeanProfile
//	TSWG_SUBNET_ROUTER_CMD   a shell command to run on the router after
//	                         each setup, for experiments ($MODE is the mode)
//	TSWG_SUBNET_CLIENT_CMD   likewise, on each client
//	TSWG_SUBNET_RSS_BALANCE  if set, before each measured run, run the load
//	                         for a few seconds and rebalance the router's
//	                         NIC's RSS table during it (see package rss)
//	TSWG_SUBNET_ROUTER_STATS if set, log the router's wg0, UDP and TCP
//	                         counters after each run, to see drops
//	TSWG_SUBNET_PAUSE        a duration to pause after each setup, to debug
//	TSWG_COMPARE_RUNS        runs of each mode, interleaved (default 3)
//	TSWG_BENCH_DUR           length of each run (default 10s)
func TestLeanSubnetRouter(t *testing.T) {
	modes := os.Getenv("TSWG_LEAN_SUBNET")
	if modes == "" {
		t.Skip("set TSWG_LEAN_SUBNET=mode,... (and TSWG_LEAN=1, TSWG_REMOTE) to run")
	}
	if os.Getenv("TSWG_REMOTE") == "" {
		t.Skip("needs remote mode (TSWG_REMOTE) with at least 3 hosts")
	}
	envInt := func(k string, def int) int {
		if s := os.Getenv(k); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil {
				t.Fatalf("%s: %v", k, err)
			}
			return n
		}
		return def
	}
	dur := 10 * time.Second
	if s := os.Getenv("TSWG_BENCH_DUR"); s != "" {
		var err error
		if dur, err = time.ParseDuration(s); err != nil {
			t.Fatalf("TSWG_BENCH_DUR: %v", err)
		}
	}
	clientMode := os.Getenv("TSWG_SUBNET_CLIENT_MODE")
	if clientMode == "" {
		clientMode = modeTSWG
	}
	streams := envInt("TSWG_SUBNET_STREAMS", 16)
	runs := envInt("TSWG_COMPARE_RUNS", 3)
	load := os.Getenv("TSWG_SUBNET_LOAD")
	fetch := load == "fetch" || load == "serve" || load == "crawl"
	fetchSize := envInt("TSWG_SUBNET_FETCH_SIZE", 1<<20)
	fetchReq := envInt("TSWG_SUBNET_FETCH_REQ", 500)

	l := newLab(t, 0)
	if len(l.vms) < 3 {
		t.Fatalf("need at least 3 hosts, have %d", len(l.vms))
	}
	router, backend, clients := l.vms[0], l.vms[1], l.vms[2:]
	if n := envInt("TSWG_SUBNET_CLIENTS", len(clients)); n < len(clients) {
		clients = clients[:n]
	}
	s := &subnetLab{l: l, router: router, backend: backend, clients: clients, clientMode: clientMode}
	s.setupRouter(envInt("TSWG_SUBNET_ROUTER_CPUS", 0))
	for _, v := range append([]*vm{backend, router}, clients...) {
		if err := v.do("POST", fmt.Sprintf("/bench/serve?port=%d", benchPort), nil); err != nil {
			t.Fatal(err)
		}
	}
	cpus := router.getText("/file?" + url.Values{"path": {"/sys/devices/system/cpu/online"}}.Encode())
	t.Logf("router %s (CPUs %s), backend %s, %d clients (%s) with %d flows each, %v runs",
		router.host.Name, strings.TrimSpace(cpus), backend.host.Name, len(clients), clientMode, streams, dur)
	if fetch {
		t.Logf("load: fetches of %d bytes with %d-byte requests", fetchSize, fetchReq)
	}

	senders := make([]netbench.Node, len(clients))
	for i, c := range clients {
		senders[i] = benchNode{c}
	}
	dst := netip.AddrPortFrom(backend.under4, benchPort)
	type key struct{ mode, metric string }
	results := map[key][]float64{}
	metrics := []string{"Mbps", "router CPU %", "router CPU-s/GB", "fairness", "min client Mbps"}
	if fetch {
		metrics = append(metrics, "responses/s")
	}
	for run := range runs {
		for _, mode := range strings.Split(modes, ",") {
			s.setup(mode)
			if d, err := time.ParseDuration(os.Getenv("TSWG_SUBNET_PAUSE")); err == nil {
				t.Logf("pausing %v after setting up %s, for debugging", d, mode)
				time.Sleep(d)
			}
			var prof profileResult
			var profErr error
			profDone := make(chan bool)
			profiling := run == runs-1 && slices.Contains(strings.Split(os.Getenv("TSWG_SUBNET_PROFILE"), ","), mode)
			if profiling {
				go func() {
					defer close(profDone)
					time.Sleep(dur / 4)
					profErr = router.do("GET", "/profile?"+url.Values{
						"dur":   {(dur / 2).String()},
						"top":   {"80"},
						"focus": {os.Getenv("TSWG_PROFILE_FOCUS")},
					}.Encode(), &prof)
				}()
			}
			if os.Getenv("TSWG_SUBNET_RSS_BALANCE") != "" {
				s.rssBalance(mode, load, streams, fetchSize, fetchReq)
			}
			watch := []netbench.Node{benchNode{router}, senders[0]}
			var r netbench.FanInResult
			var err error
			// For serve and crawl, the router is an endpoint, reached
			// at its tunnel address (or underlay, without a tunnel).
			hostAddr := func(v *vm) netip.AddrPort {
				if mode == modePlain {
					return netip.AddrPortFrom(v.under4, benchPort)
				}
				return netip.AddrPortFrom(tunnel4(v.i), benchPort)
			}
			switch {
			case load == "serve":
				r, err = netbench.RunTCPFetch(senders, benchNode{router}, watch, hostAddr(router), streams, fetchSize, fetchReq, dur)
			case load == "crawl":
				var addrs []netip.AddrPort
				for _, c := range clients {
					addrs = append(addrs, hostAddr(c))
				}
				r, err = netbench.RunTCPCrawl(benchNode{router}, addrs, watch, streams, fetchSize, fetchReq, dur)
			case fetch:
				r, err = netbench.RunTCPFetch(senders, benchNode{backend}, watch, dst, streams, fetchSize, fetchReq, dur)
			default:
				r, err = netbench.RunTCPFanIn(senders, benchNode{backend}, watch, dst, streams, dur)
			}
			if err != nil {
				t.Fatalf("%s run %d: %v", mode, run, err)
			}
			if os.Getenv("TSWG_SUBNET_ROUTER_STATS") != "" {
				s.logRouterStats(mode)
			}
			if profiling {
				<-profDone
				if profErr != nil {
					t.Errorf("profiling router: %v", profErr)
				} else {
					t.Logf("router %s profile:\n%s", mode, formatProfile(prof))
				}
			}
			t.Logf("run %d: router %s: %.0f Mbps, router CPU %.0f%% (%.2f CPU-s/GB), backend CPU %.0f%%, client 0 CPU %.0f%%, fairness %.3f, clients %s Mbps",
				run, mode, r.Mbps, 100*r.WatchCPU[0], r.WatchCPUSecPerGB[0], 100*r.ReceiverCPU, 100*r.WatchCPU[1], r.Fairness, fmtMbps(r.SenderMbps))
			for metric, v := range map[string]float64{
				"Mbps":            r.Mbps,
				"router CPU %":    100 * r.WatchCPU[0],
				"router CPU-s/GB": r.WatchCPUSecPerGB[0],
				"fairness":        r.Fairness,
				"min client Mbps": slices.Min(r.SenderMbps),
				"responses/s":     float64(r.Responses) / dur.Seconds(),
			} {
				if metric == "responses/s" && !fetch {
					continue
				}
				results[key{mode, metric}] = append(results[key{mode, metric}], v)
			}
		}
	}
	for _, metric := range metrics {
		for _, mode := range strings.Split(modes, ",") {
			rs := slices.Sorted(slices.Values(results[key{mode, metric}]))
			t.Logf("%-8s %-16s median %9.2f (min %9.2f, max %9.2f, %d runs)",
				mode, metric, rs[len(rs)/2], rs[0], rs[len(rs)-1], len(rs))
		}
	}
}

func fmtMbps(ms []float64) string {
	var parts []string
	for _, m := range ms {
		parts = append(parts, fmt.Sprintf("%.0f", m))
	}
	return strings.Join(parts, "/")
}

// subnetLab is TestLeanSubnetRouter's setup.
type subnetLab struct {
	l          *lab
	router     *vm
	backend    *vm
	clients    []*vm
	clientMode string
	ts         tsState // for the tailscaled modes; see subnet_tailscaled_test.go
}

// rssBalance runs the load briefly and, during it, rebalances the router's
// NIC's RSS table; see TSWG_SUBNET_RSS_BALANCE.
func (s *subnetLab) rssBalance(mode, load string, streams, fetchSize, fetchReq int) {
	t := s.l.t
	senders := make([]netbench.Node, len(s.clients))
	var addrs []netip.AddrPort
	for i, c := range s.clients {
		senders[i] = benchNode{c}
		if mode == modePlain {
			addrs = append(addrs, netip.AddrPortFrom(c.under4, benchPort))
		} else {
			addrs = append(addrs, netip.AddrPortFrom(tunnel4(c.i), benchPort))
		}
	}
	routerAddr := netip.AddrPortFrom(tunnel4(s.router.i), benchPort)
	if mode == modePlain {
		routerAddr = netip.AddrPortFrom(s.router.under4, benchPort)
	}
	dst := netip.AddrPortFrom(s.backend.under4, benchPort)
	const dur = 15 * time.Second // longer than balancing takes
	done := make(chan error, 1)
	go func() {
		var err error
		switch load {
		case "serve":
			_, err = netbench.RunTCPFetch(senders, benchNode{s.router}, nil, routerAddr, streams, fetchSize, fetchReq, dur)
		case "crawl":
			_, err = netbench.RunTCPCrawl(benchNode{s.router}, addrs, nil, streams, fetchSize, fetchReq, dur)
		case "fetch":
			_, err = netbench.RunTCPFetch(senders, benchNode{s.backend}, nil, dst, streams, fetchSize, fetchReq, dur)
		default:
			_, err = netbench.RunTCPFanIn(senders, benchNode{s.backend}, nil, dst, streams, dur)
		}
		done <- err
	}()
	time.Sleep(2 * time.Second)
	var res rss.Result
	if err := s.router.do("POST", "/rss-balance", &res); err != nil {
		t.Errorf("rebalancing the router's RSS table: %v", err)
	} else {
		t.Logf("router RSS: %d queues, busiest/mean %.2f -> %.2f; %d entries probed, %d moved, new key %v",
			res.Queues, rss.MaxOverMean(res.Before), rss.MaxOverMean(res.After), res.Probed, res.Changed, res.NewKey)
	}
	if err := <-done; err != nil {
		t.Fatalf("RSS balancing load: %v", err)
	}
}

// logRouterStats logs the router's wg0 interface counters, UDP and TCP
// counters, and NIC drop counters.
func (s *subnetLab) logRouterStats(mode string) {
	file := func(path string) string {
		return s.router.getText("/file?" + url.Values{"path": {path}}.Encode())
	}
	var lines []string
	for line := range strings.SplitSeq(file("/proc/net/dev"), "\n") {
		if strings.Contains(line, "wg0:") || strings.Contains(line, "Inter-") || strings.Contains(line, " face ") {
			lines = append(lines, line)
		}
	}
	snmp := file("/proc/net/snmp")
	t := s.l.t
	t.Logf("router %s counters:\n%s\n%s\n%s", mode, strings.Join(lines, "\n"), snmpLines(snmp, "Udp:"), snmpLines(snmp, "Ip:"))
	if out, err := s.router.host.ssh(`dev=$(ip -o route get 172.31.0.1 | sed -n "s/.* dev \([^ ]*\).*/\1/p"); sudo ethtool -S $dev | grep -E "drop|miss|err|allowance_exceeded" | grep -v ": 0$"`, nil); err == nil {
		t.Logf("router %s NIC counters (nonzero):\n%s", mode, out)
	}
}

// mtu returns the tunnel MTU to use.
func (s *subnetLab) mtu() string {
	if m := os.Getenv("TSWG_SUBNET_MTU"); m != "" {
		return m
	}
	return "1280"
}

// setupRouter makes the router forward and masquerade traffic to the
// backend's network, with only cpus CPUs online (if nonzero), and arranges
// to undo it all.
func (s *subnetLab) setupRouter(cpus int) {
	t := s.l.t
	h := s.router.host
	script := fmt.Sprintf(`
set -e
sudo sysctl -qw net.ipv4.ip_forward=1
# Plain routing goes in and out the same NIC; don't redirect clients past us.
sudo sysctl -qw net.ipv4.conf.all.send_redirects=0
for f in /proc/sys/net/ipv4/conf/*/send_redirects; do echo 0 | sudo tee $f >/dev/null; done
dev=$(ip -o route get %[1]s | sed -n 's/.* dev \([^ ]*\).*/\1/p')
me=$(ip -o route get %[1]s | sed -n 's/.* src \([^ ]*\).*/\1/p')
sudo nft delete table ip tswgbench 2>/dev/null || true
sudo nft add table ip tswgbench
sudo nft add chain ip tswgbench post '{ type nat hook postrouting priority srcnat; }'
sudo nft add rule ip tswgbench post oifname "$dev" ip saddr != "$me" masquerade
n=0
for c in /sys/devices/system/cpu/cpu[0-9]*; do
	[ -f $c/online ] || continue
	cpu=${c##*cpu}
	if [ %[2]d -gt 0 ] && [ $cpu -ge %[2]d ]; then
		echo 0 | sudo tee $c/online >/dev/null
	else
		echo 1 | sudo tee $c/online >/dev/null
	fi
done
`, s.backend.under4, cpus)
	if _, err := h.ssh(script, nil); err != nil {
		t.Fatalf("setting up router: %v", err)
	}
	// Clients mustn't take redirects around the router either.
	for _, c := range s.clients {
		if _, err := c.host.ssh("for f in /proc/sys/net/ipv4/conf/*/accept_redirects; do echo 0 | sudo tee $f >/dev/null; done", nil); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		h.ssh(`
sudo nft delete table ip tswgbench 2>/dev/null || true
for c in /sys/devices/system/cpu/cpu[0-9]*/online; do echo 1 | sudo tee $c >/dev/null; done
`, nil)
	})
}

// setup sets up the router's data plane, mode, and the clients' tunnels
// (or for modePlain, routes) to it.
func (s *subnetLab) setup(mode string) {
	t := s.l.t
	for _, v := range s.l.vms {
		if err := v.do("POST", "/teardown", nil); err != nil {
			t.Fatal(err)
		}
	}
	if isTailscaledMode(mode) {
		s.setupTailscaled(mode == modeTSKernel)
		return
	}
	s.stopTailscaled()
	backendRoute := netip.PrefixFrom(s.backend.under4, 32).String()
	if mode == modePlain {
		// With TSWG_SUBNET_PLAIN_MTU, the direct paths between the
		// router and the clients (for the serve and crawl loads) get
		// that MTU too, on the underlay device.
		mtu := os.Getenv("TSWG_SUBNET_PLAIN_MTU")
		direct := func(to netip.Addr) []string {
			if mtu == "" {
				return nil
			}
			return []string{netip.PrefixFrom(to, 32).String() + " dev underlay mtu " + mtu}
		}
		var routerRoutes []string
		for _, c := range s.clients {
			route := backendRoute + " via " + s.router.under4.String()
			if mtu != "" {
				route += " mtu " + mtu
			}
			q := url.Values{"mode": {modePlain}, "route": append([]string{route}, direct(s.router.under4)...)}
			if err := c.do("POST", "/setup?"+q.Encode(), nil); err != nil {
				t.Fatalf("setting up client: %v", err)
			}
			routerRoutes = append(routerRoutes, direct(c.under4)...)
		}
		if len(routerRoutes) > 0 {
			q := url.Values{"mode": {modePlain}, "route": routerRoutes}
			if err := s.router.do("POST", "/setup?"+q.Encode(), nil); err != nil {
				t.Fatalf("setting up router: %v", err)
			}
		}
		return
	}
	routerKey := key.NewNode()
	clientKeys := make([]key.NodePrivate, len(s.clients))
	rq := url.Values{
		"mode":  {mode},
		"port":  {fmt.Sprint(wgPort)},
		"addrs": {tunnel4(s.router.i).String() + "/24"},
		"mtu":   {s.mtu()},
	}
	rpriv, _ := routerKey.MarshalText()
	rq.Set("private-key", string(rpriv))
	for i, c := range s.clients {
		clientKeys[i] = key.NewNode()
		rq.Add("peer", clientKeys[i].Public().String())
		rq.Add("endpoint", netip.AddrPortFrom(c.under4, wgPort).String())
		rq.Add("allowed-ips", netip.PrefixFrom(tunnel4(c.i), 32).String())
	}
	if err := s.router.do("POST", "/setup?"+rq.Encode(), nil); err != nil {
		t.Fatalf("setting up router (%s): %v", mode, err)
	}
	if cmd := os.Getenv("TSWG_SUBNET_ROUTER_CMD"); cmd != "" {
		if out, err := s.router.host.ssh("MODE="+mode+"; "+cmd, nil); err != nil {
			t.Fatalf("TSWG_SUBNET_ROUTER_CMD: %v", err)
		} else if out != "" {
			t.Logf("router command: %s", strings.TrimSpace(out))
		}
	}
	for i, c := range s.clients {
		priv, _ := clientKeys[i].MarshalText()
		q := url.Values{
			"mode":        {s.clientMode},
			"private-key": {string(priv)},
			"peer":        {routerKey.Public().String()},
			"endpoint":    {netip.AddrPortFrom(s.router.under4, wgPort).String()},
			"allowed-ips": {netip.PrefixFrom(tunnel4(s.router.i), 32).String() + "," + backendRoute},
			"port":        {fmt.Sprint(wgPort)},
			"addrs":       {tunnel4(c.i).String() + "/24"},
			"route":       {backendRoute},
			"mtu":         {s.mtu()},
		}
		if err := c.do("POST", "/setup?"+q.Encode(), nil); err != nil {
			t.Fatalf("setting up client %d: %v", i, err)
		}
	}
	if cmd := os.Getenv("TSWG_SUBNET_CLIENT_CMD"); cmd != "" {
		var wg sync.WaitGroup
		for _, c := range s.clients {
			wg.Go(func() {
				if _, err := c.host.ssh("MODE="+s.clientMode+"; "+cmd, nil); err != nil {
					t.Errorf("TSWG_SUBNET_CLIENT_CMD on %s: %v", c.host.Name, err)
				}
			})
		}
		wg.Wait()
	}
}
