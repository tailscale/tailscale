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
	"testing"
	"time"

	"tailscale.com/tstest/tswgbench/netbench"
	"tailscale.com/types/key"
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
// router without a tunnel, for the ceiling). The clients use
// TSWG_SUBNET_CLIENT_MODE (default tswg), so as not to be the bottleneck.
// Other settings:
//
//	TSWG_SUBNET_CLIENTS      clients to use (default all)
//	TSWG_SUBNET_STREAMS      TCP flows per client (default 16)
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
//	TSWG_SUBNET_ROUTER_STATS if set, log the router's wg0, UDP and TCP
//	                         counters after each run, to see drops
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
	if err := backend.do("POST", fmt.Sprintf("/bench/serve?port=%d", benchPort), nil); err != nil {
		t.Fatal(err)
	}
	cpus := router.getText("/file?" + url.Values{"path": {"/sys/devices/system/cpu/online"}}.Encode())
	t.Logf("router %s (CPUs %s), backend %s, %d clients (%s) with %d flows each, %v runs",
		router.host.Name, strings.TrimSpace(cpus), backend.host.Name, len(clients), clientMode, streams, dur)

	senders := make([]netbench.Node, len(clients))
	for i, c := range clients {
		senders[i] = benchNode{c}
	}
	dst := netip.AddrPortFrom(backend.under4, benchPort)
	type key struct{ mode, metric string }
	results := map[key][]float64{}
	metrics := []string{"Mbps", "router CPU %", "router CPU-s/GB", "fairness", "min client Mbps"}
	for run := range runs {
		for _, mode := range strings.Split(modes, ",") {
			s.setup(mode)
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
			r, err := netbench.RunTCPFanIn(senders, benchNode{backend}, []netbench.Node{benchNode{router}, senders[0]}, dst, streams, dur)
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
			} {
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
	backendRoute := netip.PrefixFrom(s.backend.under4, 32).String()
	if mode == modePlain {
		for _, c := range s.clients {
			route := backendRoute + " via " + s.router.under4.String()
			if m := os.Getenv("TSWG_SUBNET_PLAIN_MTU"); m != "" {
				route += " mtu " + m
			}
			q := url.Values{"mode": {modePlain}, "route": {route}}
			if err := c.do("POST", "/setup?"+q.Encode(), nil); err != nil {
				t.Fatalf("setting up client: %v", err)
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
}
