// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The agent command is the /init of the tswgbench VMs: a tiny initramfs
// that boots straight into it. It brings up the VM's network from the
// kernel command line and serves an HTTP API for the host to set up a
// tunnel with one of several data planes and to run benchmarks over it.
//
// Kernel command line parameters:
//
//	tswgbench.ip4=CIDR  the VM's IPv4 address on eth0
//	tswgbench.ip6=CIDR  the VM's IPv6 address on eth0
//
// HTTP API, on port 8080:
//
//	GET  /health
//	POST /setup?mode=MODE&...   set up wg0; see setup
//	POST /teardown              remove wg0
//	GET  /show                  tswg or kernel WireGuard device state (JSON)
//	POST /shutdown              power off
//	     /bench/...             see tailscale.com/tstest/tswgbench/netbench
package main

import (
	"bytes"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/netlink"
	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
	"tailscale.com/tstest/tswgbench/netbench"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/tswg"
)

const tunnelDev = "wg0"

func main() {
	log.SetFlags(log.Lmicroseconds)
	log.SetPrefix("agent: ")
	if os.Getpid() == 1 {
		if err := setupInit(); err != nil {
			log.Fatalf("init: %v", err)
		}
	}
	params, err := cmdlineParams()
	if err != nil {
		log.Fatal(err)
	}
	// On a machine that's already networked (an EC2 instance, in the
	// harness's remote mode), there are no tswgbench parameters, and we
	// leave the network alone.
	if params["tswgbench.ip4"] != "" || params["tswgbench.ip6"] != "" {
		if err := setupNetwork(params["tswgbench.ip4"], params["tswgbench.ip6"]); err != nil {
			log.Fatalf("network: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "OK\n") })
	mux.HandleFunc("POST /setup", handleSetup)
	mux.HandleFunc("POST /teardown", handleTeardown)
	mux.HandleFunc("GET /show", handleShow)
	mux.HandleFunc("GET /profile", handleProfile)
	// Debugging: read a /proc or /sys file, and the kernel log.
	mux.HandleFunc("GET /file", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("path")
		if !strings.HasPrefix(p, "/proc/") && !strings.HasPrefix(p, "/sys/") {
			http.Error(w, "only /proc and /sys", http.StatusBadRequest)
			return
		}
		b, err := os.ReadFile(p)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(b)
	})
	mux.HandleFunc("GET /dmesg", handleDmesg)
	mux.HandleFunc("POST /shutdown", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "OK\n")
		go func() {
			time.Sleep(100 * time.Millisecond)
			unix.Sync()
			unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
		}()
	})
	netbench.Register(mux, "/bench/")
	log.Printf("serving on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// setupInit does what an init system would: mounts the pseudo
// filesystems.
func setupInit() error {
	for _, m := range []struct{ src, dst, fstype string }{
		{"proc", "/proc", "proc"},
		{"sysfs", "/sys", "sysfs"},
		{"devtmpfs", "/dev", "devtmpfs"},
		{"tmpfs", "/tmp", "tmpfs"},
	} {
		os.MkdirAll(m.dst, 0755)
		if err := unix.Mount(m.src, m.dst, m.fstype, 0, ""); err != nil && !errors.Is(err, unix.EBUSY) {
			return fmt.Errorf("mounting %s: %w", m.dst, err)
		}
	}
	return nil
}

// cmdlineParams returns the key=value parameters on the kernel command
// line.
func cmdlineParams() (map[string]string, error) {
	b, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, f := range strings.Fields(string(b)) {
		if k, v, ok := strings.Cut(f, "="); ok {
			m[k] = v
		}
	}
	return m, nil
}

// setupNetwork brings up lo and eth0 with the given addresses.
func setupNetwork(ip4, ip6 string) error {
	// Skip IPv6 duplicate address detection, which would delay using the
	// addresses for a second or so.
	for _, f := range []string{"/proc/sys/net/ipv6/conf/all/accept_dad", "/proc/sys/net/ipv6/conf/default/accept_dad"} {
		os.WriteFile(f, []byte("0"), 0644)
	}
	for _, name := range []string{"lo", "eth0"} {
		link, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
	}
	return addAddrs("eth0", ip4, ip6)
}

// addAddrs adds the non-empty addresses (CIDRs) to the device named dev.
func addAddrs(dev string, cidrs ...string) error {
	link, err := netlink.LinkByName(dev)
	if err != nil {
		return err
	}
	for _, c := range cidrs {
		if c == "" {
			continue
		}
		a, err := netlink.ParseAddr(c)
		if err != nil {
			return err
		}
		a.Flags = unix.IFA_F_NODAD
		if err := netlink.AddrReplace(link, a); err != nil {
			return fmt.Errorf("adding %s to %s: %w", c, dev, err)
		}
	}
	return nil
}

var (
	mu         sync.Mutex
	wggoDev    *device.Device // in wggo mode
	moduleOnce sync.Once
	moduleErr  error
)

// handleSetup sets up the tunnel device wg0 and routes.
//
// Query parameters:
//
//	mode         plain (no tunnel), kernelwg (the kernel's WireGuard), tswg
//	             (the tswg module, from /tswg.ko), or wggo (Tailscale's
//	             wireguard-go with a TUN device)
//	private-key  privkey:...
//	peer         nodekey:..., repeated for each peer
//	endpoint     each peer's IP:port, in the same order
//	allowed-ips  each peer's comma-separated allowed IP prefixes, in the
//	             same order
//	port         UDP listen port
//	addrs        comma-separated CIDRs for wg0
//	mtu          wg0's MTU (default 1280, Tailscale's)
//	napi-threaded  if set, 0 or 1, written to wg0's sysfs "threaded"
//	             (whether its NAPI runs in kthreads or softirq)
//	route        a route to add, repeated: "PREFIX" (via wg0) or "PREFIX
//	             via GATEWAY" (on the underlay, also in plain mode),
//	             optionally followed by " mtu N" (which also sets the MSS
//	             TCP advertises); teardown removes them
func handleSetup(w http.ResponseWriter, r *http.Request) {
	if err := setup(r.URL.Query()); err != nil {
		log.Printf("setup: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, "OK\n")
}

// peerSetup is one peer of wg0.
type peerSetup struct {
	key      key.NodePublic
	endpoint netip.AddrPort
	allowed  []netip.Prefix
}

func setup(q map[string][]string) error {
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	mode := get("mode")
	mu.Lock()
	defer mu.Unlock()
	teardownLocked()
	if mode == "plain" {
		return addRoutes(q["route"])
	}
	var priv key.NodePrivate
	if err := priv.UnmarshalText([]byte(get("private-key"))); err != nil {
		return fmt.Errorf("private-key: %w", err)
	}
	if len(q["endpoint"]) != len(q["peer"]) || len(q["allowed-ips"]) != len(q["peer"]) {
		return fmt.Errorf("need an endpoint and allowed-ips for each of %d peers", len(q["peer"]))
	}
	var peers []peerSetup
	for i, pk := range q["peer"] {
		var p peerSetup
		if err := p.key.UnmarshalText([]byte(pk)); err != nil {
			return fmt.Errorf("peer: %w", err)
		}
		var err error
		if p.endpoint, err = netip.ParseAddrPort(q["endpoint"][i]); err != nil {
			return fmt.Errorf("endpoint: %w", err)
		}
		for s := range strings.SplitSeq(q["allowed-ips"][i], ",") {
			pfx, err := netip.ParsePrefix(s)
			if err != nil {
				return fmt.Errorf("allowed-ips: %w", err)
			}
			p.allowed = append(p.allowed, pfx)
		}
		peers = append(peers, p)
	}
	port, err := strconv.ParseUint(get("port"), 10, 16)
	if err != nil {
		return fmt.Errorf("port: %w", err)
	}
	mtu := 1280
	if s := get("mtu"); s != "" {
		if mtu, err = strconv.Atoi(s); err != nil {
			return fmt.Errorf("mtu: %w", err)
		}
	}

	switch mode {
	case "kernelwg", "tswg":
		family, kind := "wireguard", "wireguard"
		if mode == "tswg" {
			moduleOnce.Do(func() {
				var ko []byte
				if ko, moduleErr = os.ReadFile("/tswg.ko"); moduleErr == nil {
					loadModuleDeps(ko)
					moduleErr = tswg.LoadModule(ko)
				}
			})
			if moduleErr != nil {
				return moduleErr
			}
			family, kind = tswg.FamilyName, tswg.LinkType
		}
		if err := tswg.AddLinkType(tunnelDev, kind); err != nil {
			return err
		}
		c, err := tswg.OpenFamily(family)
		if err != nil {
			return err
		}
		defer c.Close()
		port16 := uint16(port)
		cfg := tswg.Config{PrivateKey: &priv, ListenPort: &port16}
		for _, p := range peers {
			cfg.Peers = append(cfg.Peers, tswg.PeerConfig{
				PublicKey:  p.key,
				Endpoint:   p.endpoint,
				AllowedIPs: p.allowed,
			})
		}
		if err := c.ConfigureDevice(tunnelDev, cfg); err != nil {
			return err
		}
	case "wggo":
		tdev, err := tun.CreateTUN(tunnelDev, mtu)
		if err != nil {
			return fmt.Errorf("creating TUN: %w", err)
		}
		dev := device.NewDevice(tdev, conn.NewStdNetBind(), device.NewLogger(device.LogLevelError, "wggo: "))
		privRaw := priv.Raw32()
		var uapi strings.Builder
		fmt.Fprintf(&uapi, "private_key=%s\nlisten_port=%d\n", hex.EncodeToString(privRaw[:]), port)
		for _, p := range peers {
			peerRaw := p.key.Raw32()
			fmt.Fprintf(&uapi, "public_key=%s\nendpoint=%s\n", hex.EncodeToString(peerRaw[:]), p.endpoint)
			for _, pfx := range p.allowed {
				fmt.Fprintf(&uapi, "allowed_ip=%s\n", pfx)
			}
		}
		if err := dev.IpcSet(uapi.String()); err != nil {
			dev.Close()
			return fmt.Errorf("configuring wireguard-go: %w", err)
		}
		if err := dev.Up(); err != nil {
			dev.Close()
			return err
		}
		wggoDev = dev
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}

	link, err := netlink.LinkByName(tunnelDev)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return err
	}
	if err := addAddrs(tunnelDev, strings.Split(get("addrs"), ",")...); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	if v := get("napi-threaded"); v != "" {
		if err := os.WriteFile("/sys/class/net/"+tunnelDev+"/threaded", []byte(v), 0644); err != nil {
			return fmt.Errorf("napi-threaded: %w", err)
		}
	}
	return addRoutes(q["route"])
}

// loadModuleDeps loads the modules that the kernel module image ko depends
// on (its .modinfo "depends="), as modprobe would: where they're modules
// rather than built in, as on Ubuntu (udp_tunnel, libcurve25519), loading
// ko itself would fail with unknown symbols. Failures are left for loading
// ko to report.
func loadModuleDeps(ko []byte) {
	f, err := elf.NewFile(bytes.NewReader(ko))
	if err != nil {
		return
	}
	sec := f.Section(".modinfo")
	if sec == nil {
		return
	}
	info, err := sec.Data()
	if err != nil {
		return
	}
	for kv := range bytes.SplitSeq(info, []byte{0}) {
		deps, ok := bytes.CutPrefix(kv, []byte("depends="))
		if !ok {
			continue
		}
		for dep := range strings.SplitSeq(string(deps), ",") {
			if dep == "" {
				continue
			}
			if out, err := exec.Command("modprobe", dep).CombinedOutput(); err != nil {
				log.Printf("modprobe %s: %v: %s", dep, err, bytes.TrimSpace(out))
			}
		}
	}
}

// routes are the routes setup added, for teardown to remove. mu guards it.
var routes []*netlink.Route

// addRoutes adds routes (see handleSetup's route parameter). mu must be
// held.
func addRoutes(specs []string) error {
	for _, spec := range specs {
		rest, mtuStr, hasMTU := strings.Cut(spec, " mtu ")
		dst, via, hasVia := strings.Cut(rest, " via ")
		pfx, err := netip.ParsePrefix(dst)
		if err != nil {
			return fmt.Errorf("route %q: %w", spec, err)
		}
		r := &netlink.Route{Dst: &net.IPNet{
			IP:   pfx.Addr().AsSlice(),
			Mask: net.CIDRMask(pfx.Bits(), pfx.Addr().BitLen()),
		}}
		if hasVia {
			gw, err := netip.ParseAddr(via)
			if err != nil {
				return fmt.Errorf("route %q: %w", spec, err)
			}
			r.Gw = gw.AsSlice()
		} else {
			link, err := netlink.LinkByName(tunnelDev)
			if err != nil {
				return err
			}
			r.LinkIndex = link.Attrs().Index
		}
		if hasMTU {
			mtu, err := strconv.Atoi(mtuStr)
			if err != nil {
				return fmt.Errorf("route %q: %w", spec, err)
			}
			r.MTU = mtu
			r.AdvMSS = mtu - 40 // IPv4 and TCP headers
		}
		if err := netlink.RouteReplace(r); err != nil {
			return fmt.Errorf("route %q: %w", spec, err)
		}
		routes = append(routes, r)
	}
	return nil
}

func handleTeardown(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	teardownLocked()
	io.WriteString(w, "OK\n")
}

// teardownLocked removes the tunnel device, if any. mu must be held.
func teardownLocked() {
	for _, r := range routes {
		netlink.RouteDel(r)
	}
	routes = nil
	if wggoDev != nil {
		wggoDev.Close()
		wggoDev = nil
	}
	if link, err := netlink.LinkByName(tunnelDev); err == nil {
		netlink.LinkDel(link)
	}
}

// handleDmesg writes the kernel log, read from /dev/kmsg with raw syscalls
// (an *os.File would block in the netpoller at the end of the log).
func handleDmesg(w http.ResponseWriter, r *http.Request) {
	fd, err := unix.Open("/dev/kmsg", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer unix.Close(fd)
	buf := make([]byte, 8192)
	for {
		n, err := unix.Read(fd, buf)
		if err == unix.EINTR || err == unix.EPIPE {
			continue
		}
		if err != nil || n <= 0 {
			return
		}
		if _, msg, ok := strings.Cut(string(buf[:n]), ";"); ok {
			io.WriteString(w, msg)
		}
	}
}

// handleShow writes the state of the tswg or kernel WireGuard device wg0
// as JSON, without its private key.
func handleShow(w http.ResponseWriter, r *http.Request) {
	family := tswg.FamilyName
	if link, err := netlink.LinkByName(tunnelDev); err == nil && link.Type() == "wireguard" {
		family = "wireguard"
	}
	c, err := tswg.OpenFamily(family)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer c.Close()
	d, err := c.Device(tunnelDev)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d.PrivateKey = key.NodePrivate{}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(d)
}
