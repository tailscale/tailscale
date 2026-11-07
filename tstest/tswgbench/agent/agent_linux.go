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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
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

// handleSetup sets up the tunnel device wg0 with one peer.
//
// Query parameters:
//
//	mode         plain (no tunnel), kernelwg (the kernel's WireGuard), tswg
//	             (the tswg module, from /tswg.ko), or wggo (Tailscale's
//	             wireguard-go with a TUN device)
//	private-key  privkey:...
//	peer         nodekey:...
//	endpoint     the peer's IP:port
//	port         UDP listen port
//	addrs        comma-separated CIDRs for wg0
//	allowed-ips  comma-separated peer allowed IP prefixes
//	mtu          wg0's MTU (default 1280, Tailscale's)
func handleSetup(w http.ResponseWriter, r *http.Request) {
	if err := setup(r.URL.Query()); err != nil {
		log.Printf("setup: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, "OK\n")
}

func setup(q map[string][]string) error {
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	mode := get("mode")
	if mode == "plain" {
		return nil
	}
	var priv key.NodePrivate
	if err := priv.UnmarshalText([]byte(get("private-key"))); err != nil {
		return fmt.Errorf("private-key: %w", err)
	}
	var peer key.NodePublic
	if err := peer.UnmarshalText([]byte(get("peer"))); err != nil {
		return fmt.Errorf("peer: %w", err)
	}
	ep, err := netip.ParseAddrPort(get("endpoint"))
	if err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	port, err := strconv.ParseUint(get("port"), 10, 16)
	if err != nil {
		return fmt.Errorf("port: %w", err)
	}
	var allowed []netip.Prefix
	for s := range strings.SplitSeq(get("allowed-ips"), ",") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("allowed-ips: %w", err)
		}
		allowed = append(allowed, p)
	}
	mtu := 1280
	if s := get("mtu"); s != "" {
		if mtu, err = strconv.Atoi(s); err != nil {
			return fmt.Errorf("mtu: %w", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	teardownLocked()
	switch mode {
	case "kernelwg", "tswg":
		family, kind := "wireguard", "wireguard"
		if mode == "tswg" {
			moduleOnce.Do(func() {
				var ko []byte
				if ko, moduleErr = os.ReadFile("/tswg.ko"); moduleErr == nil {
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
		if err := c.ConfigureDevice(tunnelDev, tswg.Config{
			PrivateKey: &priv,
			ListenPort: &port16,
			Peers: []tswg.PeerConfig{{
				PublicKey:  peer,
				Endpoint:   ep,
				AllowedIPs: allowed,
			}},
		}); err != nil {
			return err
		}
	case "wggo":
		tdev, err := tun.CreateTUN(tunnelDev, mtu)
		if err != nil {
			return fmt.Errorf("creating TUN: %w", err)
		}
		dev := device.NewDevice(tdev, conn.NewStdNetBind(), device.NewLogger(device.LogLevelError, "wggo: "))
		privRaw, peerRaw := priv.Raw32(), peer.Raw32()
		var uapi strings.Builder
		fmt.Fprintf(&uapi, "private_key=%s\nlisten_port=%d\n", hex.EncodeToString(privRaw[:]), port)
		fmt.Fprintf(&uapi, "public_key=%s\nendpoint=%s\n", hex.EncodeToString(peerRaw[:]), ep)
		for _, p := range allowed {
			fmt.Fprintf(&uapi, "allowed_ip=%s\n", p)
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
	return netlink.LinkSetUp(link)
}

func handleTeardown(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	teardownLocked()
	io.WriteString(w, "OK\n")
}

// teardownLocked removes the tunnel device, if any. mu must be held.
func teardownLocked() {
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
