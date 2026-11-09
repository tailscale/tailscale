// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

// Package tswgbench has tests and benchmarks of WireGuard data planes
// (the tswg kernel module, the kernel's own WireGuard, and Tailscale's
// wireguard-go) on a pair of lean QEMU VMs, without natlab's simulated
// network, which is too slow for benchmarking and IPv4-only. See
// https://github.com/tailscale/tailscale/issues/426.
//
// The VMs boot the natlab gokrazy kernel with a tiny initramfs whose /init
// is the agent in ./agent, and talk over a host bridge with tap devices
// and vhost-net. Setting up the bridge and taps needs passwordless sudo;
// QEMU itself needs /dev/kvm and /dev/vhost-net.
//
// The tests only run with TSWG_LEAN=1 and need the tswg module tree (see
// tswgDir). With TSWG_DEBUG_KERNEL=1, the VMs boot a debug build of the
// same kernel (KASAN, lockdep and more), which is slow but catches memory
// and locking bugs; look for "BUG:" and "WARNING:" in the consoles, which
// failing tests print.
package tswgbench

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/types/key"
)

// Network layout on the host bridge.
const (
	bridgeName = "tswgb-br"
	tapPrefix  = "tswgb-t" // plus the VM number
	agentPort  = 8080
	wgPort     = 51820
	benchPort  = 5201
)

// Each VM i (0 or 1) gets underlay addresses 10.77.0.(i+2) and
// fd77::(i+2), and tunnel addresses 10.99.0.(i+1) and fd99::(i+1).
var (
	hostIP4 = netip.MustParsePrefix("10.77.0.1/24")
	hostIP6 = netip.MustParsePrefix("fd77::1/64")
)

func underlay4(i int) netip.Addr { return netip.AddrFrom4([4]byte{10, 77, 0, byte(i + 2)}) }
func underlay6(i int) netip.Addr {
	return netip.AddrFrom16([16]byte{0: 0xfd, 1: 0x77, 15: byte(i + 2)})
}
func tunnel4(i int) netip.Addr { return netip.AddrFrom4([4]byte{10, 99, 0, byte(i + 1)}) }
func tunnel6(i int) netip.Addr {
	return netip.AddrFrom16([16]byte{0: 0xfd, 1: 0x99, 15: byte(i + 1)})
}

// tswgDir returns the directory of the tswg kernel module tree, from
// $TSWG_DIR or ~/src/tslinux.
func tswgDir(t testing.TB) string {
	t.Helper()
	dir := os.Getenv("TSWG_DIR")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, "src", "tslinux")
	}
	if _, err := os.Stat(filepath.Join(dir, "scripts", "build-for-gokrazy.sh")); err != nil {
		t.Skipf("tswg module tree not found at %s (set TSWG_DIR): %v", dir, err)
	}
	return dir
}

// requireLab skips the test unless the lab can run.
func requireLab(t testing.TB) {
	t.Helper()
	if os.Getenv("TSWG_LEAN") == "" {
		t.Skip("set TSWG_LEAN=1 to run")
	}
	for _, dev := range []string{"/dev/kvm", "/dev/vhost-net"} {
		if f, err := os.OpenFile(dev, os.O_RDWR, 0); err != nil {
			t.Skipf("need %s: %v", dev, err)
		} else {
			f.Close()
		}
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skipf("need passwordless sudo for the bridge and taps: %v", err)
	}
}

// artifacts are the files the VMs boot, built once per test process.
var artifacts struct {
	once   sync.Once
	err    error
	kernel string // vmlinuz path
	initrd string // initramfs path
	tmpDir string
}

// buildArtifacts builds the agent and tswg.ko and packs them into an
// initramfs.
func buildArtifacts(t testing.TB) (kernel, initrd string) {
	t.Helper()
	artifacts.once.Do(func() {
		artifacts.err = func() error {
			dir, err := os.MkdirTemp("", "tswgbench")
			if err != nil {
				return err
			}
			artifacts.tmpDir = dir
			pkg, err := vmtest.GokrazyKernelPackageDir()
			if err != nil {
				return fmt.Errorf("finding gokrazy kernel: %w", err)
			}
			artifacts.kernel = filepath.Join(pkg, "vmlinuz")
			var koEnv []string
			if os.Getenv("TSWG_DEBUG_KERNEL") != "" {
				// The same kernel with KASAN, lockdep and other
				// checks; see tslinux's scripts/gokrazy-debug-kernel.sh.
				out, err := exec.Command(filepath.Join(tswgDir(t), "scripts", "gokrazy-debug-kernel.sh"), pkg).Output()
				if err != nil {
					return fmt.Errorf("building debug kernel: %w", err)
				}
				kdir := strings.TrimSpace(string(out))
				artifacts.kernel = filepath.Join(kdir, "arch", "x86", "boot", "bzImage")
				koEnv = append(koEnv, "TSWG_KDIR="+kdir)
			}

			agent := filepath.Join(dir, "agent")
			build := exec.Command("go", "build", "-o", agent, "tailscale.com/tstest/tswgbench/agent")
			build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
			if out, err := build.CombinedOutput(); err != nil {
				return fmt.Errorf("building agent: %v\n%s", err, out)
			}

			ko := exec.Command(filepath.Join(tswgDir(t), "scripts", "build-for-gokrazy.sh"), pkg, filepath.Join(dir, "ko"))
			ko.Env = append(os.Environ(), koEnv...)
			var stderr bytes.Buffer
			ko.Stderr = &stderr
			koPath, err := ko.Output()
			if err != nil {
				return fmt.Errorf("building tswg.ko: %v\n%s", err, stderr.Bytes())
			}

			initrd, err := makeInitramfs(map[string]string{
				"init":    agent,
				"tswg.ko": strings.TrimSpace(string(koPath)),
			})
			if err != nil {
				return err
			}
			artifacts.initrd = filepath.Join(dir, "initrd.gz")
			return os.WriteFile(artifacts.initrd, initrd, 0644)
		}()
	})
	if artifacts.err != nil {
		t.Fatal(artifacts.err)
	}
	return artifacts.kernel, artifacts.initrd
}

// makeInitramfs returns a gzipped newc cpio archive with the pseudo
// filesystem mount points, /dev/console, and the given files (archive
// name to host path); "init" is executable.
func makeInitramfs(files map[string]string) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	ino := 1
	add := func(name string, mode, rdevMajor, rdevMinor uint32, data []byte) error {
		hdr := fmt.Sprintf("070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
			ino, mode, 0, 0, 1, 0, len(data), 0, 0, rdevMajor, rdevMinor, len(name)+1, 0)
		ino++
		pad := func(n int) []byte { return make([]byte, (4-n%4)%4) }
		for _, b := range [][]byte{[]byte(hdr), []byte(name), {0}, pad(len(hdr) + len(name) + 1), data, pad(len(data))} {
			if _, err := gz.Write(b); err != nil {
				return err
			}
		}
		return nil
	}
	const (
		dirMode  = 0o040755
		charMode = 0o020600
	)
	for _, d := range []string{"dev", "proc", "sys", "tmp"} {
		if err := add(d, dirMode, 0, 0, nil); err != nil {
			return nil, err
		}
	}
	if err := add("dev/console", charMode, 5, 1, nil); err != nil {
		return nil, err
	}
	for name, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		mode := uint32(0o100644)
		if name == "init" {
			mode = 0o100755
		}
		if err := add(name, mode, 0, 0, data); err != nil {
			return nil, err
		}
	}
	if err := add("TRAILER!!!", 0, 0, 0, nil); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// sudo runs an ip(8) command as root.
func sudo(t testing.TB, args ...string) {
	t.Helper()
	out, err := exec.Command("sudo", append([]string{"-n"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("sudo %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// setupNetwork creates the host bridge and one multiqueue tap per VM
// (owned by the current user, so QEMU needn't be root), removing any left
// over from a previous run, and arranges for their removal.
func setupNetwork(t testing.TB, vms, queues int) {
	t.Helper()
	cleanup := func() {
		for i := range vms {
			exec.Command("sudo", "-n", "ip", "link", "del", fmt.Sprintf("%s%d", tapPrefix, i)).Run()
		}
		exec.Command("sudo", "-n", "ip", "link", "del", bridgeName).Run()
	}
	cleanup()
	t.Cleanup(cleanup)

	user := os.Getenv("USER")
	sudo(t, "ip", "link", "add", bridgeName, "type", "bridge")
	// Keep bridged traffic out of the host's iptables (Docker's FORWARD
	// policy is DROP), in case br_netfilter is loaded.
	exec.Command("sudo", "-n", "ip", "link", "set", bridgeName, "type", "bridge", "nf_call_iptables", "0", "nf_call_ip6tables", "0").Run()
	sudo(t, "ip", "addr", "add", hostIP4.String(), "dev", bridgeName)
	sudo(t, "ip", "-6", "addr", "add", hostIP6.String(), "dev", bridgeName, "nodad")
	sudo(t, "ip", "link", "set", bridgeName, "up")
	for i := range vms {
		tap := fmt.Sprintf("%s%d", tapPrefix, i)
		args := []string{"ip", "tuntap", "add", "dev", tap, "mode", "tap", "user", user}
		if queues > 1 {
			args = append(args, "multi_queue")
		}
		sudo(t, args...)
		sudo(t, "ip", "link", "set", tap, "master", bridgeName)
		sudo(t, "ip", "link", "set", tap, "up")
	}
}

// vm is one of the lab's VMs: a local QEMU VM, or in remote mode, a
// machine elsewhere (see remote_test.go).
type vm struct {
	i      int
	ctl    netip.AddrPort // the agent's address
	under4 netip.Addr     // the underlay addresses the tunnel runs over
	under6 netip.Addr
	client *http.Client

	// console returns the VM's kernel messages so far.
	console func() []byte

	cmd     *exec.Cmd   // QEMU, for local VMs
	logPath string      // QEMU's serial console, for local VMs
	host    *remoteHost // the machine, in remote mode
}

// lab is a set of VMs: a pair for local QEMU VMs, and all the hosts in
// remote mode. Two-VM tests use the first two.
type lab struct {
	t   testing.TB
	vms []*vm

	// setupExtra, if non-nil, adjusts the agent setup query for VM i in
	// setup, for tests that need more routes or allowed IPs.
	setupExtra func(i int, q url.Values)
}

// kernelSplats are console messages that mean a kernel found a bug.
var kernelSplats = []string{
	"BUG:",
	"WARNING:",
	"Oops:",
	"Kernel panic",
	"possible circular locking dependency",
	"INFO: task", // hung task
	"rcu: INFO:",
}

// newLab boots two VMs with cpus virtual CPUs (and as many NIC queues)
// each, or in remote mode (TSWG_REMOTE), sets up the remote machines,
// whatever their size.
func newLab(t testing.TB, cpus int) *lab {
	t.Helper()
	if os.Getenv("TSWG_REMOTE") != "" {
		return newRemoteLab(t)
	}
	requireLab(t)
	kernel, initrd := buildArtifacts(t)
	setupNetwork(t, 2, cpus)

	l := &lab{t: t, vms: make([]*vm, 2)}
	logDir := t.TempDir()
	for i := range l.vms {
		v := &vm{
			i:       i,
			ctl:     netip.AddrPortFrom(underlay4(i), agentPort),
			under4:  underlay4(i),
			under6:  underlay6(i),
			logPath: filepath.Join(logDir, fmt.Sprintf("vm%d.log", i)),
			client:  &http.Client{},
		}
		v.console = func() []byte {
			b, _ := os.ReadFile(v.logPath)
			return b
		}
		netdev := fmt.Sprintf("tap,id=n0,ifname=%s%d,script=no,downscript=no,vhost=on", tapPrefix, i)
		nic := fmt.Sprintf("virtio-net-pci,netdev=n0,mac=52:54:00:77:00:%02x", i+2)
		if cpus > 1 {
			netdev += fmt.Sprintf(",queues=%d", cpus)
			nic += fmt.Sprintf(",mq=on,vectors=%d", 2*cpus+2)
		}
		// Without guest USO, the host splits UDP GSO packets from the
		// other VM before handing them to this one, as a physical
		// network would, so receivers see individual datagrams (and
		// coalesce them with GRO, if they do). With it, VM-to-VM UDP
		// arrives still coalesced, which flatters UDP data planes in a
		// way real networks don't. TSWG_LAB_GUEST_USO=1 enables it.
		if os.Getenv("TSWG_LAB_GUEST_USO") == "" {
			nic += ",guest_uso4=off,guest_uso6=off"
		}
		v.cmd = exec.Command("qemu-system-x86_64",
			"-machine", "q35,accel=kvm",
			"-cpu", "host",
			"-smp", fmt.Sprint(cpus),
			"-m", cmp.Or(os.Getenv("TSWG_LAB_MEM"), "1024"), // MiB
			"-nodefaults", "-no-user-config", "-nographic", "-no-reboot",
			"-kernel", kernel,
			"-initrd", initrd,
			"-append", fmt.Sprintf("console=ttyS0 panic=-1 tswgbench.ip4=%s/24 tswgbench.ip6=%s/64 %s",
				underlay4(i), underlay6(i), os.Getenv("TSWG_LAB_CMDLINE")),
			"-serial", "file:"+v.logPath,
			"-netdev", netdev,
			"-device", nic,
			"-device", "virtio-rng-pci",
		)
		if out, err := v.cmd.StderrPipe(); err == nil {
			go io.Copy(io.Discard, out)
		}
		if err := v.cmd.Start(); err != nil {
			t.Fatalf("starting VM %d: %v", i, err)
		}
		t.Cleanup(func() {
			v.cmd.Process.Kill()
			v.cmd.Wait()
		})
		l.vms[i] = v
	}
	l.checkConsoles()
	for _, v := range l.vms {
		if err := v.waitHealthy(30 * time.Second); err != nil {
			t.Fatalf("VM %d didn't come up: %v\nconsole:\n%s", v.i, err, v.console())
		}
	}
	return l
}

// checkConsoles arranges to fail the test if a VM's kernel reports a bug
// (an oops, a KASAN or lockdep report, a warning), and on failure, to show
// the end of each VM's console, where that would be. Cleanups run in
// reverse order, so this runs before the VMs are killed.
func (l *lab) checkConsoles() {
	t := l.t
	t.Cleanup(func() {
		for _, v := range l.vms {
			log := v.console()
			for _, bad := range kernelSplats {
				if i := bytes.Index(log, []byte(bad)); i >= 0 {
					t.Errorf("VM %d kernel reported %q", v.i, bad)
					break
				}
			}
		}
		if !t.Failed() {
			return
		}
		for _, v := range l.vms {
			log := v.console()
			lines := strings.Split(strings.TrimRight(string(log), "\n"), "\n")
			t.Logf("VM %d console (tail):\n%s", v.i, strings.Join(lines[max(0, len(lines)-150):], "\n"))
		}
	})
}

func (v *vm) url(path string) string {
	return fmt.Sprintf("http://%s/%s", v.ctl, strings.TrimPrefix(path, "/"))
}

func (v *vm) waitHealthy(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", v.url("/health"), nil)
		res, err := v.client.Do(req)
		cancel()
		if err == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				return nil
			}
			err = fmt.Errorf("status %s", res.Status)
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// do makes an HTTP request to the VM's agent and decodes the JSON response
// into v, if non-nil.
func (v *vm) do(method, path string, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, v.url(path), nil)
	if err != nil {
		return err
	}
	res, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("VM %d: %s %s: %s: %s", v.i, method, path, res.Status, bytes.TrimSpace(body))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

// benchNode is a netbench.Node for the VM.
type benchNode struct{ v *vm }

func (b benchNode) Do(method, path string, v any) error { return b.v.do(method, "/bench/"+path, v) }

// The data planes the lab can set up.
const (
	modePlain    = "plain"    // no tunnel
	modeKernelWG = "kernelwg" // the kernel's own WireGuard
	modeTSWG     = "tswg"     // the tswg module
	modeWGGo     = "wggo"     // Tailscale's wireguard-go, with a TUN device
)

var allModes = []string{modePlain, modeKernelWG, modeTSWG, modeWGGo}

// setup sets up a tunnel between the VMs with the given data plane, over
// the IPv4 or IPv6 (if v6) underlay, and returns the address (on VM 1) to
// send traffic to: VM 1's tunnel address of the underlay's family, or,
// for modePlain, its underlay address.
func (l *lab) setup(mode string, v6 bool) netip.Addr {
	l.t.Helper()
	under := func(i int) netip.Addr { return l.vms[i].under4 }
	tun := tunnel4
	if v6 {
		under = func(i int) netip.Addr { return l.vms[i].under6 }
		tun = tunnel6
	}
	for _, v := range l.vms {
		if err := v.do("POST", "/teardown", nil); err != nil {
			l.t.Fatal(err)
		}
	}
	if mode == modePlain {
		// TSWG_LAB_PLAIN_MTU clamps the VMs' paths to each other to that
		// MTU, to compare with tunnels of that MTU at the same packet
		// sizes.
		if mtu := os.Getenv("TSWG_LAB_PLAIN_MTU"); mtu != "" {
			for i, v := range l.vms[:2] {
				q := url.Values{"mode": {modePlain}, "route": {
					netip.PrefixFrom(under(1-i), under(1-i).BitLen()).String() + " dev underlay mtu " + mtu}}
				if err := v.do("POST", "/setup?"+q.Encode(), nil); err != nil {
					l.t.Fatalf("setting up plain: %v", err)
				}
			}
		}
		return under(1)
	}
	keys := [2]key.NodePrivate{key.NewNode(), key.NewNode()}
	for i, v := range l.vms[:2] {
		j := 1 - i
		priv, _ := keys[i].MarshalText()
		q := url.Values{
			"mode":        {mode},
			"private-key": {string(priv)},
			"peer":        {keys[j].Public().String()},
			"endpoint":    {netip.AddrPortFrom(under(j), wgPort).String()},
			"port":        {fmt.Sprint(wgPort)},
			"addrs":       {tunnel4(i).String() + "/24," + tunnel6(i).String() + "/64"},
			"allowed-ips": {tunnel4(j).String() + "/32," + tunnel6(j).String() + "/128"},
		}
		// TSWG_NAPI_THREADED (0 or 1) sets whether the kernel tunnels'
		// NAPI runs in kthreads or softirq.
		if v := os.Getenv("TSWG_NAPI_THREADED"); v != "" && mode != modeWGGo {
			q.Set("napi-threaded", v)
		}
		if l.setupExtra != nil {
			l.setupExtra(i, q)
		}
		if err := v.do("POST", "/setup?"+q.Encode(), nil); err != nil {
			l.t.Fatalf("setting up %s: %v", mode, err)
		}
		// TSWG_MODULE_PARAMS (name=value,...) sets tswg module
		// parameters, for experiments.
		if params := os.Getenv("TSWG_MODULE_PARAMS"); params != "" && mode == modeTSWG {
			for _, kv := range strings.Split(params, ",") {
				name, value, _ := strings.Cut(kv, "=")
				if err := v.do("POST", "/param?"+url.Values{"name": {name}, "value": {value}}.Encode(), nil); err != nil {
					l.t.Fatalf("TSWG_MODULE_PARAMS %s: %v", kv, err)
				}
			}
		}
	}
	return tun(1)
}
