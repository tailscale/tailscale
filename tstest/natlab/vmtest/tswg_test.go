// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"bytes"
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
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/types/key"
	"tailscale.com/util/mak"
	"tailscale.com/wgengine/tswg"
)

// tswgDir returns the directory of the tswg kernel module tree (see
// https://github.com/tailscale/tailscale/issues/426), from $TSWG_DIR, or
// else this repo's kernel/linux. It skips the test if the tree isn't there.
func tswgDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("TSWG_DIR")
	if dir == "" {
		dir, _ = filepath.Abs(filepath.Join("..", "..", "..", "kernel", "linux"))
	}
	if _, err := os.Stat(filepath.Join(dir, "scripts", "build-for-ubuntu.sh")); err != nil {
		t.Skipf("tswg module tree not found at %s (set TSWG_DIR): %v", dir, err)
	}
	return dir
}

// tswgFiles builds tswg.ko for kernel release kver and tswgctl for
// linux/amd64 and registers both with the vnet file server under
// "tswg/<kver>/". It only does the work once per kernel release.
type tswgFiles struct {
	t   *testing.T
	env *vmtest.Env
	dir string

	mu   sync.Mutex
	done map[string]bool // kernel releases already registered
}

func (f *tswgFiles) ensure(kver string) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.done[kver] {
		return
	}

	out := filepath.Join(f.t.TempDir(), kver)
	build := exec.Command(filepath.Join(f.dir, "scripts", "build-for-ubuntu.sh"), kver, out)
	var stderr strings.Builder
	build.Stderr = &stderr
	koPath, err := build.Output()
	if err != nil {
		f.t.Fatalf("building tswg.ko for %s: %v\n%s", kver, err, stderr.String())
	}
	ko, err := os.ReadFile(strings.TrimSpace(string(koPath)))
	if err != nil {
		f.t.Fatal(err)
	}

	ctlPath := filepath.Join(out, "tswgctl")
	gobuild := exec.Command("go", "build", "-o", ctlPath, "tailscale.com/cmd/tswgctl")
	gobuild.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := gobuild.CombinedOutput(); err != nil {
		f.t.Fatalf("building tswgctl: %v\n%s", err, out)
	}
	ctl, err := os.ReadFile(ctlPath)
	if err != nil {
		f.t.Fatal(err)
	}

	f.env.RegisterFile("tswg/"+kver+"/tswg.ko", ko)
	f.env.RegisterFile("tswg/"+kver+"/tswgctl", ctl)
	mak.Set(&f.done, kver, true)
}

// ssh runs cmd on n as root over the debug SSH NIC and fails the test on
// error.
func ssh(t *testing.T, env *vmtest.Env, n *vmtest.Node, cmd string) string {
	t.Helper()
	out, err := env.SSHExec(n, cmd)
	if err != nil {
		t.Fatalf("[%s] %s: %v\n%s", n.Name(), cmd, err, out)
	}
	return out
}

// installTSWG builds (if needed) and installs tswg.ko and tswgctl on n and
// loads the module.
func installTSWG(t *testing.T, env *vmtest.Env, files *tswgFiles, n *vmtest.Node) {
	t.Helper()
	kver := strings.TrimSpace(ssh(t, env, n, "uname -r"))
	files.ensure(kver)
	base := "http://52.52.0.6/tswg/" + kver
	ssh(t, env, n, strings.Join([]string{
		"set -e",
		"mkdir -p /lib/modules/" + kver + "/updates",
		"curl -sSf -o /lib/modules/" + kver + "/updates/tswg.ko " + base + "/tswg.ko",
		"curl -sSf -o /usr/local/bin/tswgctl " + base + "/tswgctl",
		"chmod +x /usr/local/bin/tswgctl",
		"depmod -a",
		"modprobe tswg",
	}, "\n"))
	t.Logf("[%s] tswg loaded: %s", n.Name(), strings.TrimSpace(ssh(t, env, n, "dmesg | grep 'tswg:' | tail -2")))
}

// TestTSWGManualTunnel loads the tswg kernel module on two Ubuntu VMs on
// the same LAN, configures a tunnel between them by hand with tswgctl (no
// tailscaled involvement), and checks that pings cross it.
func TestTSWGManualTunnel(t *testing.T) {
	dir := tswgDir(t)
	env := vmtest.New(t)
	lan := env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)
	n1 := env.AddNode("tswg1", lan, vmtest.OS(vmtest.Ubuntu2404), vmtest.DontJoinTailnet())
	n2 := env.AddNode("tswg2", lan, vmtest.OS(vmtest.Ubuntu2404), vmtest.DontJoinTailnet())
	env.Start()

	files := &tswgFiles{t: t, env: env, dir: dir}
	nodes := []*vmtest.Node{n1, n2}
	for _, n := range nodes {
		installTSWG(t, env, files, n)
	}

	const port = 51820
	keys := []key.NodePrivate{key.NewNode(), key.NewNode()}
	tunIP := func(i int) string { return fmt.Sprintf("10.99.0.%d", i+1) }
	for i, n := range nodes {
		j := 1 - i
		priv, _ := keys[i].MarshalText()
		ssh(t, env, n, strings.Join([]string{
			"set -e",
			"ip link add tsw0 type tswg",
			"ip addr add " + tunIP(i) + "/24 dev tsw0",
			fmt.Sprintf("tswgctl set tsw0 -private-key=%s -listen-port=%d -peer=%s -endpoint=%s:%d -allowed-ips=%s/32",
				priv, port, keys[j].Public(), nodes[j].LanIP(lan), port, tunIP(j)),
			"ip link set tsw0 up",
		}, "\n"))
	}

	out := ssh(t, env, n1, "ping -c 3 -W 2 "+tunIP(1))
	t.Logf("ping over tsw0:\n%s", out)

	for i, n := range nodes {
		var d tswg.Device
		if err := json.Unmarshal([]byte(ssh(t, env, n, "tswgctl show tsw0")), &d); err != nil {
			t.Fatalf("[%s] parsing tswgctl show: %v", n.Name(), err)
		}
		checkTSWGDevice(t, n, &d, keys[i].Public(), port)
	}
}

// checkTSWGDevice checks that d, the state of node n's tsw0 device, has the
// given public key and listen port and a single peer that has completed a
// handshake and exchanged traffic.
func checkTSWGDevice(t *testing.T, n *vmtest.Node, d *tswg.Device, pub key.NodePublic, port uint16) {
	t.Helper()
	if d.PublicKey != pub {
		t.Errorf("[%s] public key = %v, want %v", n.Name(), d.PublicKey, pub)
	}
	if d.ListenPort != port {
		t.Errorf("[%s] listen port = %d, want %d", n.Name(), d.ListenPort, port)
	}
	if len(d.Peers) != 1 {
		t.Fatalf("[%s] got %d peers, want 1", n.Name(), len(d.Peers))
	}
	p := d.Peers[0]
	if p.LastHandshake.IsZero() || time.Since(p.LastHandshake) > 5*time.Minute {
		t.Errorf("[%s] peer last handshake = %v; want recent", n.Name(), p.LastHandshake)
	}
	if p.RxBytes == 0 || p.TxBytes == 0 {
		t.Errorf("[%s] peer rx=%d tx=%d; want both nonzero", n.Name(), p.RxBytes, p.TxBytes)
	}
	t.Logf("[%s] peer %v endpoint=%v rx=%d tx=%d handshake=%v",
		n.Name(), p.PublicKey.ShortString(), p.Endpoint, p.RxBytes, p.TxBytes, p.LastHandshake)
}

// buildTSWGForGokrazy builds tswg.ko for the kernel that natlab's gokrazy
// images boot and returns its contents.
func buildTSWGForGokrazy(t *testing.T, dir string) []byte {
	t.Helper()
	pkg, err := vmtest.GokrazyKernelPackageDir()
	if err != nil {
		t.Fatalf("finding gokrazy kernel: %v", err)
	}
	build := exec.Command(filepath.Join(dir, "scripts", "build-for-gokrazy.sh"), pkg, t.TempDir())
	var stderr strings.Builder
	build.Stderr = &stderr
	koPath, err := build.Output()
	if err != nil {
		t.Fatalf("building tswg.ko for gokrazy: %v\n%s", err, stderr.String())
	}
	ko, err := os.ReadFile(strings.TrimSpace(string(koPath)))
	if err != nil {
		t.Fatal(err)
	}
	return ko
}

// tta makes an HTTP request to node n's test agent and returns the response
// body, failing the test on error or a non-200 status.
func tta(t *testing.T, n *vmtest.Node, method, path string, body []byte) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://unused"+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	res, err := n.Agent().HTTPClient.Do(req)
	if err != nil {
		t.Fatalf("[%s] %s %s: %v", n.Name(), method, path, err)
	}
	defer res.Body.Close()
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("[%s] %s %s: reading body: %v", n.Name(), method, path, err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("[%s] %s %s: %s: %s", n.Name(), method, path, res.Status, resBody)
	}
	return string(resBody)
}

// TestTSWGGokrazyManualTunnel is like TestTSWGManualTunnel, but on the
// natlab gokrazy image, which boots a recent upstream kernel and has no
// userspace tools. The test agent loads tswg.ko with init_module(2) and
// configures the device over netlink itself, as tailscaled eventually will.
func TestTSWGGokrazyManualTunnel(t *testing.T) {
	dir := tswgDir(t)
	ko := buildTSWGForGokrazy(t, dir)

	env := vmtest.New(t)
	lan := env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)
	n1 := env.AddNode("tswg1", lan, vmtest.OS(vmtest.Gokrazy), vmtest.DontJoinTailnet())
	n2 := env.AddNode("tswg2", lan, vmtest.OS(vmtest.Gokrazy), vmtest.DontJoinTailnet())
	env.Start()

	nodes := []*vmtest.Node{n1, n2}
	for _, n := range nodes {
		tta(t, n, "POST", "/tswg/load", ko)
		t.Logf("[%s] tswg loaded: %s", n.Name(), strings.TrimSpace(tta(t, n, "GET", "/tswg/dmesg", nil)))
	}

	const port = 51820
	keys := []key.NodePrivate{key.NewNode(), key.NewNode()}
	tunIP := func(i int) string { return fmt.Sprintf("10.99.0.%d", i+1) }
	for i, n := range nodes {
		j := 1 - i
		priv, _ := keys[i].MarshalText()
		q := url.Values{
			"dev":         {"tsw0"},
			"addr":        {tunIP(i) + "/24"},
			"private-key": {string(priv)},
			"listen-port": {fmt.Sprint(port)},
			"peer":        {keys[j].Public().String()},
			"endpoint":    {fmt.Sprintf("%s:%d", nodes[j].LanIP(lan), port)},
			"allowed-ips": {tunIP(j) + "/32"},
		}
		tta(t, n, "POST", "/tswg/up?"+q.Encode(), nil)
	}

	env.LANPing(n1, netip.MustParseAddr(tunIP(1)))

	for i, n := range nodes {
		var d tswg.Device
		if err := json.Unmarshal([]byte(tta(t, n, "GET", "/tswg/show?dev=tsw0", nil)), &d); err != nil {
			t.Fatalf("[%s] parsing /tswg/show: %v", n.Name(), err)
		}
		checkTSWGDevice(t, n, &d, keys[i].Public(), port)
	}
}
