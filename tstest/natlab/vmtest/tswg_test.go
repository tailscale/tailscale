// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"encoding/json"
	"fmt"
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
// https://github.com/tailscale/tailscale/issues/426), from $TSWG_DIR or
// ~/src/tslinux. It skips the test if the tree isn't there.
func tswgDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("TSWG_DIR")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, "src", "tslinux")
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
		if d.PublicKey != keys[i].Public() {
			t.Errorf("[%s] public key = %v, want %v", n.Name(), d.PublicKey, keys[i].Public())
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
}
