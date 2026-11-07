// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package tswgbench

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Remote mode runs the lean tests on machines elsewhere, such as EC2
// instances from tslinux's scripts/ec2.sh, rather than local QEMU VMs:
// TSWG_REMOTE names a JSON file of remoteHosts (the first two are used).
// Each machine must be a Linux box we can ssh to that has sudo, the build
// tools and headers for its running kernel, and lets us reach port 8080
// (the agent) and lets the machines reach each other on any port.
//
// For each test process, newRemoteLab copies the agent and the tswg
// sources to each machine, builds tswg.ko there against its own kernel,
// and runs the agent as root (systemd unit tswgbench-agent).
//
// While a test uses the machines, it touches the file last-used next to
// the hosts file every minute, which keeps tslinux's ec2-idle-stop.sh from
// stopping them as idle.

// remoteHost is a machine for remote mode, as ec2.sh writes them.
type remoteHost struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Public   string `json:"public"`   // address we reach it (ssh, the agent) on
	Private4 string `json:"private4"` // IPv4 underlay address, for tunnels
	IP6      string `json:"ip6"`      // IPv6 underlay address, for tunnels
	User     string `json:"user"`
	Key      string `json:"key"` // ssh private key file
}

// ssh runs script with sh on h, with stdin as its input, and returns its
// standard output.
func (h remoteHost) ssh(script string, stdin []byte) (string, error) {
	cmd := exec.Command("ssh", "-i", h.Key,
		"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=10",
		h.User+"@"+h.Public, "sh", "-c", shellQuote(script))
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%s: %v\n%s", h.Name, err, stderr.Bytes())
	}
	return stdout.String(), nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// remoteSetupScript stops any previous agent and unloads the module, builds
// tswg.ko from ~/tswg against the running kernel with the compiler that
// built it, and starts the agent.
const remoteSetupScript = `
set -e
sudo systemctl stop tswgbench-agent 2>/dev/null || true
sudo systemctl reset-failed tswgbench-agent 2>/dev/null || true
sudo ip link del wg0 2>/dev/null || true
sudo rmmod tswg 2>/dev/null || true
cc=$(grep -o 'gcc-[0-9]*' /proc/version | head -1)
mkdir -p ~/tswg-cc
ln -sf "/usr/bin/${cc:-gcc}" ~/tswg-cc/gcc
ko=$(PATH=$HOME/tswg-cc:$PATH ~/tswg/scripts/build.sh "/lib/modules/$(uname -r)/build" ~/tswgbuild 2>~/tswg-build.log) ||
	{ tail -40 ~/tswg-build.log >&2; exit 1; }
sudo cp "$ko" /tswg.ko
sudo dmesg -C
sudo systemd-run --quiet --unit=tswgbench-agent --collect "$HOME/tswgbench-agent"
uname -r
`

var remoteArtifacts struct {
	once  sync.Once
	err   error
	agent []byte
	src   []byte // tar of the tswg tree's Makefile, src and scripts
}

func newRemoteLab(t testing.TB) *lab {
	t.Helper()
	if os.Getenv("TSWG_LEAN") == "" {
		t.Skip("set TSWG_LEAN=1 to run")
	}
	b, err := os.ReadFile(os.Getenv("TSWG_REMOTE"))
	if err != nil {
		t.Fatalf("TSWG_REMOTE: %v", err)
	}
	var hosts []remoteHost
	if err := json.Unmarshal(b, &hosts); err != nil {
		t.Fatalf("TSWG_REMOTE: %v", err)
	}
	if len(hosts) < 2 {
		t.Fatalf("TSWG_REMOTE: need 2 hosts, have %d", len(hosts))
	}
	keepInUse(t, filepath.Join(filepath.Dir(os.Getenv("TSWG_REMOTE")), "last-used"))

	dir := tswgDir(t)
	remoteArtifacts.once.Do(func() {
		remoteArtifacts.err = func() error {
			tmp := t.TempDir()
			agent := filepath.Join(tmp, "agent")
			build := exec.Command("go", "build", "-o", agent, "tailscale.com/tstest/tswgbench/agent")
			build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
			if out, err := build.CombinedOutput(); err != nil {
				return fmt.Errorf("building agent: %v\n%s", err, out)
			}
			var err error
			if remoteArtifacts.agent, err = os.ReadFile(agent); err != nil {
				return err
			}
			tar := exec.Command("tar", "-C", dir, "-czf", "-",
				"--exclude=*.o", "--exclude=*.ko", "--exclude=*.cmd", "--exclude=generated/autoconf.h",
				"Makefile", "src", "scripts")
			remoteArtifacts.src, err = tar.Output()
			if err != nil {
				return fmt.Errorf("tar of %s: %v", dir, err)
			}
			return nil
		}()
	})
	if remoteArtifacts.err != nil {
		t.Fatal(remoteArtifacts.err)
	}

	l := &lab{t: t}
	var wg sync.WaitGroup
	errs := make([]error, len(l.vms))
	for i := range l.vms {
		h := hosts[i]
		v := &vm{
			i:      i,
			ctl:    netip.AddrPortFrom(netip.MustParseAddr(h.Public), agentPort),
			client: &http.Client{},
		}
		if v.under4, err = netip.ParseAddr(h.Private4); err != nil {
			t.Fatalf("%s: private4: %v", h.Name, err)
		}
		if h.IP6 != "" {
			if v.under6, err = netip.ParseAddr(h.IP6); err != nil {
				t.Fatalf("%s: ip6: %v", h.Name, err)
			}
		}
		v.console = func() []byte { return []byte(v.getText("/dmesg")) }
		l.vms[i] = v
		wg.Go(func() {
			errs[i] = func() error {
				start := time.Now()
				if _, err := h.ssh("rm -rf ~/tswg && mkdir ~/tswg && tar -C ~/tswg -xzf -", remoteArtifacts.src); err != nil {
					return err
				}
				if _, err := h.ssh("cat > ~/tswgbench-agent.new && chmod +x ~/tswgbench-agent.new && mv ~/tswgbench-agent.new ~/tswgbench-agent", remoteArtifacts.agent); err != nil {
					return err
				}
				kernel, err := h.ssh(remoteSetupScript, nil)
				if err != nil {
					return err
				}
				t.Logf("VM %d is %s (%s, kernel %s), set up in %v", i, h.Name, h.Type,
					strings.TrimSpace(kernel), time.Since(start).Round(time.Second))
				return nil
			}()
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range l.vms {
		if err := v.waitHealthy(30 * time.Second); err != nil {
			t.Fatalf("VM %d didn't come up: %v", v.i, err)
		}
	}
	l.checkConsoles()
	t.Cleanup(func() {
		for _, v := range l.vms {
			v.do("POST", "/teardown", nil)
		}
	})
	return l
}

// keepInUse touches marker now and every minute until the test ends.
func keepInUse(t testing.TB, marker string) {
	touch := func() {
		now := time.Now()
		if err := os.Chtimes(marker, now, now); os.IsNotExist(err) {
			os.WriteFile(marker, nil, 0644)
		}
	}
	touch()
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				touch()
			case <-done:
				return
			}
		}
	}()
	t.Cleanup(func() {
		close(done)
		touch()
	})
}
