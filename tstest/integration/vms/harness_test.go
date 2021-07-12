// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

package vms

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/gliderlabs/ssh"
	"golang.org/x/net/proxy"
	"inet.af/netaddr"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
)

type Harness struct {
	testerDialer   proxy.Dialer
	testerDir      string
	bins           *integration.Binaries
	signer         ssh.Signer
	cs             *testcontrol.Server
	loginServerURL string
	testerV4       netaddr.IP
}

func (h *Harness) Tailscale(t *testing.T, args ...string) []byte {
	t.Helper()

	args = append([]string{"--socket=" + filepath.Join(h.testerDir, "sock")}, args...)

	cmd := exec.Command(h.bins.CLI, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}

	return out
}

// makeTestNode creates a userspace tailscaled running in netstack mode that
// enables us to make connections to and from the tailscale network being
// tested. This mutates the Harness to allow tests to dial into the tailscale
// network as well as control the tester's tailscaled.
func (h *Harness) makeTestNode(t *testing.T, bins *integration.Binaries, controlURL string) {
	dir := t.TempDir()
	h.testerDir = dir

	port, err := getProbablyFreePortNumber()
	if err != nil {
		t.Fatalf("can't get free port: %v", err)
	}

	cmd := exec.Command(
		bins.Daemon,
		"--tun=userspace-networking",
		"--state="+filepath.Join(dir, "state.json"),
		"--socket="+filepath.Join(dir, "sock"),
		fmt.Sprintf("--socks5-server=localhost:%d", port),
	)

	cmd.Env = append(
		os.Environ(),
		"NOTIFY_SOCKET="+filepath.Join(dir, "notify_socket"),
		"TS_LOG_TARGET="+h.loginServerURL,
	)

	err = cmd.Start()
	if err != nil {
		t.Fatalf("can't start tailscaled: %v", err)
	}

	t.Cleanup(func() {
		cmd.Process.Kill()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)

outer:
	for {
		select {
		case <-ctx.Done():
			t.Fatal("timed out waiting for tailscaled to come up")
			return
		case <-ticker.C:
			conn, err := net.Dial("unix", filepath.Join(dir, "sock"))
			if err != nil {
				continue
			}

			conn.Close()
			break outer
		}
	}

	run(t, dir, bins.CLI,
		"--socket="+filepath.Join(dir, "sock"),
		"up",
		"--login-server="+controlURL,
		"--hostname=tester",
	)

	dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), nil, &net.Dialer{})
	if err != nil {
		t.Fatalf("can't make netstack proxy dialer: %v", err)
	}
	h.testerDialer = dialer
	h.testerV4 = bytes2Netaddr(h.Tailscale(t, "ip", "-4"))
}

func bytes2Netaddr(inp []byte) netaddr.IP {
	return netaddr.MustParseIP(string(bytes.TrimSpace(inp)))
}
