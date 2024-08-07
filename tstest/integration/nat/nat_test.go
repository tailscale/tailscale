// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
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

	"golang.org/x/sync/errgroup"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tstest/natlab/vnet"
)

type natTest struct {
	tb      testing.TB
	base    string // base image
	tempDir string // for qcow2 images
	vnet    *vnet.Server
}

func newNatTest(tb testing.TB) *natTest {
	nt := &natTest{
		tb:      tb,
		tempDir: tb.TempDir(),
		base:    "/Users/bradfitz/src/tailscale.com/gokrazy/tsapp.qcow2",
	}

	if _, err := os.Stat(nt.base); err != nil {
		tb.Skipf("skipping test; base image %q not found", nt.base)
	}
	return nt
}

type addNodeFunc func(c *vnet.Config) *vnet.Node

func easy(c *vnet.Config) *vnet.Node {
	n := c.NumNodes() + 1
	return c.AddNode(c.AddNetwork(
		fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
		fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyNAT))
}

func hard(c *vnet.Config) *vnet.Node {
	n := c.NumNodes() + 1
	return c.AddNode(c.AddNetwork(
		fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
		fmt.Sprintf("10.0.%d.1/24", n), vnet.HardNAT))
}

func (nt *natTest) runTest(node1, node2 addNodeFunc) {
	t := nt.tb

	var c vnet.Config
	nodes := []*vnet.Node{
		node1(&c),
		node2(&c),
	}

	var err error
	nt.vnet, err = vnet.New(&c)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	nt.tb.Cleanup(func() {
		nt.vnet.Close()
	})

	var wg sync.WaitGroup // waiting for srv.Accept goroutine
	defer wg.Wait()

	sockAddr := filepath.Join(nt.tempDir, "qemu.sock")
	srv, err := net.Listen("unix", sockAddr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			go nt.vnet.ServeUnixConn(c.(*net.UnixConn), vnet.ProtocolQEMU)
		}
	}()

	for i, node := range nodes {
		disk := fmt.Sprintf("%s/node-%d.qcow2", nt.tempDir, i)
		out, err := exec.Command("qemu-img", "create",
			"-f", "qcow2",
			"-F", "qcow2",
			"-b", nt.base,
			disk).CombinedOutput()
		if err != nil {
			t.Fatalf("qemu-img create: %v, %s", err, out)
		}

		cmd := exec.Command("qemu-system-x86_64",
			"-M", "microvm,isa-serial=off",
			"-m", "1G",
			"-nodefaults", "-no-user-config", "-nographic",
			"-kernel", "/Users/bradfitz/src/github.com/tailscale/gokrazy-kernel/vmlinuz",
			"-append", "console=hvc0 root=PARTUUID=60c24cc1-f3f9-427a-8199-dd02023b0001/PARTNROFF=1 ro init=/gokrazy/init panic=10 oops=panic pci=off nousb tsc=unstable clocksource=hpet tailscale-tta=1",
			"-drive", "id=blk0,file="+disk+",format=qcow2",
			"-device", "virtio-blk-device,drive=blk0",
			"-netdev", "stream,id=net0,addr.type=unix,addr.path="+sockAddr,
			"-device", "virtio-serial-device",
			"-device", "virtio-net-device,netdev=net0,mac="+node.MAC().String(),
			"-chardev", "stdio,id=virtiocon0,mux=on",
			"-device", "virtconsole,chardev=virtiocon0",
			"-mon", "chardev=virtiocon0,mode=readline",
			"-audio", "none",
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatalf("qemu: %v", err)
		}
		nt.tb.Cleanup(func() {
			cmd.Process.Kill()
			cmd.Wait()
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c1 := &http.Client{Transport: nt.vnet.NodeAgentRoundTripper(nodes[0])}
	c2 := &http.Client{Transport: nt.vnet.NodeAgentRoundTripper(nodes[1])}

	var eg errgroup.Group
	var sts [2]*ipnstate.Status
	for i, c := range []*http.Client{c1, c2} {
		i, c := i, c
		eg.Go(func() error {
			st, err := status(ctx, c)
			if err != nil {
				return fmt.Errorf("node%d status: %w", i, err)
			}
			t.Logf("node%d status: %v", i, st)
			if err := up(ctx, c); err != nil {
				return fmt.Errorf("node%d up: %w", i, err)
			}
			t.Logf("node%d up!", i)
			st, err = status(ctx, c)
			if err != nil {
				return fmt.Errorf("node%d status: %w", i, err)
			}
			sts[i] = st

			if st.BackendState != "Running" {
				return fmt.Errorf("node%d state = %q", i, st.BackendState)
			}
			t.Logf("node%d up with %v", i, sts[i].Self.TailscaleIPs)
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		t.Fatalf("initial setup: %v", err)
	}

	route, err := ping(ctx, c1, sts[1].Self.TailscaleIPs[0].String())
	t.Logf("ping route: %v, %v", route, err)
}

func status(ctx context.Context, c *http.Client) (*ipnstate.Status, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://unused/status", nil)
	if err != nil {
		return nil, err
	}
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	all, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("ReadAll: %w", err)
	}
	var st ipnstate.Status
	if err := json.Unmarshal(all, &st); err != nil {
		return nil, fmt.Errorf("JSON marshal error: %v; body was %q", err, all)
	}
	return &st, nil
}

type routeType string

const (
	routeDirect routeType = "direct"
	routeDERP   routeType = "derp"
	routeLAN    routeType = "lan"
)

func ping(ctx context.Context, c *http.Client, target string) (routeType, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", "http://unused/ping?target="+url.QueryEscape(target), nil)
	if err != nil {
		return "", err
	}
	res, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", fmt.Errorf("unexpected status code %v", res.Status)
	}
	all, _ := io.ReadAll(res.Body)
	var route routeType
	for _, line := range strings.Split(string(all), "\n") {
		if strings.Contains(line, " via DERP") {
			route = routeDERP
			continue
		}
		// pong from foo (100.82.3.4) via ADDR:PORT in 69ms
		if _, rest, ok := strings.Cut(line, " via "); ok {
			ipPorStr, _, _ := strings.Cut(rest, " in ")
			ipPort, err := netip.ParseAddrPort(ipPorStr)
			if err == nil {
				if ipPort.Addr().IsPrivate() {
					route = routeLAN
				} else {
					route = routeDirect
				}
				continue
			}
		}
	}
	if route == "" {
		return routeType(all), nil
	}
	return route, nil
}

func up(ctx context.Context, c *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://unused/up", nil)
	if err != nil {
		return err
	}
	res, err := c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	all, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		return fmt.Errorf("unexpected status code %v: %s", res.Status, all)
	}
	return nil
}

func TestEasyEasy(t *testing.T) {
	nt := newNatTest(t)
	nt.runTest(easy, easy)
}

func TestEasyHard(t *testing.T) {
	nt := newNatTest(t)
	nt.runTest(easy, hard)
}
