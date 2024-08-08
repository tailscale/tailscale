// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nat

import (
	"context"
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
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/sync/errgroup"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/types/logger"
)

type natTest struct {
	tb      testing.TB
	base    string // base image
	tempDir string // for qcow2 images
	vnet    *vnet.Server
	kernel  string // linux kernel path
}

func newNatTest(tb testing.TB) *natTest {
	root, err := os.Getwd()
	if err != nil {
		tb.Fatal(err)
	}
	modRoot := filepath.Join(root, "../../..")

	linuxKernel, err := findKernelPath(filepath.Join(modRoot, "gokrazy/tsapp/builddir/github.com/tailscale/gokrazy-kernel/go.mod"))
	if err != nil {
		tb.Fatalf("findKernelPath: %v", err)
	}
	tb.Logf("found kernel: %v", linuxKernel)

	nt := &natTest{
		tb:      tb,
		tempDir: tb.TempDir(),
		base:    filepath.Join(modRoot, "gokrazy/tsapp.qcow2"),
		kernel:  linuxKernel,
	}

	if _, err := os.Stat(nt.base); err != nil {
		tb.Skipf("skipping test; base image %q not found", nt.base)
	}
	return nt
}

func findKernelPath(goMod string) (string, error) {
	b, err := os.ReadFile(goMod)
	if err != nil {
		return "", err
	}
	mf, err := modfile.Parse("go.mod", b, nil)
	if err != nil {
		return "", err
	}
	goModB, err := exec.Command("go", "env", "GOMODCACHE").CombinedOutput()
	if err != nil {
		return "", err
	}
	for _, r := range mf.Require {
		if r.Mod.Path == "github.com/tailscale/gokrazy-kernel" {
			return strings.TrimSpace(string(goModB)) + "/" + r.Mod.String() + "/vmlinuz", nil
		}
	}
	return "", fmt.Errorf("failed to find kernel in %v", goMod)
}

type addNodeFunc func(c *vnet.Config) *vnet.Node

func easy(c *vnet.Config) *vnet.Node {
	n := c.NumNodes() + 1
	return c.AddNode(c.AddNetwork(
		fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
		fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyNAT))
}

func easyPMP(c *vnet.Config) *vnet.Node {
	n := c.NumNodes() + 1
	return c.AddNode(c.AddNetwork(
		fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
		fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyNAT, vnet.NATPMP))
}

func hard(c *vnet.Config) *vnet.Node {
	n := c.NumNodes() + 1
	return c.AddNode(c.AddNetwork(
		fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
		fmt.Sprintf("10.0.%d.1/24", n), vnet.HardNAT))
}

func hardPMP(c *vnet.Config) *vnet.Node {
	n := c.NumNodes() + 1
	return c.AddNode(c.AddNetwork(
		fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
		fmt.Sprintf("10.7.%d.1/24", n), vnet.HardNAT, vnet.NATPMP))
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
			"-m", "384M",
			"-nodefaults", "-no-user-config", "-nographic",
			"-kernel", nt.kernel,
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

	lc1 := nt.vnet.NodeAgentClient(nodes[0])
	lc2 := nt.vnet.NodeAgentClient(nodes[1])
	clients := []*vnet.NodeAgentClient{lc1, lc2}

	var eg errgroup.Group
	var sts [2]*ipnstate.Status
	for i, c := range clients {
		i, c := i, c
		eg.Go(func() error {
			wg.Add(1)
			go func() {
				defer wg.Done()
				streamDaemonLogs(ctx, t, c, fmt.Sprintf("node%d:", i))
			}()
			st, err := c.Status(ctx)
			if err != nil {
				return fmt.Errorf("node%d status: %w", i, err)
			}
			t.Logf("node%d status: %v", i, st)
			if err := up(ctx, c); err != nil {
				return fmt.Errorf("node%d up: %w", i, err)
			}
			t.Logf("node%d up!", i)
			st, err = c.Status(ctx)
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

	route, err := ping(ctx, lc1, sts[1].Self.TailscaleIPs[0])
	t.Logf("ping route: %v, %v", logger.AsJSON(route), err)
}

func streamDaemonLogs(ctx context.Context, t testing.TB, c *vnet.NodeAgentClient, nodeID string) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	r, err := c.TailDaemonLogs(ctx)
	if err != nil {
		t.Errorf("tailDaemonLogs: %v", err)
		return
	}
	logger := log.New(os.Stderr, nodeID+" ", log.Lmsgprefix)
	dec := json.NewDecoder(r)
	for {
		// /{"logtail":{"client_time":"2024-08-08T17:42:31.95095956Z","proc_id":2024742977,"proc_seq":232},"text":"magicsock: derp-1 connected; connGen=1\n"}
		var logEntry struct {
			LogTail struct {
				ClientTime time.Time `json:"client_time"`
			}
			Text string `json:"text"`
		}
		if err := dec.Decode(&logEntry); err != nil {
			if err == io.EOF || errors.Is(err, context.Canceled) {
				return
			}
			t.Errorf("log entry: %v", err)
			return
		}
		logger.Printf("%s %s", logEntry.LogTail.ClientTime.Format("2006/01/02 15:04:05"), logEntry.Text)
	}
}

func ping(ctx context.Context, c *vnet.NodeAgentClient, target netip.Addr) (*ipnstate.PingResult, error) {
	n := 0
	var res *ipnstate.PingResult
	anyPong := false
	for n < 10 {
		n++
		pr, err := c.PingWithOpts(ctx, target, tailcfg.PingDisco, tailscale.PingOpts{})
		if err != nil {
			if anyPong {
				return res, nil
			}
			return nil, err
		}
		if pr.Err != "" {
			return nil, errors.New(pr.Err)
		}
		if pr.DERPRegionID == 0 {
			return pr, nil
		}
		res = pr
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
	if res == nil {
		return nil, errors.New("no ping response")
	}
	return res, nil
}

func up(ctx context.Context, c *vnet.NodeAgentClient) error {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://unused/up", nil)
	if err != nil {
		return err
	}
	res, err := c.HTTPClient.Do(req)
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

func TestEasyHardPMP(t *testing.T) {
	nt := newNatTest(t)
	nt.runTest(easy, hardPMP)
}

func TestEasyPMPHard(t *testing.T) {
	nt := newNatTest(t)
	nt.runTest(easyPMP, hard)
}
