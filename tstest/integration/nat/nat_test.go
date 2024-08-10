// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nat

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
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
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/natlab/vnet"
)

var (
	logTailscaled = flag.Bool("log-tailscaled", false, "log tailscaled output")
	pcapFile      = flag.String("pcap", "", "write pcap to file")
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

	nt := &natTest{
		tb:      tb,
		tempDir: tb.TempDir(),
		base:    filepath.Join(modRoot, "gokrazy/tsapp.qcow2"),
	}

	if _, err := os.Stat(nt.base); err != nil {
		tb.Skipf("skipping test; base image %q not found", nt.base)
	}

	nt.kernel, err = findKernelPath(filepath.Join(modRoot, "gokrazy/tsapp/builddir/github.com/tailscale/gokrazy-kernel/go.mod"))
	if err != nil {
		tb.Skipf("skipping test; kernel not found: %v", err)
	}
	tb.Logf("found kernel: %v", nt.kernel)

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

type addNodeFunc func(c *vnet.Config) *vnet.Node // returns nil to omit test

func easy(c *vnet.Config) *vnet.Node {
	n := c.NumNodes() + 1
	return c.AddNode(c.AddNetwork(
		fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
		fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyNAT))
}

func easyAF(c *vnet.Config) *vnet.Node {
	n := c.NumNodes() + 1
	return c.AddNode(c.AddNetwork(
		fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
		fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyAFNAT))
}

func sameLAN(c *vnet.Config) *vnet.Node {
	nw := c.FirstNetwork()
	if nw == nil {
		return nil
	}
	if !nw.CanTakeMoreNodes() {
		return nil
	}
	return c.AddNode(nw)
}

func one2one(c *vnet.Config) *vnet.Node {
	n := c.NumNodes() + 1
	return c.AddNode(c.AddNetwork(
		fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
		fmt.Sprintf("172.16.%d.1/24", n), vnet.One2OneNAT))
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

func (nt *natTest) runTest(node1, node2 addNodeFunc) pingRoute {
	t := nt.tb

	var c vnet.Config
	c.SetPCAPFile(*pcapFile)
	nodes := []*vnet.Node{
		node1(&c),
		node2(&c),
	}
	if nodes[0] == nil || nodes[1] == nil {
		t.Skip("skipping test; not applicable combination")
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
			if *logTailscaled {
				wg.Add(1)
				go func() {
					defer wg.Done()
					streamDaemonLogs(ctx, t, c, fmt.Sprintf("node%d:", i))
				}()
			}
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

	defer nt.vnet.Close()

	pingRes, err := ping(ctx, lc1, sts[1].Self.TailscaleIPs[0])
	if err != nil {
		t.Fatalf("ping failure: %v", err)
	}
	route := classifyPing(pingRes)
	t.Logf("ping route: %v", route)
	return route
}

func classifyPing(pr *ipnstate.PingResult) pingRoute {
	if pr == nil {
		return routeNil
	}
	if pr.Endpoint != "" {
		ap, err := netip.ParseAddrPort(pr.Endpoint)
		if err == nil {
			if ap.Addr().IsPrivate() {
				return routeLocal
			}
			return routeDirect
		}
	}
	return routeDERP // presumably
}

type pingRoute string

const (
	routeDERP   pingRoute = "derp"
	routeLocal  pingRoute = "local"
	routeDirect pingRoute = "direct"
	routeNil    pingRoute = "nil" // *ipnstate.PingResult is nil
)

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

type nodeType struct {
	name string
	fn   addNodeFunc
}

var types = []nodeType{
	{"easy", easy},
	{"easyAF", easyAF},
	{"hard", hard},
	{"easyPMP", easyPMP},
	{"hardPMP", hardPMP},
	{"one2one", one2one},
	{"sameLAN", sameLAN},
}

func TestEasyEasy(t *testing.T) {
	nt := newNatTest(t)
	nt.runTest(easy, easy)
}

var pair = flag.String("pair", "", "comma-separated pair of types to test (easy, easyAF, hard, easyPMP, hardPMP, one2one, sameLAN)")

func TestPair(t *testing.T) {
	t1, t2, ok := strings.Cut(*pair, ",")
	if !ok {
		t.Skipf("skipping test without --pair=type1,type2 set")
	}
	find := func(name string) addNodeFunc {
		for _, nt := range types {
			if nt.name == name {
				return nt.fn
			}
		}
		t.Fatalf("unknown type %q", name)
		return nil
	}

	nt := newNatTest(t)
	nt.runTest(find(t1), find(t2))
}

var runGrid = flag.Bool("run-grid", false, "run grid test")

func TestGrid(t *testing.T) {
	if !*runGrid {
		t.Skip("skipping grid test; set --run-grid to run")
	}
	t.Parallel()

	sem := syncs.NewSemaphore(2)
	var (
		mu  sync.Mutex
		res = make(map[string]pingRoute)
	)
	for _, a := range types {
		for _, b := range types {
			key := a.name + "-" + b.name
			keyBack := b.name + "-" + a.name
			t.Run(key, func(t *testing.T) {
				t.Parallel()

				sem.Acquire()
				defer sem.Release()

				filename := key + ".cache"
				contents, _ := os.ReadFile(filename)
				if len(contents) == 0 {
					filename2 := keyBack + ".cache"
					contents, _ = os.ReadFile(filename2)
				}
				route := pingRoute(strings.TrimSpace(string(contents)))

				if route == "" {
					nt := newNatTest(t)
					route = nt.runTest(a.fn, b.fn)
					if err := os.WriteFile(filename, []byte(string(route)), 0666); err != nil {
						t.Fatalf("writeFile: %v", err)
					}
				}

				mu.Lock()
				defer mu.Unlock()
				res[key] = route
				t.Logf("results: %v", res)
			})
		}
	}

	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		var hb bytes.Buffer
		pf := func(format string, args ...any) {
			fmt.Fprintf(&hb, format, args...)
		}
		rewrite := func(s string) string {
			return strings.ReplaceAll(s, "PMP", "+pm")
		}
		pf("<html><table border=1 cellpadding=5>")
		pf("<tr><td></td>")
		for _, a := range types {
			pf("<td><b>%s</b></td>", rewrite(a.name))
		}
		pf("</tr>\n")

		for _, a := range types {
			if a.name == "sameLAN" {
				continue
			}
			pf("<tr><td><b>%s</b></td>", rewrite(a.name))
			for _, b := range types {
				key := a.name + "-" + b.name
				key2 := b.name + "-" + a.name
				v := cmp.Or(res[key], res[key2], "-")
				if v == "derp" {
					pf("<td><div style='color: red; font-weight: bold'>%s</div></td>", v)
				} else if v == "local" {
					pf("<td><div style='color: green; font-weight: bold'>%s</div></td>", v)
				} else {
					pf("<td>%s</td>", v)
				}
			}
			pf("</tr>\n")
		}
		pf("</table>")
		pf("<b>easy</b>: Endpoint-Independent Mapping, Address and Port-Dependent Filtering (e.g. Linux, Google Wifi, Unifi, eero)<br>")
		pf("<b>easyAF</b>: Endpoint-Independent Mapping, Address-Dependent Filtering (James says telephony things or Zyxel type things)<br>")
		pf("<b>hard</b>: Address and Port-Dependent Mapping, Address and Port-Dependent Filtering (FreeBSD, OPNSense, pfSense)<br>")
		pf("<b>one2one</b>: One-to-One NAT (e.g. an EC2 instance with a public IPv4)<br>")
		pf("<b>x+pm</b>: x, with port mapping (NAT-PMP, PCP, UPnP, etc)<br>")
		pf("<b>sameLAN</b>: a second node in the same LAN as the first<br>")
		pf("</html>")

		if err := os.WriteFile("grid.html", hb.Bytes(), 0666); err != nil {
			t.Fatalf("writeFile: %v", err)
		}
	})
}
