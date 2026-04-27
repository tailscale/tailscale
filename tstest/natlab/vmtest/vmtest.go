// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package vmtest provides a high-level framework for running integration tests
// across multiple QEMU virtual machines connected by natlab's vnet virtual
// network infrastructure. It supports mixed OS types (gokrazy, Ubuntu, Debian)
// and multi-NIC configurations for scenarios like subnet routing.
//
// Prerequisites:
//   - qemu-system-x86_64 and KVM access (typically the "kvm" group; no root required)
//   - A built gokrazy natlabapp image (auto-built on first run via "make natlab" in gokrazy/)
//
// Run tests with:
//
//	go test ./tstest/natlab/vmtest/ --run-vm-tests -v
package vmtest

import (
	"context"
	"flag"
	"fmt"
	"io"
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

	"golang.org/x/sync/errgroup"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/util/set"
)

var (
	runVMTests     = flag.Bool("run-vm-tests", false, "run tests that require VMs with KVM")
	verboseVMDebug = flag.Bool("verbose-vm-debug", false, "enable verbose debug logging for VM tests")
)

// Env is a test environment that manages virtual networks and QEMU VMs.
// Create one with New, add networks and nodes, then call Start.
type Env struct {
	t       testing.TB
	cfg     vnet.Config
	server  *vnet.Server
	nodes   []*Node
	tempDir string

	sockAddr string // shared Unix socket path for all QEMU netdevs
	binDir   string // directory for compiled binaries

	// gokrazy-specific paths
	gokrazyBase   string // path to gokrazy base qcow2 image
	gokrazyKernel string // path to gokrazy kernel

	qemuProcs []*exec.Cmd // launched QEMU processes
}

// logVerbosef logs a message only when --verbose-vm-debug is set.
func (e *Env) logVerbosef(format string, args ...any) {
	if *verboseVMDebug {
		e.t.Helper()
		e.t.Logf(format, args...)
	}
}

// New creates a new test environment. It skips the test if --run-vm-tests is not set.
func New(t testing.TB) *Env {
	if !*runVMTests {
		t.Skip("skipping VM test; set --run-vm-tests to run")
	}

	tempDir := t.TempDir()
	return &Env{
		t:       t,
		tempDir: tempDir,
		binDir:  filepath.Join(tempDir, "bin"),
	}
}

// AddNetwork creates a new virtual network. Arguments follow the same pattern as
// vnet.Config.AddNetwork (string IPs, NAT types, NetworkService values).
func (e *Env) AddNetwork(opts ...any) *vnet.Network {
	return e.cfg.AddNetwork(opts...)
}

// Node represents a virtual machine in the test environment.
type Node struct {
	name string
	num  int // assigned during AddNode

	os               OSImage
	nets             []*vnet.Network
	vnetNode         *vnet.Node // primary vnet node (set during Start)
	agent            *vnet.NodeAgentClient
	joinTailnet      bool
	advertiseRoutes  string
	snatSubnetRoutes *bool // nil means default (true)
	webServerPort    int
	sshPort          int // host port for SSH debug access (cloud VMs only)
}

// AddNode creates a new VM node. The name is used for identification and as the
// webserver greeting. Options can be *vnet.Network (for network attachment),
// NodeOption values, or vnet node options (like vnet.TailscaledEnv).
func (e *Env) AddNode(name string, opts ...any) *Node {
	n := &Node{
		name:        name,
		os:          Gokrazy, // default
		joinTailnet: true,
	}
	e.nodes = append(e.nodes, n)

	// Separate network options from other options.
	var vnetOpts []any
	for _, o := range opts {
		switch o := o.(type) {
		case *vnet.Network:
			n.nets = append(n.nets, o)
			vnetOpts = append(vnetOpts, o)
		case nodeOptOS:
			n.os = OSImage(o)
		case nodeOptNoTailscale:
			n.joinTailnet = false
			vnetOpts = append(vnetOpts, vnet.DontJoinTailnet)
		case nodeOptAdvertiseRoutes:
			n.advertiseRoutes = string(o)
		case nodeOptSNATSubnetRoutes:
			v := bool(o)
			n.snatSubnetRoutes = &v
		case nodeOptWebServer:
			n.webServerPort = int(o)
		default:
			// Pass through to vnet (TailscaledEnv, NodeOption, MAC, etc.)
			vnetOpts = append(vnetOpts, o)
		}
	}

	n.vnetNode = e.cfg.AddNode(vnetOpts...)
	n.num = n.vnetNode.Num()
	return n
}

// LanIP returns the LAN IPv4 address of this node on the given network.
// This is only valid after Env.Start() has been called.
func (n *Node) LanIP(net *vnet.Network) netip.Addr {
	return n.vnetNode.LanIP(net)
}

// NodeOption types for configuring nodes.

type nodeOptOS OSImage
type nodeOptNoTailscale struct{}
type nodeOptAdvertiseRoutes string
type nodeOptSNATSubnetRoutes bool
type nodeOptWebServer int

// OS returns a NodeOption that sets the node's operating system image.
func OS(img OSImage) nodeOptOS { return nodeOptOS(img) }

// DontJoinTailnet returns a NodeOption that prevents the node from running tailscale up.
func DontJoinTailnet() nodeOptNoTailscale { return nodeOptNoTailscale{} }

// AdvertiseRoutes returns a NodeOption that configures the node to advertise
// the given routes (comma-separated CIDRs) when joining the tailnet.
func AdvertiseRoutes(routes string) nodeOptAdvertiseRoutes {
	return nodeOptAdvertiseRoutes(routes)
}

// SNATSubnetRoutes returns a NodeOption that sets whether the node should
// source NAT traffic to advertised subnet routes. The default is true.
// Setting this to false preserves original source IPs, which is needed
// for site-to-site configurations.
func SNATSubnetRoutes(v bool) nodeOptSNATSubnetRoutes { return nodeOptSNATSubnetRoutes(v) }

// WebServer returns a NodeOption that starts a webserver on the given port.
// The webserver responds with "Hello world I am <nodename> from <sourceIP>" on all requests.
func WebServer(port int) nodeOptWebServer { return nodeOptWebServer(port) }

// Start initializes the virtual network, builds/downloads images, compiles
// binaries, launches QEMU processes, and waits for all TTA agents to connect.
// It should be called after all AddNetwork/AddNode calls.
func (e *Env) Start() {
	t := e.t
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	if err := os.MkdirAll(e.binDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Determine which GOOS/GOARCH pairs need compiled binaries (non-gokrazy
	// images). Gokrazy has binaries built-in, so doesn't need compilation.
	type platform struct{ goos, goarch string }
	needPlatform := set.Set[platform]{}
	for _, n := range e.nodes {
		if !n.os.IsGokrazy {
			needPlatform.Add(platform{n.os.GOOS(), n.os.GOARCH()})
		}
	}

	// Compile binaries and download/build images in parallel.
	// Any failure cancels the others via the errgroup context.
	eg, egCtx := errgroup.WithContext(ctx)
	for _, p := range needPlatform.Slice() {
		eg.Go(func() error {
			return e.compileBinariesForOS(egCtx, p.goos, p.goarch)
		})
	}
	didOS := set.Set[string]{} // dedup by image name
	for _, n := range e.nodes {
		if didOS.Contains(n.os.Name) {
			continue
		}
		didOS.Add(n.os.Name)
		if n.os.IsGokrazy {
			eg.Go(func() error {
				return e.ensureGokrazy(egCtx)
			})
		} else {
			eg.Go(func() error {
				return ensureImage(egCtx, n.os)
			})
		}
	}
	if err := eg.Wait(); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Create the vnet server.
	var err error
	e.server, err = vnet.New(&e.cfg)
	if err != nil {
		t.Fatalf("vnet.New: %v", err)
	}
	t.Cleanup(func() { e.server.Close() })

	// Register compiled binaries with the file server VIP.
	// Binaries are registered at <goos>_<goarch>/<name> (e.g. "linux_amd64/tta").
	for _, p := range needPlatform.Slice() {
		dir := p.goos + "_" + p.goarch
		for _, name := range []string{"tta", "tailscale", "tailscaled"} {
			data, err := os.ReadFile(filepath.Join(e.binDir, dir, name))
			if err != nil {
				t.Fatalf("reading compiled %s/%s: %v", dir, name, err)
			}
			e.server.RegisterFile(dir+"/"+name, data)
		}
	}

	// Cloud-init config is delivered via local seed ISOs (created in startCloudQEMU),
	// not via the cloud-init HTTP VIP, because network-config must be available
	// during init-local before systemd-networkd-wait-online blocks.

	// Start Unix socket listener.
	e.sockAddr = filepath.Join(e.tempDir, "vnet.sock")
	srv, err := net.Listen("unix", e.sockAddr)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			go e.server.ServeUnixConn(c.(*net.UnixConn), vnet.ProtocolQEMU)
		}
	}()

	// Launch QEMU processes.
	for _, n := range e.nodes {
		if err := e.startQEMU(n); err != nil {
			t.Fatalf("startQEMU(%s): %v", n.name, err)
		}
	}

	// Set up agent clients and wait for all agents to connect.
	for _, n := range e.nodes {
		n.agent = e.server.NodeAgentClient(n.vnetNode)
		n.vnetNode.SetClient(n.agent)
	}

	// Wait for agents, then bring up tailscale.
	var agentEg errgroup.Group
	for _, n := range e.nodes {
		agentEg.Go(func() error {
			t.Logf("[%s] waiting for agent...", n.name)
			st, err := n.agent.Status(ctx)
			if err != nil {
				return fmt.Errorf("[%s] agent status: %w", n.name, err)
			}
			t.Logf("[%s] agent connected, backend state: %s", n.name, st.BackendState)

			if n.vnetNode.HostFirewall() {
				if err := n.agent.EnableHostFirewall(ctx); err != nil {
					return fmt.Errorf("[%s] enable firewall: %w", n.name, err)
				}
			}

			if n.joinTailnet {
				if err := e.tailscaleUp(ctx, n); err != nil {
					return fmt.Errorf("[%s] tailscale up: %w", n.name, err)
				}
				st, err = n.agent.Status(ctx)
				if err != nil {
					return fmt.Errorf("[%s] status after up: %w", n.name, err)
				}
				if st.BackendState != "Running" {
					return fmt.Errorf("[%s] state = %q, want Running", n.name, st.BackendState)
				}
				t.Logf("[%s] up with %v", n.name, st.Self.TailscaleIPs)
			}

			return nil
		})
	}
	if err := agentEg.Wait(); err != nil {
		t.Fatal(err)
	}

	// Start webservers.
	for _, n := range e.nodes {
		if n.webServerPort > 0 {
			if err := e.startWebServer(ctx, n); err != nil {
				t.Fatalf("startWebServer(%s): %v", n.name, err)
			}
		}
	}
}

// tailscaleUp runs "tailscale up" on the node via TTA.
func (e *Env) tailscaleUp(ctx context.Context, n *Node) error {
	url := "http://unused/up?accept-routes=true"
	if n.advertiseRoutes != "" {
		url += "&advertise-routes=" + n.advertiseRoutes
	}
	if n.snatSubnetRoutes != nil {
		if *n.snatSubnetRoutes {
			url += "&snat-subnet-routes=true"
		} else {
			url += "&snat-subnet-routes=false"
		}
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	res, err := n.agent.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		return fmt.Errorf("tailscale up: %s: %s", res.Status, body)
	}
	return nil
}

// startWebServer tells TTA on the node to start a webserver.
func (e *Env) startWebServer(ctx context.Context, n *Node) error {
	url := fmt.Sprintf("http://unused/start-webserver?port=%d&name=%s", n.webServerPort, n.name)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	res, err := n.agent.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("start-webserver: %s: %s", res.Status, body)
	}
	e.t.Logf("[%s] webserver started on port %d", n.name, n.webServerPort)
	return nil
}

// SetExitNode sets the client node's exit node to use for internet traffic.
// If exitNode is nil, the client's exit node is cleared (i.e., turned off).
// Otherwise exitNode must be a tailnet node with an approved 0.0.0.0/0 (and
// ::/0) route, typically configured via [AdvertiseRoutes] and
// [Env.ApproveRoutes].
func (e *Env) SetExitNode(client, exitNode *Node) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var ip netip.Addr
	if exitNode != nil {
		st, err := exitNode.agent.Status(ctx)
		if err != nil {
			e.t.Fatalf("SetExitNode: status for %s: %v", exitNode.name, err)
		}
		if len(st.Self.TailscaleIPs) == 0 {
			e.t.Fatalf("SetExitNode: %s has no Tailscale IPs", exitNode.name)
		}
		ip = st.Self.TailscaleIPs[0]
	}

	if _, err := client.agent.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			ExitNodeID: "",
			ExitNodeIP: ip,
		},
		ExitNodeIDSet: true,
		ExitNodeIPSet: true,
	}); err != nil {
		e.t.Fatalf("SetExitNode(%s -> %v): %v", client.name, exitNode, err)
	}
	if exitNode == nil {
		e.t.Logf("[%s] cleared exit node", client.name)
	} else {
		e.t.Logf("[%s] using exit node %s (%v)", client.name, exitNode.name, ip)
	}
}

// SetAcceptRoutes toggles the node's RouteAll preference (the
// --accept-routes flag), controlling whether it installs subnet routes
// advertised by peers.
func (e *Env) SetAcceptRoutes(n *Node, on bool) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := n.agent.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs:       ipn.Prefs{RouteAll: on},
		RouteAllSet: true,
	}); err != nil {
		e.t.Fatalf("SetAcceptRoutes(%s, %v): %v", n.name, on, err)
	}
	e.t.Logf("[%s] accept-routes=%v", n.name, on)
}

// ApproveRoutes tells the test control server to approve subnet routes
// for the given node. The routes should be CIDR strings.
func (e *Env) ApproveRoutes(n *Node, routes ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get the node's public key from its status.
	st, err := n.agent.Status(ctx)
	if err != nil {
		e.t.Fatalf("ApproveRoutes: status for %s: %v", n.name, err)
	}
	nodeKey := st.Self.PublicKey

	var prefixes []netip.Prefix
	for _, r := range routes {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			e.t.Fatalf("ApproveRoutes: bad route %q: %v", r, err)
		}
		prefixes = append(prefixes, p)
	}

	// Enable --accept-routes on all other tailscale nodes BEFORE setting the
	// routes on the control server. This way, when the map update arrives with
	// the new peer routes, peers will immediately install them.
	for _, other := range e.nodes {
		if other == n || !other.joinTailnet {
			continue
		}
		if _, err := other.agent.EditPrefs(ctx, &ipn.MaskedPrefs{
			Prefs:       ipn.Prefs{RouteAll: true},
			RouteAllSet: true,
		}); err != nil {
			e.t.Fatalf("ApproveRoutes: set accept-routes on %s: %v", other.name, err)
		}
	}

	// Approve the routes on the control server. SetSubnetRoutes notifies all
	// peers via updatePeerChanged, so they'll re-fetch their MapResponse.
	e.server.ControlServer().SetSubnetRoutes(nodeKey, prefixes)

	// Wait for each peer to see the routes.
	for _, r := range routes {
		for _, other := range e.nodes {
			if other == n || !other.joinTailnet {
				continue
			}
			if !e.waitForPeerRoute(other, r, 15*time.Second) {
				e.DumpStatus(other)
				e.t.Fatalf("ApproveRoutes: %s never saw route %s", other.name, r)
			}
		}
	}
	e.t.Logf("approved routes %v on %s", routes, n.name)

	// Ping the advertiser from each peer to establish WireGuard tunnels.
	for _, other := range e.nodes {
		if other == n || !other.joinTailnet {
			continue
		}
		e.ping(other, n)
	}
}

// ping pings from one node to another's Tailscale IP, retrying until it succeeds
// or the timeout expires. This establishes the WireGuard tunnel between the nodes.
func (e *Env) ping(from, to *Node) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	toSt, err := to.agent.Status(ctx)
	if err != nil {
		e.t.Fatalf("ping: can't get %s status: %v", to.name, err)
	}
	if len(toSt.Self.TailscaleIPs) == 0 {
		e.t.Fatalf("ping: %s has no Tailscale IPs", to.name)
	}
	targetIP := toSt.Self.TailscaleIPs[0]

	for {
		pingCtx, pingCancel := context.WithTimeout(ctx, 3*time.Second)
		pr, err := from.agent.PingWithOpts(pingCtx, targetIP, tailcfg.PingDisco, local.PingOpts{})
		pingCancel()
		if err == nil && pr.Err == "" {
			e.logVerbosef("ping: %s -> %s OK", from.name, targetIP)
			return
		}
		if ctx.Err() != nil {
			e.t.Fatalf("ping: %s -> %s timed out", from.name, targetIP)
		}
		time.Sleep(time.Second)
	}
}

// AddRoute adds a kernel static route on the given node, pointing prefix at
// via. It uses TTA's /add-route handler, so it works on any node where TTA
// is running (which is all of them — DontJoinTailnet only skips
// `tailscale up`; the agent runs regardless). Currently Linux-only in TTA.
//
// Fatals on error.
func (e *Env) AddRoute(n *Node, prefix, via string) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reqURL := fmt.Sprintf("http://unused/add-route?prefix=%s&via=%s", prefix, via)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		e.t.Fatalf("AddRoute: %v", err)
	}
	resp, err := n.agent.HTTPClient.Do(req)
	if err != nil {
		e.t.Fatalf("AddRoute(%s, %s → %s): %v", n.name, prefix, via, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		e.t.Fatalf("AddRoute(%s, %s → %s): %s: %s", n.name, prefix, via, resp.Status, body)
	}
}

// SSHExec runs a command on a cloud VM via its debug SSH NIC.
// Only works for cloud VMs that have the debug NIC and SSH key configured.
// Returns stdout and any error.
func (e *Env) SSHExec(n *Node, cmd string) (string, error) {
	if n.sshPort == 0 {
		return "", fmt.Errorf("node %s has no SSH debug port", n.name)
	}
	sshCmd := exec.Command("ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=5",
		"-i", "/tmp/vmtest_key",
		"-p", fmt.Sprintf("%d", n.sshPort),
		"root@127.0.0.1",
		cmd)
	out, err := sshCmd.CombinedOutput()
	return string(out), err
}

// DumpStatus logs the tailscale status of a node, including its peers and their
// AllowedIPs. Useful for debugging routing issues.
func (e *Env) DumpStatus(n *Node) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	st, err := n.agent.Status(ctx)
	if err != nil {
		e.t.Logf("[%s] DumpStatus error: %v", n.name, err)
		return
	}
	var selfAllowed []string
	if st.Self.AllowedIPs != nil {
		for i := range st.Self.AllowedIPs.Len() {
			selfAllowed = append(selfAllowed, st.Self.AllowedIPs.At(i).String())
		}
	}
	var selfPrimary []string
	if st.Self.PrimaryRoutes != nil {
		for i := range st.Self.PrimaryRoutes.Len() {
			selfPrimary = append(selfPrimary, st.Self.PrimaryRoutes.At(i).String())
		}
	}
	e.t.Logf("[%s] self: %v, backend=%s, AllowedIPs=%v, PrimaryRoutes=%v", n.name, st.Self.TailscaleIPs, st.BackendState, selfAllowed, selfPrimary)
	for _, peer := range st.Peer {
		var aips []string
		if peer.AllowedIPs != nil {
			for i := range peer.AllowedIPs.Len() {
				aips = append(aips, peer.AllowedIPs.At(i).String())
			}
		}
		e.t.Logf("[%s] peer %s (%s): AllowedIPs=%v, Online=%v, Relay=%q, CurAddr=%q",
			n.name, peer.HostName, peer.TailscaleIPs,
			aips, peer.Online, peer.Relay, peer.CurAddr)
	}
}

// waitForPeerRoute polls the node's status until it sees the given route prefix
// in a peer's AllowedIPs, or until timeout. Returns true if found.
func (e *Env) waitForPeerRoute(n *Node, prefix string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		st, err := n.agent.Status(ctx)
		if err != nil {
			return false
		}
		for _, peer := range st.Peer {
			if peer.AllowedIPs != nil {
				for i := range peer.AllowedIPs.Len() {
					if peer.AllowedIPs.At(i).String() == prefix {
						return true
					}
				}
			}
		}
		if ctx.Err() != nil {
			return false
		}
		time.Sleep(time.Second)
	}
}

// HTTPGet makes an HTTP GET request from the given node to the specified URL.
// The request is proxied through TTA's /http-get handler.
func (e *Env) HTTPGet(from *Node, targetURL string) string {
	for attempt := range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		reqURL := "http://unused/http-get?url=" + targetURL
		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			cancel()
			e.t.Fatalf("HTTPGet: %v", err)
		}
		res, err := from.agent.HTTPClient.Do(req)
		cancel()
		if err != nil {
			e.logVerbosef("HTTPGet attempt %d from %s: %v", attempt+1, from.name, err)
			continue
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode == http.StatusBadGateway || res.StatusCode == http.StatusServiceUnavailable {
			e.t.Logf("HTTPGet attempt %d from %s: status %d, body: %s", attempt+1, from.name, res.StatusCode, string(body))
			time.Sleep(2 * time.Second)
			continue
		}
		return string(body)
	}
	e.t.Fatalf("HTTPGet from %s to %s: all attempts failed", from.name, targetURL)
	return ""
}

var buildGokrazy sync.Once

// ensureGokrazy builds the gokrazy base image (once per test process) and
// locates the kernel. The build is fast (~4s) so we always rebuild to ensure
// the baked-in binaries (tta, tailscale, tailscaled) match the current source.
func (e *Env) ensureGokrazy(ctx context.Context) error {
	if e.gokrazyBase != "" {
		return nil // already found
	}

	modRoot, err := findModRoot()
	if err != nil {
		return err
	}

	var buildErr error
	buildGokrazy.Do(func() {
		e.t.Logf("building gokrazy natlab image...")
		cmd := exec.CommandContext(ctx, "make", "natlab")
		cmd.Dir = filepath.Join(modRoot, "gokrazy")
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		if err := cmd.Run(); err != nil {
			buildErr = fmt.Errorf("make natlab: %w", err)
		}
	})
	if buildErr != nil {
		return buildErr
	}

	e.gokrazyBase = filepath.Join(modRoot, "gokrazy/natlabapp.qcow2")

	kernel, err := findKernelPath(filepath.Join(modRoot, "go.mod"))
	if err != nil {
		return fmt.Errorf("finding kernel: %w", err)
	}
	e.gokrazyKernel = kernel
	return nil
}

// compileBinariesForOS cross-compiles tta, tailscale, and tailscaled for the
// given GOOS/GOARCH and places them in e.binDir/<goos>_<goarch>/.
func (e *Env) compileBinariesForOS(ctx context.Context, goos, goarch string) error {
	modRoot, err := findModRoot()
	if err != nil {
		return err
	}

	dir := goos + "_" + goarch
	outDir := filepath.Join(e.binDir, dir)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	binaries := []struct{ name, pkg string }{
		{"tta", "./cmd/tta"},
		{"tailscale", "./cmd/tailscale"},
		{"tailscaled", "./cmd/tailscaled"},
	}

	var eg errgroup.Group
	for _, bin := range binaries {
		eg.Go(func() error {
			outPath := filepath.Join(outDir, bin.name)
			e.t.Logf("compiling %s/%s...", dir, bin.name)
			cmd := exec.CommandContext(ctx, "go", "build", "-o", outPath, bin.pkg)
			cmd.Dir = modRoot
			cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("building %s/%s: %v\n%s", dir, bin.name, err, out)
			}
			e.t.Logf("compiled %s/%s", dir, bin.name)
			return nil
		})
	}
	return eg.Wait()
}

// findModRoot returns the root of the Go module (where go.mod is).
func findModRoot() (string, error) {
	out, err := exec.Command("go", "env", "GOMOD").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("go env GOMOD: %w", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == os.DevNull {
		return "", fmt.Errorf("not in a Go module")
	}
	return filepath.Dir(gomod), nil
}

// findKernelPath finds the gokrazy kernel vmlinuz path from go.mod.
func findKernelPath(goMod string) (string, error) {
	// Import the same logic as nat_test.go.
	b, err := os.ReadFile(goMod)
	if err != nil {
		return "", err
	}

	goModCacheB, err := exec.Command("go", "env", "GOMODCACHE").CombinedOutput()
	if err != nil {
		return "", err
	}
	goModCache := strings.TrimSpace(string(goModCacheB))

	// Parse go.mod to find gokrazy-kernel version.
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "github.com/tailscale/gokrazy-kernel") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return filepath.Join(goModCache, parts[0]+"@"+parts[1], "vmlinuz"), nil
			}
		}
	}
	return "", fmt.Errorf("gokrazy-kernel not found in %s", goMod)
}
