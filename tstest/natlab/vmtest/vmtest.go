// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package vmtest provides a high-level framework for running integration tests
// across multiple QEMU virtual machines connected by natlab's vnet virtual
// network infrastructure. It supports mixed OS types (gokrazy, Ubuntu, Debian)
// and multi-NIC configurations for scenarios like subnet routing.
//
// Prerequisites:
//   - qemu-system-x86_64 (KVM is used automatically on Linux when /dev/kvm is accessible)
//   - A built gokrazy natlabapp image (auto-built on first run via "make natlab" in gokrazy/)
//
// Run tests with:
//
//	go test ./tstest/natlab/vmtest/ --run-vm-tests -v
package vmtest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"go4.org/mem"
	"golang.org/x/sync/errgroup"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/types/key"
	"tailscale.com/util/mak"
)

var (
	runVMTests     = flag.Bool("run-vm-tests", false, "run tests that require QEMU VMs")
	verboseVMDebug = flag.Bool("verbose-vm-debug", false, "enable verbose debug logging for VM tests")
	testVersion    = flag.String("test-version", "", `if non-empty, download tailscale & tailscaled at the given release version (e.g. "1.97.255", "unstable", or "stable") instead of building from the source tree`)
)

// Env is a test environment that manages virtual networks and QEMU VMs.
// Create one with New, add networks and nodes, then call Start.
type Env struct {
	t       testing.TB
	cfg     vnet.Config
	server  *vnet.Server
	nodes   []*Node
	tempDir string

	sockDir       string // short-path dir for Unix sockets (macOS has 104-byte limit)
	sockAddr      string // shared Unix socket path for all QEMU netdevs
	dgramSockAddr string // Unix dgram socket path for macOS VMs (tailmac)
	binDir        string // directory for compiled binaries

	// testVersion is the resolved Tailscale release version to use (empty if
	// building from source). When non-empty, tailscale and tailscaled binaries
	// are downloaded from pkgs.tailscale.com instead of compiled from the tree.
	testVersion string

	// gokrazy-specific paths
	gokrazyBase   string // path to gokrazy base qcow2 image
	gokrazyKernel string // path to gokrazy kernel

	// tailmac-specific paths (macOS VMs)
	tailmacDir        string // path to tailmac bin/ directory containing Host.app
	macosSnapshot     string // path to cached macOS VM snapshot directory
	macosSnapshotOnce sync.Once

	qemuProcs []*exec.Cmd // launched QEMU processes

	sameTailnetUser           bool // all nodes register as the same Tailnet user
	allOnline                 bool // mark every peer as Online=true in MapResponses
	peerRelayGrants           bool // grant peer-relay capabilities on the wildcard packet filter
	selfSignedDERPCertPinning bool // serve test DERP map with sha256-raw cert pins
	fakeACME                  bool // point tailscaled at vnet's fake ACME server

	controlDNSDomain string             // MagicDNS domain for the test control server (see ControlDNS)
	controlDNS       *tailcfg.DNSConfig // DNS config for the test control server (see ControlDNS)

	// Shared resource initialization (sync.Once for things multiple nodes share).
	vnetOnce      sync.Once
	gokrazyOnce   sync.Once
	qemuSockOnce  sync.Once
	dgramSockOnce sync.Once
	compileMu     sync.Mutex
	compileOnce   map[string]*sync.Once // keyed by goos_goarch
	imageOnce     map[string]*sync.Once // keyed by OSImage.Name

	// Web UI support.
	ctx        context.Context // cancelled when test ends
	eventBus   *EventBus
	testStatus *TestStatus
	stepsMu    sync.Mutex
	stepsByKey map[string]*Step
	steps      []*Step

	nodeStatusMu sync.Mutex
	nodeStatus   map[string]*NodeStatus // keyed by node name
}

// logVerbosef logs a message only when --verbose-vm-debug is set.
func (e *Env) logVerbosef(format string, args ...any) {
	if *verboseVMDebug {
		e.t.Helper()
		e.t.Logf(format, args...)
	}
}

// vmPlatform defines how a VM type boots. Each OS image type (gokrazy,
// cloud, macOS) implements this interface.
type vmPlatform interface {
	// planSteps registers steps with the web UI in a dry-run pass.
	planSteps(e *Env, n *Node)

	// boot does everything needed to get this node running: ensure images,
	// compile binaries, set up sockets, launch VM. Called concurrently.
	boot(ctx context.Context, e *Env, n *Node) error
}

// platform returns the vmPlatform for this node's OS type.
func (n *Node) platform() vmPlatform {
	if n.os.IsMacOS {
		return macPlatform{}
	}
	if n.os.IsGokrazy {
		return gokrazyPlatform{}
	}
	return qemuCloudPlatform{}
}

// AddStep declares an expected stage of the test. The web UI shows all steps
// from the start, tracking their progress. Call before or during the test.
// Returns a *Step whose Begin/End methods drive the progress display.
func (e *Env) AddStep(name string) *Step {
	s := &Step{
		name:  name,
		index: len(e.steps),
		env:   e,
	}
	e.steps = append(e.steps, s)
	return s
}

// Step returns a step by key, creating it if it doesn't exist.
// Safe for concurrent use. Both planSteps (dry-run) and boot (real-run)
// call this to get the same Step object.
func (e *Env) Step(key string) *Step {
	e.stepsMu.Lock()
	defer e.stepsMu.Unlock()
	if s, ok := e.stepsByKey[key]; ok {
		return s
	}
	s := &Step{
		name:  key,
		index: len(e.steps),
		env:   e,
	}
	e.steps = append(e.steps, s)
	if e.stepsByKey == nil {
		e.stepsByKey = make(map[string]*Step)
	}
	e.stepsByKey[key] = s
	return s
}

// Steps returns all declared steps in order.
func (e *Env) Steps() []*Step {
	return e.steps
}

// publishStepChange publishes a step status change event.
func (e *Env) publishStepChange(s *Step) {
	e.eventBus.Publish(VMEvent{
		Type:    EventStepChanged,
		Message: fmt.Sprintf("%s %s", s.Status().Icon(), s.name),
		Step:    s,
	})
}

// initNodeStatus initializes the NodeStatus for all nodes. Called after
// AddNode but before Start so the web UI can render them.
func (e *Env) initNodeStatus() {
	e.nodeStatusMu.Lock()
	defer e.nodeStatusMu.Unlock()
	for _, n := range e.nodes {
		nics := make([]NICStatus, len(n.nets))
		for i := range n.nets {
			nics[i] = NICStatus{
				NetName: e.nicLabel(n, i),
				DHCP:    "waiting",
			}
		}
		e.nodeStatus[n.name] = &NodeStatus{
			Name:         n.name,
			OS:           n.os.Name,
			NICs:         nics,
			JoinsTailnet: n.joinTailnet,
			Tailscale:    "--",
		}
	}
}

// nicLabel returns a short human-readable label for a node's i-th NIC.
// After Start(), we can use the assigned LAN IP. Before that, we use "NIC N".
func (e *Env) nicLabel(n *Node, i int) string {
	if n.vnetNode != nil {
		ip := n.vnetNode.LanIP(n.nets[i])
		if ip.IsValid() {
			return ip.String()
		}
	}
	return fmt.Sprintf("NIC %d", i)
}

// getNodeStatus returns the current status for a node.
func (e *Env) getNodeStatus(name string) NodeStatus {
	e.nodeStatusMu.Lock()
	defer e.nodeStatusMu.Unlock()
	ns := e.nodeStatus[name]
	if ns == nil {
		return NodeStatus{Name: name, Tailscale: "--"}
	}
	return *ns
}

// setNodeDHCP updates the DHCP status for a specific NIC on a node.
func (e *Env) setNodeDHCP(name string, nicIdx int, status string) {
	e.nodeStatusMu.Lock()
	ns := e.nodeStatus[name]
	if ns != nil && nicIdx < len(ns.NICs) {
		ns.NICs[nicIdx].DHCP = status
	}
	e.nodeStatusMu.Unlock()
}

// setNodeTailscale updates the Tailscale status for a node and publishes
// an event so the web UI updates via WebSocket.
func (e *Env) setNodeTailscale(name, status string) {
	e.nodeStatusMu.Lock()
	ns := e.nodeStatus[name]
	if ns != nil {
		ns.Tailscale = status
	}
	e.nodeStatusMu.Unlock()
	e.eventBus.Publish(VMEvent{
		NodeName: name,
		Type:     EventTailscale,
		Message:  "Tailscale: " + status,
		Detail:   status,
	})
}

// appendConsoleLine adds a line to a node's console buffer.
func (e *Env) appendConsoleLine(name, line string) {
	e.nodeStatusMu.Lock()
	ns := e.nodeStatus[name]
	if ns != nil {
		ns.Console = append(ns.Console, line)
		if len(ns.Console) > maxConsoleLines {
			ns.Console = ns.Console[len(ns.Console)-maxConsoleLines:]
		}
	}
	e.nodeStatusMu.Unlock()
}

// nicIndexForMAC returns the NIC index (0-based) for a given MAC on a node.
// Returns -1 if not found.
func (e *Env) nicIndexForMAC(name string, mac vnet.MAC) int {
	for _, n := range e.nodes {
		if n.name != name {
			continue
		}
		for i := range n.nets {
			if n.vnetNode.NICMac(i) == mac {
				return i
			}
		}
	}
	return -1
}

// nodeNameByNum returns the node name for a given vnet node number.
func (e *Env) nodeNameByNum(num int) string {
	for _, n := range e.nodes {
		if n.num == num {
			return n.name
		}
	}
	return fmt.Sprintf("node%d", num)
}

// New creates a new test environment. It skips the test if --run-vm-tests is
// not set. opts may contain [EnvOption] values returned by helpers like
// [SameTailnetUser].
func New(t testing.TB, opts ...EnvOption) *Env {
	if !*runVMTests {
		t.Skip("skipping VM test; set --run-vm-tests to run")
	}

	tempDir := t.TempDir()

	// Unix sockets have a short path limit (104 bytes on macOS). The Go
	// test TempDir path easily exceeds that, so create a dedicated short
	// directory under /tmp for sockets.
	sockDir, err := os.MkdirTemp("", "vmtest")
	if err != nil {
		t.Fatalf("creating socket tempdir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })

	e := &Env{
		t:          t,
		tempDir:    tempDir,
		sockDir:    sockDir,
		binDir:     filepath.Join(tempDir, "bin"),
		eventBus:   newEventBus(),
		testStatus: newTestStatus(),
		nodeStatus: make(map[string]*NodeStatus),
	}
	for _, o := range opts {
		o.applyTo(e)
	}
	t.Cleanup(func() {
		e.testStatus.finish(t.Failed())
		e.eventBus.Publish(VMEvent{
			Type:    EventTestStatus,
			Message: e.testStatus.State(),
			Detail:  formatDuration(e.testStatus.Elapsed()),
		})
	})
	return e
}

// EnvOption configures an [Env] in [New].
type EnvOption interface {
	applyTo(*Env)
}

type envOptFunc func(*Env)

func (f envOptFunc) applyTo(e *Env) { f(e) }

// SameTailnetUser returns an [EnvOption] that makes every node register with
// the test control server as the same Tailnet user. This is needed for
// cross-node features that require a same-user relationship — Taildrop, for
// example.
func SameTailnetUser() EnvOption {
	return envOptFunc(func(e *Env) { e.sameTailnetUser = true })
}

// AllOnline returns an [EnvOption] that makes the test control server mark
// every peer as Online=true in MapResponses (testcontrol.Server.AllOnline).
// Several disco-key handling fast paths in the controlclient and wgengine
// only fire when the peer is reported online; without this option those
// paths are silently skipped, which can mask bugs and slow down recovery
// from disco-key rotations.
func AllOnline() EnvOption {
	return envOptFunc(func(e *Env) { e.allOnline = true })
}

// PeerRelayGrants returns an [EnvOption] that makes the test control server
// grant [tailcfg.PeerCapabilityRelay] and [tailcfg.PeerCapabilityRelayTarget]
// on the wildcard packet filter (testcontrol.Server.PeerRelayGrants). Without
// those capabilities, magicsock does not consider any peer a candidate
// peer-relay server, so a node that has [ipn.Prefs.RelayServerPort] set
// cannot actually be used as a relay by its peers.
func PeerRelayGrants() EnvOption {
	return envOptFunc(func(e *Env) { e.peerRelayGrants = true })
}

// SelfSignedDERPCertPinning returns an [EnvOption] that makes the test control
// server advertise a DERP map whose nodes use CertName="sha256-raw:<hex>"
// pinning against the self-signed certs vnet's fake DERP servers serve. This
// exercises the sha256-raw verification path end-to-end (in tailscaled and in
// `tailscale debug derp`) without involving a real CA.
func SelfSignedDERPCertPinning() EnvOption {
	return envOptFunc(func(e *Env) { e.selfSignedDERPCertPinning = true })
}

// FakeACME returns an [EnvOption] that points nodes at vnet's in-process ACME
// CA and configures the test control server to advertise MagicDNS cert domains.
func FakeACME() EnvOption {
	return envOptFunc(func(e *Env) { e.fakeACME = true })
}

// ControlDNS returns an [EnvOption] that makes the test control server send
// the given DNS configuration in MapResponses, with node names placed under
// the given MagicDNS domain (e.g. "tailnet.test").
func ControlDNS(magicDNSDomain string, cfg *tailcfg.DNSConfig) EnvOption {
	return envOptFunc(func(e *Env) {
		e.controlDNSDomain = magicDNSDomain
		e.controlDNS = cfg
	})
}

// AddNetwork creates a new virtual network. Arguments follow the same pattern as
// vnet.Config.AddNetwork (string IPs, NAT types, NetworkService values).
func (e *Env) AddNetwork(opts ...any) *vnet.Network {
	return e.cfg.AddNetwork(opts...)
}

// RegisterFile registers a file with the vnet fileserver.
// It is served at http://files.tailscale/<path>.
func (e *Env) RegisterFile(path string, data []byte) {
	if e.server == nil {
		e.t.Fatalf("RegisterFile called before Start")
	}
	e.server.RegisterFile(path, data)
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
	runSSH           bool // true to enable the node's Tailscale SSH server
	noAgent          bool // true to skip TTA agent setup (e.g. macOS VMs without TTA)
	systemdUnit      bool // true to run tailscaled via the stock systemd unit (Linux cloud VMs only)
	advertiseRoutes  string
	snatSubnetRoutes *bool // nil means default (true)
	webServerPort    int
	sshPort          int     // host port for SSH debug access (cloud VMs only)
	dnsMode          DNSMode // desired Linux DNS backend to provision; "" means the image default
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
		case nodeOptTailscaleSSH:
			n.runSSH = true
		case nodeOptNoAgent:
			n.noAgent = true
		case nodeOptSystemdUnit:
			n.systemdUnit = true
		case nodeOptAdvertiseRoutes:
			n.advertiseRoutes = string(o)
		case nodeOptSNATSubnetRoutes:
			v := bool(o)
			n.snatSubnetRoutes = &v
		case nodeOptWebServer:
			n.webServerPort = int(o)
		case nodeOptDNSMode:
			switch DNSMode(o) {
			case DNSDefault, DNSDirect:
			default:
				e.t.Fatalf("AddNode(%q): unsupported DNSMode %q", name, DNSMode(o))
			}
			n.dnsMode = DNSMode(o)
		default:
			// Pass through to vnet (TailscaledEnv, NodeOption, MAC, etc.)
			vnetOpts = append(vnetOpts, o)
		}
	}
	if e.fakeACME {
		vnetOpts = append(vnetOpts, vnet.TailscaledEnv{
			Key:   "TS_DEBUG_ACME_DIRECTORY_URL",
			Value: "http://acme.example/directory",
		})
	}

	if n.systemdUnit && (n.os.IsGokrazy || n.os.GOOS() != "linux") {
		e.t.Fatalf("SystemdUnit is only supported on Linux cloud VMs; node %s is %s", name, n.os.Name)
	}

	// macOS VMs require a macOS arm64 host (Apple Virtualization.framework via
	// tailmac). Skip the test now rather than letting it proceed through the
	// rest of the setup only to fail later.
	if n.os.IsMacOS && (runtime.GOOS != "darwin" || runtime.GOARCH != "arm64") {
		e.t.Skipf("macOS VM tests require a macOS arm64 host (got %s/%s)", runtime.GOOS, runtime.GOARCH)
	}

	// Linux cloud images must declare a family; it drives distro-specific
	// cloud-init provisioning. gokrazy and non-Linux images don't use that path.
	if n.os.isLinuxCloudImage() && n.os.Family == "" {
		e.t.Fatalf("AddNode(%q): Linux cloud image %q has no LinuxFamily set", name, n.os.Name)
	}

	n.vnetNode = e.cfg.AddNode(vnetOpts...)
	n.num = n.vnetNode.Num()
	return n
}

// Name returns the name of the Node.
func (n *Node) Name() string {
	return n.name
}

// LanIP returns the LAN IPv4 address of this node on the given network.
// This is only valid after Env.Start() has been called.
// Name returns the node's name as set in [Env.AddNode].
func (n *Node) LanIP(net *vnet.Network) netip.Addr {
	return n.vnetNode.LanIP(net)
}

// DropControlTraffic sets up a blackhole for control traffic for just this
// node on all the networks belonging to the node.
func (n *Node) DropControlTraffic() {
	for _, network := range n.nets {
		network.BlackholeControlForAddr(n.LanIP(network))
	}
}

// NodeOption types for configuring nodes.

type nodeOptOS OSImage
type nodeOptNoTailscale struct{}
type nodeOptTailscaleSSH struct{}
type nodeOptNoAgent struct{}
type nodeOptSystemdUnit struct{}
type nodeOptAdvertiseRoutes string
type nodeOptSNATSubnetRoutes bool
type nodeOptWebServer int
type nodeOptDNSMode DNSMode

// DNSMode is a provisioning directive, not a DNS-backend name: it says what, if
// anything, to do to the guest's DNS before tailscaled starts, letting one
// distro image cover multiple backends. DNSDefault leaves DNS untouched (the
// resulting backend is image-dependent); the other modes provision the guest to
// force a specific backend, and are named to match the mode strings in
// net/dns/manager_linux.go so the result can be checked with
// [Env.AssertDNSBackend].
type DNSMode string

const (
	// DNSDefault leaves the image's DNS configuration untouched, so the backend
	// is whatever the image runs by default (typically systemd-resolved on
	// modern distros). It has no [Env.AssertDNSBackend] counterpart because the
	// result isn't forced.
	DNSDefault DNSMode = ""

	// DNSDirect masks systemd-resolved and installs a plain /etc/resolv.conf
	// so tailscaled selects the "direct" manager (rewrites resolv.conf itself).
	DNSDirect DNSMode = "direct"
)

// OS returns a NodeOption that sets the node's operating system image.
func OS(img OSImage) nodeOptOS { return nodeOptOS(img) }

// DontJoinTailnet returns a NodeOption that prevents the node from running tailscale up.
func DontJoinTailnet() nodeOptNoTailscale { return nodeOptNoTailscale{} }

// TailscaleSSH returns a NodeOption that enables the node's Tailscale SSH
// server by passing --ssh to tailscale up. If any node has this option, the
// test control server is configured with a permissive SSH policy that lets
// any tailnet node connect as any SSH user, mapped to the same-named local
// user.
func TailscaleSSH() nodeOptTailscaleSSH { return nodeOptTailscaleSSH{} }

// NoAgent returns a NodeOption that skips TTA agent setup. The node will not
// have a test agent, so agent-dependent operations (Status, ExecOnNode, etc.)
// won't work. Useful for VMs that just need to boot and respond to ICMP.
func NoAgent() nodeOptNoAgent { return nodeOptNoAgent{} }

// SystemdUnit returns a NodeOption that makes the node run tailscaled via the
// stock systemd unit that Linux packages ship (cmd/tailscaled/tailscaled.service
// with cmd/tailscaled/tailscaled.defaults as its EnvironmentFile), instead of
// launching tailscaled directly as a background process. This exercises the
// unit's sandboxing directives and its Type=notify readiness handshake.
// It is only supported on Linux cloud VMs (e.g. Ubuntu, Debian).
func SystemdUnit() nodeOptSystemdUnit { return nodeOptSystemdUnit{} }

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

// WithDNSMode returns a NodeOption that provisions the (Linux) node so
// tailscaled selects the given DNS backend. Only meaningful for Linux cloud
// images; ignored for gokrazy/macOS. See [DNSMode].
func WithDNSMode(m DNSMode) nodeOptDNSMode { return nodeOptDNSMode(m) }

// Start initializes the virtual network, boots all VMs in parallel, and waits
// for all TTA agents to connect. It should be called after all AddNetwork/AddNode calls.
func (e *Env) Start() {
	t := e.t

	// Give bring-up (image build, boot, agent wait) a generous budget measured
	// from now. We deliberately do NOT derive this from the test deadline: on
	// CI, per-test timeouts can be tight (a few minutes), and reserving headroom
	// under the deadline was observed to steal time bring-up legitimately needs,
	// failing slow-but-healthy runs. If bring-up genuinely exceeds this, the
	// `go test -timeout` panic is an acceptable (if blunt) backstop.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)
	e.ctx = ctx

	e.initNodeStatus()
	e.maybeStartWebServer()

	if err := os.MkdirAll(e.binDir, 0755); err != nil {
		t.Fatal(err)
	}

	if *testVersion != "" {
		v, err := resolveTestVersion(ctx, *testVersion)
		if err != nil {
			t.Fatalf("resolving --test-version=%q: %v", *testVersion, err)
		}
		e.testVersion = v
		t.Logf("using Tailscale release version %s (from --test-version=%q)", v, *testVersion)
	}

	// Dry-run: let each platform register its steps with the web UI.
	userSteps := e.steps
	e.steps = nil
	for _, n := range e.nodes {
		n.platform().planSteps(e, n)
	}
	for _, n := range e.nodes {
		if !n.noAgent {
			e.Step("Wait for agent: " + n.name)
		}
		if n.joinTailnet {
			e.Step("Tailscale up: " + n.name)
		}
	}
	for _, s := range userSteps {
		s.index = len(e.steps)
		e.steps = append(e.steps, s)
	}

	// Boot all nodes in parallel. Each platform handles its own
	// dependencies (image prep, binary compilation, socket setup)
	// via sync.Once, so independent work overlaps naturally.
	//
	// Under TCG, concurrent boots oversubscribe the host CPUs and a heavy
	// guest can starve its siblings past the stuck-detector; serialize boots
	// there so each clears that gate before the next starts. KVM stays parallel.
	var bootEg errgroup.Group
	if !hardwareAccelAvailable() {
		bootEg.SetLimit(1)
	}
	for _, n := range e.nodes {
		bootEg.Go(func() error {
			return n.platform().boot(ctx, e, n)
		})
	}
	if err := bootEg.Wait(); err != nil {
		t.Fatalf("boot: %v", err)
	}

	// Set up agent clients and wait for all agents to connect.
	for _, n := range e.nodes {
		if n.noAgent {
			continue
		}
		e.initVnet() // ensure vnet is ready for agent clients
		n.agent = e.server.NodeAgentClient(n.vnetNode)
		n.vnetNode.SetClient(n.agent)
	}

	var agentEg errgroup.Group
	for _, n := range e.nodes {
		if n.noAgent {
			continue
		}
		agentEg.Go(func() error {
			aStep := e.Step("Wait for agent: " + n.name)
			aStep.Begin()
			t.Logf("[%s] waiting for agent...", n.name)
			if n.joinTailnet {
				st, err := n.agent.Status(ctx)
				if err != nil {
					return fmt.Errorf("[%s] agent status: %w", n.name, err)
				}
				t.Logf("[%s] agent connected, backend state: %s", n.name, st.BackendState)
			} else {
				if err := e.waitForAgentConn(ctx, n); err != nil {
					return fmt.Errorf("[%s] agent connect: %w", n.name, err)
				}
				t.Logf("[%s] agent connected (no tailscale)", n.name)
			}
			aStep.End(nil)

			if n.vnetNode.HostFirewall() {
				if err := n.agent.EnableHostFirewall(ctx); err != nil {
					return fmt.Errorf("[%s] enable firewall: %w", n.name, err)
				}
			}

			if n.joinTailnet {
				tsStep := e.Step("Tailscale up: " + n.name)
				tsStep.Begin()
				if err := e.tailscaleUp(ctx, n); err != nil {
					return fmt.Errorf("[%s] tailscale up: %w", n.name, err)
				}
				st2, err := n.agent.Status(ctx)
				if err != nil {
					return fmt.Errorf("[%s] status after up: %w", n.name, err)
				}
				if st2.BackendState != "Running" {
					return fmt.Errorf("[%s] state = %q, want Running", n.name, st2.BackendState)
				}

				// Apply any capabilities for the node to the map.
				// SetNodeCapMap pushes an updated map response immediately, then wait
				// until the node reports the capability in its status.
				if cm := n.vnetNode.WantCapMap(); cm != nil {
					e.server.ControlServer().SetNodeCapMap(st2.Self.PublicKey, cm)
					if err := tstest.WaitFor(15*time.Second, func() error {
						st, err := n.agent.Status(ctx)
						if err != nil {
							return err
						}
						if st.Self == nil {
							return fmt.Errorf("self is nil")
						}
						for c := range cm {
							if !st.Self.HasCap(c) {
								return fmt.Errorf("cap %v not yet received", c)
							}
						}
						return nil
					}); err != nil {
						return fmt.Errorf("[%s] waiting for capabilities: %w", n.name, err)
					}
				}

				ips := fmt.Sprintf("%v", st2.Self.TailscaleIPs)
				e.setNodeTailscale(n.name, "Running "+ips)
				t.Logf("[%s] up with %v", n.name, st2.Self.TailscaleIPs)
				tsStep.End(nil)
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
	if n.runSSH {
		url += "&ssh=true"
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

// SetExitNodeIP sets the client's ExitNodeIP preference directly, by IP.
// This is the right helper for plain-WireGuard exit nodes (Mullvad-style)
// that aren't on the tailnet — pass an invalid netip.Addr{} to clear.
// For tailnet exit nodes whose Tailscale IP is discoverable via TTA, use
// [Env.SetExitNode] instead.
func (e *Env) SetExitNodeIP(client *Node, ip netip.Addr) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := client.agent.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			ExitNodeID: "",
			ExitNodeIP: ip,
		},
		ExitNodeIDSet: true,
		ExitNodeIPSet: true,
	}); err != nil {
		e.t.Fatalf("SetExitNodeIP(%s, %v): %v", client.name, ip, err)
	}
	if !ip.IsValid() {
		e.t.Logf("[%s] cleared exit node", client.name)
	} else {
		e.t.Logf("[%s] using exit-node IP %v", client.name, ip)
	}
}

// ControlServer returns the underlying test control server, for tests that
// need to inject custom peers, masquerade pairs, etc. The returned server's
// Node store is shared with the running tailnet, so changes take effect on
// the next netmap update sent to peers.
func (e *Env) ControlServer() *testcontrol.Server {
	return e.server.ControlServer()
}

// FakeACMERootPEM returns the root certificate for vnet's fake ACME CA.
func (e *Env) FakeACMERootPEM() []byte {
	e.initVnet()
	return e.server.FakeACMERootPEM()
}

// BringUpMullvadWGServer brings up a userspace WireGuard server on n,
// configured as a single-peer "Mullvad-style" exit-node target. The
// server runs inside n's TTA process on a Linux TUN named "wg0".
//
// gw is the WG interface address (e.g. 10.64.0.1/24). The server listens
// on listenPort, accepts only the single peer whose public key is peerPub
// at peerAllowedIP, and MASQUERADEs egress traffic from masqSrc so that
// decrypted packets from the peer egress with n's WAN IP.
//
// It returns the freshly generated public key of the WG server, which
// the caller must pin as the peer key on the [tailcfg.Node] it injects
// into the netmap to advertise this server as a plain-WireGuard exit
// node. It fatals the test on error.
func (e *Env) BringUpMullvadWGServer(n *Node, gw netip.Prefix, listenPort uint16, peerPub key.NodePublic, peerAllowedIP, masqSrc netip.Prefix) key.NodePublic {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	peerPubRaw := peerPub.Raw32()
	v := url.Values{
		"addr":            {gw.String()},
		"listen-port":     {strconv.Itoa(int(listenPort))},
		"peer-pub-b64":    {base64.StdEncoding.EncodeToString(peerPubRaw[:])},
		"peer-allowed-ip": {peerAllowedIP.String()},
		"masq-src":        {masqSrc.String()},
	}
	reqURL := "http://unused/wg-server-up?" + v.Encode()
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		e.t.Fatalf("BringUpMullvadWGServer: %v", err)
	}
	res, err := n.agent.HTTPClient.Do(req)
	if err != nil {
		e.t.Fatalf("BringUpMullvadWGServer(%s): %v", n.name, err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		e.t.Fatalf("BringUpMullvadWGServer(%s): %s: %s", n.name, res.Status, body)
	}
	var pubB64 string
	for line := range strings.SplitSeq(string(body), "\n") {
		if s, ok := strings.CutPrefix(strings.TrimSpace(line), "PUBKEY="); ok {
			pubB64 = s
			break
		}
	}
	if pubB64 == "" {
		e.t.Fatalf("BringUpMullvadWGServer(%s): no PUBKEY in response: %q", n.name, body)
	}
	pubRaw, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pubRaw) != 32 {
		e.t.Fatalf("BringUpMullvadWGServer(%s): bad PUBKEY %q: %v", n.name, pubB64, err)
	}
	return key.NodePublicFromRaw32(mem.B(pubRaw))
}

// Status returns the tailscale status of the given node, fetched from its
// TTA agent. It fatals the test on error.
func (e *Env) Status(n *Node) *ipnstate.Status {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := n.agent.Status(ctx)
	if err != nil {
		e.t.Fatalf("Status(%s): %v", n.name, err)
	}
	return st
}

// ClientMetrics returns the client metrics exported by the given node.
func (e *Env) ClientMetrics(n *Node) ClientMetrics {
	e.t.Helper()
	raw, err := n.Agent().DaemonMetrics(e.t.Context())
	if err != nil {
		e.t.Fatalf("Node %q DaemonMetrics: %v", n.Name(), err)
	}

	// Metrics are reported in Prometheus exposition format.
	// prometheus/common v0.67 made the validation scheme mandatory;
	// the zero-value parser now panics. LegacyValidation matches the
	// classic ASCII metric/label name rules that the tailscaled
	// client exporter uses.
	parser := expfmt.NewTextParser(model.LegacyValidation)
	mfs, err := parser.TextToMetricFamilies(bytes.NewReader(raw))
	if err != nil {
		e.t.Fatalf("Node %q parse client metrics: %v", n.Name(), err)
	}

	// Tailscale client metrics are all unlabelled integer-valued counters and
	// gauges, so we don't need to handle the full generality of the Prometheus
	// representation. If we see anything else, we'll log and skip it.
	out := make(ClientMetrics)
	for _, mf := range mfs {
		name := mf.GetName()
		if _, ok := out[name]; ok {
			e.t.Logf("Node %q: duplicate client metric %q (ignored)", n.Name(), name)
			continue
		} else if len(mf.Metric) != 1 {
			e.t.Logf("Node %q: got %d values for client metric %q, want 1 (ignored)", n.Name(), len(mf.Metric), name)
			continue
		}

		var mtype string
		var value int64
		switch mf.GetType() {
		case dto.MetricType_COUNTER:
			mtype = "counter"
			value = int64(mf.Metric[0].GetCounter().GetValue())
		case dto.MetricType_GAUGE:
			mtype = "gauge"
			value = int64(mf.Metric[0].GetGauge().GetValue())
		default:
			e.t.Logf("Node %q unexpected client metric %q type %q (ignored)", n.Name(), name, mf.GetType().String())
			continue
		}
		out[name] = ClientMetric{
			Name:  name,
			Type:  mtype,
			Value: value,
		}
	}
	return out
}

// dnsBackendMetricPrefix is the prefix of the clientmetric gauge that
// tailscaled sets to 1 for the Linux DNS mode it selected. See
// net/dns/manager_linux.go.
const dnsBackendMetricPrefix = "dns_manager_linux_mode_"

// DNSBackend returns the Linux DNS backend ("mode") the node's tailscaled
// selected (e.g. "systemd-resolved", "direct"). tailscaled sets a single gauge
// named dns_manager_linux_mode_<mode> to 1 for its selected mode (see
// net/dns/manager_linux.go); this finds that gauge and returns <mode>. It fails
// the test if none is set (non-Linux node, or DNS not yet configured).
func (e *Env) DNSBackend(n *Node) string {
	e.t.Helper()
	for name, m := range e.ClientMetrics(n) {
		mode, ok := strings.CutPrefix(name, dnsBackendMetricPrefix)
		if !ok || m.Value != 1 {
			continue
		}
		// tailscaled sanitizes "-" to "_" when forming the metric name;
		// reverse it so we return net/dns's spelling ("systemd-resolved").
		return strings.ReplaceAll(mode, "_", "-")
	}
	e.t.Fatalf("Node %q: no %s* gauge set (non-Linux node, or DNS not yet configured)", n.Name(), dnsBackendMetricPrefix)
	return ""
}

// AssertDNSBackend fails the test unless the node's selected Linux DNS backend
// matches want (see [Env.DNSBackend] for the mode strings). Use it in distro
// tests to prove the node exercises the intended DNS manager.
func (e *Env) AssertDNSBackend(n *Node, want string) {
	e.t.Helper()
	if got := e.DNSBackend(n); got != want {
		e.t.Fatalf("Node %q: DNS backend = %q, want %q", n.Name(), got, want)
	}
}

// ClientMetrics is a view of the client metrics exported by a node.
// The keys of the map are the metric names.
type ClientMetrics map[string]ClientMetric

// ClientMetric is a view of a node client metric.
type ClientMetric struct {
	Name  string // as published to the clientmetrics package
	Type  string // either "gauge" or "counter"
	Value int64  // the gauge or counter value
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

// ping does a disco ping from one node to another's Tailscale IP, retrying
// for up to 30 seconds, fataling on failure. It is used internally to wake
// up magicsock peer state before a test runs; tests that want to assert
// connectivity should use [Env.Ping] with the appropriate ping type and
// timeout.
func (e *Env) ping(from, to *Node) {
	e.t.Helper()
	if err := e.Ping(from, to, tailcfg.PingDisco, 30*time.Second); err != nil {
		e.t.Fatal(err)
	}
}

// Ping pings from one node to another's Tailscale IP using the given ping
// type, retrying until it succeeds or timeout expires. It returns the error
// from the last attempt if the timeout expires. Unlike the internal ping
// helper, it does not fatal the test on failure; callers can check the error
// to assert on timing.
//
// [tailcfg.PingTSMP] actually flows packets across the WireGuard tunnel and is
// the right choice for asserting end-to-end connectivity.
// [tailcfg.PingDisco] only exchanges disco messages between magicsock layers
// and is useful for warming up peer state without requiring a working tunnel.
func (e *Env) Ping(from, to *Node, ptype tailcfg.PingType, timeout time.Duration) error {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	toSt, err := to.agent.Status(ctx)
	if err != nil {
		return fmt.Errorf("ping: can't get %s status: %w", to.name, err)
	}
	if len(toSt.Self.TailscaleIPs) == 0 {
		return fmt.Errorf("ping: %s has no Tailscale IPs", to.name)
	}
	targetIP := toSt.Self.TailscaleIPs[0]

	var lastErr error
	for {
		// Per-attempt timeout: cap at 3s but never exceed the remaining budget.
		attemptTimeout := 3 * time.Second
		if d := time.Until(deadline(ctx)); d < attemptTimeout {
			attemptTimeout = d
		}
		if attemptTimeout <= 0 {
			break
		}
		pingCtx, pingCancel := context.WithTimeout(ctx, attemptTimeout)
		pr, err := from.agent.PingWithOpts(pingCtx, targetIP, ptype, local.PingOpts{})
		pingCancel()
		if err == nil && pr.Err == "" {
			e.logVerbosef("ping(%s): %s -> %s OK", ptype, from.name, targetIP)
			return nil
		}
		switch {
		case err != nil:
			lastErr = err
		case pr.Err != "":
			lastErr = fmt.Errorf("%s", pr.Err)
		}
		if ctx.Err() != nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = ctx.Err()
	}
	return fmt.Errorf("ping(%s): %s -> %s (%s) timed out after %v: %w", ptype, from.name, to.name, targetIP, timeout, lastErr)
}

// deadline returns ctx's deadline, or a zero Time if it has none.
func deadline(ctx context.Context) time.Time {
	d, _ := ctx.Deadline()
	return d
}

// PeerDiscoKey returns n's view of the given peer's disco key. It returns a
// non-nil error if the LocalAPI request fails (e.g. tailscaled briefly
// unavailable during a restart). It returns (zero, false, nil) if n is
// reachable but has no record of the given peer in its current netmap.
//
// PeerDiscoKey is suitable for use inside a [tstest.WaitFor] poll loop: it
// does not fatal the test on transient errors.
//
// The disco key is fetched from the debug-only "peer-disco-keys" LocalAPI
// action ([ipnlocal.LocalBackend.DebugPeerDiscoKeys]) rather than via
// [ipnstate.Status], to keep the production PeerStatus struct free of disco
// keys (and free of non-comparable fields like [key.DiscoPublic] that break
// reflect-based test helpers).
func (e *Env) PeerDiscoKey(n *Node, peer key.NodePublic) (key.DiscoPublic, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := n.agent.DebugResultJSON(ctx, "peer-disco-keys")
	if err != nil {
		return key.DiscoPublic{}, false, err
	}
	// DebugResultJSON returns the result as a generic any (the body is
	// re-decoded into any), so the map comes back keyed by string text-
	// encoded node keys. Re-marshal+unmarshal into a typed map for cleaner
	// lookup. (Roundtripping through JSON is fine for a test helper.)
	raw, err := json.Marshal(got)
	if err != nil {
		return key.DiscoPublic{}, false, fmt.Errorf("re-marshal: %w", err)
	}
	var m map[key.NodePublic]key.DiscoPublic
	if err := json.Unmarshal(raw, &m); err != nil {
		return key.DiscoPublic{}, false, fmt.Errorf("unmarshal peer-disco-keys: %w", err)
	}
	d, ok := m[peer]
	return d, ok, nil
}

// RotateDiscoKey asks tailscaled on n to rotate its discovery (magicsock) key
// in place via the LocalAPI debug action. The node key, control connection,
// and other tailscaled state are unaffected. It fatals the test on error.
func (e *Env) RotateDiscoKey(n *Node) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := n.agent.DebugAction(ctx, "rotate-disco-key"); err != nil {
		e.t.Fatalf("RotateDiscoKey(%s): %v", n.name, err)
	}
}

// ForcePreferredDERP pins n's home DERP to the given region via the
// "force-prefer-derp" debug action, so its reported NetInfo.PreferredDERP is
// deterministic. The force lives on the long-lived magicsock.Conn and so
// persists across an in-process profile switch. It fatals the test on error.
func (e *Env) ForcePreferredDERP(n *Node, region int) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := json.Marshal(region)
	if err != nil {
		e.t.Fatalf("ForcePreferredDERP(%s): %v", n.name, err)
	}
	if err := n.agent.DebugActionBody(ctx, "force-prefer-derp", bytes.NewReader(b)); err != nil {
		e.t.Fatalf("ForcePreferredDERP(%s, %d): %v", n.name, region, err)
	}
}

// Relogin switches n to a fresh login profile on the same test control server,
// in-process (no daemon restart), so it comes up under a NEW node identity while
// keeping the same long-lived magicsock.Conn. This is the control-client swap
// that an interactive login or profile switch performs, and is what the
// home-DERP re-report fix guards (see [magicsock.Conn.ResetNetInfoLast]).
//
// It switches to an empty profile (the in-process control-client swap the
// LocalAPI PUT /profiles/ performs) and then logs back in with "tailscale up",
// which both points the new control client at the test control and drives
// registration to completion. It waits for the node to return to Running and
// fatals the test on error.
func (e *Env) Relogin(n *Node) {
	e.t.Helper()
	// Generous timeout: the profile switch triggers a fresh registration +
	// netcheck + DERP connect, which is slow under TCG (no KVM).
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	// Switch to a fresh, empty login profile. This runs the in-process control-
	// client swap (resetForProfileChangeLocked -> setControlClientLocked) that
	// clears the home-DERP dedup cache under test, while preserving the existing
	// magicsock.Conn (and any forced home DERP from [Env.ForcePreferredDERP]).
	if err := n.agent.SwitchToEmptyProfile(ctx); err != nil {
		e.t.Fatalf("Relogin(%s): SwitchToEmptyProfile: %v", n.name, err)
	}
	// Log back in to the same test control. "tailscale up --login-server" points
	// the new control client at the test control and drives registration to
	// completion (testcontrol auto-authorizes), the same path Env.Start uses.
	if err := e.tailscaleUp(ctx, n); err != nil {
		e.t.Fatalf("Relogin(%s): up: %v", n.name, err)
	}
	if err := tstest.WaitFor(60*time.Second, func() error {
		st, err := n.agent.Status(ctx)
		if err != nil {
			return err
		}
		if st.BackendState != "Running" {
			return fmt.Errorf("backend state = %q, want Running", st.BackendState)
		}
		return nil
	}); err != nil {
		e.t.Fatalf("Relogin(%s): %v", n.name, err)
	}
}

// RestartTailscaled signals tailscaled on n to die so that its supervisor
// (gokrazy) restarts it. It then waits for tailscaled to come back to the
// "Running" backend state. It fatals the test on error.
//
// Restarting tailscaled is currently only supported on gokrazy nodes.
func (e *Env) RestartTailscaled(n *Node) {
	e.t.Helper()
	if !n.os.IsGokrazy {
		e.t.Fatalf("RestartTailscaled(%s): only supported on gokrazy nodes (have %q)", n.name, n.os.Name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "http://unused/restart-tailscaled", nil)
	if err != nil {
		e.t.Fatalf("RestartTailscaled(%s): %v", n.name, err)
	}
	res, err := n.agent.HTTPClient.Do(req)
	if err != nil {
		e.t.Fatalf("RestartTailscaled(%s): %v", n.name, err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		e.t.Fatalf("RestartTailscaled(%s): %s: %s", n.name, res.Status, body)
	}
	e.t.Logf("[%s] %s", n.name, strings.TrimSpace(string(body)))

	// Wait for tailscaled to come back. Status calls will fail while the unix
	// socket is gone, then return Starting/NeedsLogin briefly before settling
	// on Running.
	if err := tstest.WaitFor(45*time.Second, func() error {
		st, err := n.agent.Status(ctx)
		if err != nil {
			return err
		}
		if st.BackendState != "Running" {
			return fmt.Errorf("backend state = %q", st.BackendState)
		}
		return nil
	}); err != nil {
		e.t.Fatalf("RestartTailscaled(%s): waiting for Running: %v", n.name, err)
	}
}

// AddRoute adds a kernel static route on the given node, pointing prefix at
// via. It uses TTA's /add-route handler, so it works on any node where TTA
// is running (which is all of them — DontJoinTailnet only skips
// `tailscale up`; the agent runs regardless). Currently Linux-only in TTA.
//
// It fatals the test on error.
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
//
// SSH transport-level errors (exit code 255: connection refused, auth
// failure, etc.) are retried for up to ~30s to absorb the race window
// between Env.Start() returning (when tta reports the tailscale backend
// as Running) and cloud-init finishing the user/SSH-key setup. The remote
// command's own non-zero exit codes are returned to the caller without
// retry.
func (e *Env) SSHExec(n *Node, cmd string) (string, error) {
	if n.sshPort == 0 {
		return "", fmt.Errorf("node %s has no SSH debug port", n.name)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		sshCmd := exec.Command("ssh",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "BatchMode=yes",
			"-o", "ConnectTimeout=5",
			"-o", "LogLevel=ERROR",
			"-i", "/tmp/vmtest_key",
			"-p", fmt.Sprintf("%d", n.sshPort),
			"root@127.0.0.1",
			cmd)
		out, err := sshCmd.CombinedOutput()
		if err == nil {
			return string(out), nil
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 255 {
			return string(out), err
		}
		if time.Now().After(deadline) {
			return string(out), err
		}
		time.Sleep(500 * time.Millisecond)
	}
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

// HTTPResponse is the result of a successful [Env.HTTPGetStatus] call.
type HTTPResponse struct {
	// Status is the upstream HTTP status code.
	Status int
	// Body is the upstream response body.
	Body string
	// SetCookies is the parsed list of cookies the upstream set, if any.
	SetCookies []*http.Cookie
}

// HTTPGetStatus is like [Env.HTTPGet] but returns the upstream HTTP status
// code, body, and any Set-Cookie response cookies, so callers can assert on
// rejection responses (e.g. 401, 403) and drive multi-request flows that need
// cookie continuity (e.g. session-based authentication).
//
// Any sendCookies are sent on the upstream request via the Cookie header.
//
// The request is proxied through TTA's /http-get handler, which dials via
// Tailscale's UserDial; this works on any OS the test agent runs on.
//
// Like [Env.HTTPGet], HTTPGetStatus retries up to 3 times on TTA-level
// connection failures (502 / 503 from TTA when it cannot reach upstream).
// Upstream responses (including 4xx) are returned to the caller without retry.
func (e *Env) HTTPGetStatus(from *Node, targetURL string, sendCookies ...*http.Cookie) (*HTTPResponse, error) {
	cookieHeader := ""
	if len(sendCookies) > 0 {
		parts := make([]string, 0, len(sendCookies))
		for _, c := range sendCookies {
			parts = append(parts, c.Name+"="+c.Value)
		}
		cookieHeader = strings.Join(parts, "; ")
	}

	var lastErr error
	for attempt := range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		reqURL := "http://unused/http-get?url=" + url.QueryEscape(targetURL)
		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			cancel()
			return nil, err
		}
		if cookieHeader != "" {
			req.Header.Set("Cookie", cookieHeader)
		}
		res, err := from.agent.HTTPClient.Do(req)
		cancel()
		if err != nil {
			e.logVerbosef("HTTPGetStatus attempt %d from %s: %v", attempt+1, from.name, err)
			lastErr = err
			time.Sleep(2 * time.Second)
			continue
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		// A bare 502/503 with no X-Upstream-Status means TTA itself couldn't
		// reach upstream; retry. If the header is set, the upstream really
		// did answer with that status and we should pass it through.
		if (res.StatusCode == http.StatusBadGateway || res.StatusCode == http.StatusServiceUnavailable) &&
			res.Header.Get("X-Upstream-Status") == "" {
			e.logVerbosef("HTTPGetStatus attempt %d from %s: TTA %d: %s", attempt+1, from.name, res.StatusCode, string(b))
			lastErr = fmt.Errorf("TTA %d: %s", res.StatusCode, strings.TrimSpace(string(b)))
			time.Sleep(2 * time.Second)
			continue
		}
		return &HTTPResponse{
			Status:     res.StatusCode,
			Body:       string(b),
			SetCookies: res.Cookies(),
		}, nil
	}
	return nil, fmt.Errorf("HTTPGetStatus from %s to %s: gave up: %w", from.name, targetURL, lastErr)
}

// Tailscale runs the tailscale CLI on the given node via TTA.
func (e *Env) Tailscale(n *Node, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	q := url.Values{}
	for _, arg := range args {
		q.Add("arg", arg)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://unused/tailscale?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	res, err := n.agent.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return string(body), fmt.Errorf("tailscale %q: %s: %s", args, res.Status, res.Header.Get("Exec-Err"))
	}
	return string(body), nil
}

// GokrazyRoot returns the kernel root= argument from a Gokrazy node.
func (e *Env) GokrazyRoot(n *Node) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://unused/gokrazy-root", nil)
	if err != nil {
		return "", err
	}
	res, err := n.agent.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gokrazy-root: %s: %s", res.Status, strings.TrimSpace(string(body)))
	}
	return strings.TrimSpace(string(body)), nil
}

// setNodeScreenshot stores the latest screenshot data URI for a node.
func (e *Env) setNodeScreenshot(name, dataURI string) {
	e.nodeStatusMu.Lock()
	if ns := e.nodeStatus[name]; ns != nil {
		ns.Screenshot = dataURI
	}
	e.nodeStatusMu.Unlock()
}

// setNodeScreenshotPort stores the Host.app screenshot server port for a node.
func (e *Env) setNodeScreenshotPort(name string, port int) {
	e.nodeStatusMu.Lock()
	if ns := e.nodeStatus[name]; ns != nil {
		ns.ScreenshotPort = port
	}
	e.nodeStatusMu.Unlock()
}

// nodeScreenshotPort returns the Host.app screenshot server port for a node, or 0.
func (e *Env) nodeScreenshotPort(name string) int {
	e.nodeStatusMu.Lock()
	defer e.nodeStatusMu.Unlock()
	if ns := e.nodeStatus[name]; ns != nil {
		return ns.ScreenshotPort
	}
	return 0
}

// initVnet creates the vnet server. Called once via sync.Once.
func (e *Env) initVnet() {
	e.vnetOnce.Do(func() {
		var err error
		e.server, err = vnet.New(&e.cfg)
		if err != nil {
			e.t.Fatalf("vnet.New: %v", err)
		}
		e.t.Cleanup(func() { e.server.Close() })

		e.server.SetDHCPCallback(func(mac vnet.MAC, nodeNum int, msgType layers.DHCPMsgType, ip netip.Addr) {
			name := e.nodeNameByNum(nodeNum)
			nicIdx := e.nicIndexForMAC(name, mac)
			ipStr := ip.String()
			switch msgType {
			case layers.DHCPMsgTypeDiscover:
				e.setNodeDHCP(name, nicIdx, "Discover sent")
				e.eventBus.Publish(VMEvent{NodeName: name, Type: EventDHCPDiscover, Message: "DHCP Discover sent", NIC: nicIdx})
			case layers.DHCPMsgTypeOffer:
				e.setNodeDHCP(name, nicIdx, "Offered "+ipStr)
				e.eventBus.Publish(VMEvent{NodeName: name, Type: EventDHCPOffer, Message: "DHCP Offer received", Detail: ipStr, NIC: nicIdx})
			case layers.DHCPMsgTypeRequest:
				e.setNodeDHCP(name, nicIdx, "Requesting "+ipStr)
				e.eventBus.Publish(VMEvent{NodeName: name, Type: EventDHCPRequest, Message: "DHCP Request sent", Detail: ipStr, NIC: nicIdx})
			case layers.DHCPMsgTypeAck:
				e.setNodeDHCP(name, nicIdx, "Got "+ipStr)
				e.eventBus.Publish(VMEvent{NodeName: name, Type: EventDHCPAck, Message: "DHCP Ack: got " + ipStr, Detail: ipStr, NIC: nicIdx})
			}
		})

		if e.sameTailnetUser {
			e.server.ControlServer().AllNodesSameUser = true
		}
		if e.allOnline {
			e.server.ControlServer().AllOnline = true
		}
		if e.peerRelayGrants {
			e.server.ControlServer().PeerRelayGrants = true
		}
		if e.selfSignedDERPCertPinning {
			e.server.ControlServer().DERPMap = e.buildSelfSignedDERPMap()
		}
		if e.controlDNS != nil {
			cs := e.server.ControlServer()
			cs.MagicDNSDomain = e.controlDNSDomain
			cs.DNSConfig = e.controlDNS.Clone()
		}
		if e.fakeACME {
			cs := e.server.ControlServer()
			cs.MagicDNSDomain = "tailnet.test"
			if cs.DNSConfig == nil {
				cs.DNSConfig = new(tailcfg.DNSConfig)
			}
			cs.DNSConfig.Proxied = true
		}
		for _, n := range e.nodes {
			if n.runSSH {
				e.server.ControlServer().SSHPolicy = &tailcfg.SSHPolicy{
					Rules: []*tailcfg.SSHRule{{
						Principals: []*tailcfg.SSHPrincipal{{Any: true}},
						SSHUsers:   map[string]string{"*": "="},
						Action:     &tailcfg.SSHAction{Accept: true},
					}},
				}
				break
			}
		}
	})
}

// buildSelfSignedDERPMap returns a DERP map identical in structure to the
// stock test map (same regions, hostnames, virtual IPs) but with each node's
// CertName set to "sha256-raw:<hex>" pinning the actual self-signed cert
// served by vnet's fake DERP server, and InsecureForTests cleared so the
// pin is actually exercised. Nodes are matched to certs by HostName.
func (e *Env) buildSelfSignedDERPMap() *tailcfg.DERPMap {
	hostToHash := make(map[string]string, 2)
	for i := range 2 {
		hostToHash[e.server.DERPHostname(i)] = e.server.DERPCertSHA256Hex(i)
	}
	src := e.server.ControlServer().DERPMap
	dm := &tailcfg.DERPMap{
		Regions: make(map[int]*tailcfg.DERPRegion, len(src.Regions)),
	}
	for id, srcRegion := range src.Regions {
		r := *srcRegion
		r.Nodes = make([]*tailcfg.DERPNode, len(srcRegion.Nodes))
		for i, srcNode := range srcRegion.Nodes {
			n := *srcNode
			hash, ok := hostToHash[n.HostName]
			if !ok {
				e.t.Fatalf("buildSelfSignedDERPMap: no cert hash for HostName %q", n.HostName)
			}
			n.InsecureForTests = false
			n.CertName = "sha256-raw:" + hash
			r.Nodes[i] = &n
		}
		dm.Regions[id] = &r
	}
	return dm
}

// ensureQEMUSocket creates the Unix stream socket for QEMU VMs. Called once.
func (e *Env) ensureQEMUSocket() {
	e.qemuSockOnce.Do(func() {
		e.initVnet()
		e.sockAddr = filepath.Join(e.sockDir, "vnet.sock")
		srv, err := net.Listen("unix", e.sockAddr)
		if err != nil {
			e.t.Fatalf("listen unix: %v", err)
		}
		e.t.Cleanup(func() { srv.Close() })
		go func() {
			for {
				c, err := srv.Accept()
				if err != nil {
					return
				}
				go e.server.ServeUnixConn(c.(*net.UnixConn), vnet.ProtocolQEMU)
			}
		}()
	})
}

// ensureDgramSocket creates the Unix dgram socket for macOS VMs. Called once.
func (e *Env) ensureDgramSocket() {
	e.dgramSockOnce.Do(func() {
		e.initVnet()
		e.dgramSockAddr = filepath.Join(e.sockDir, "dgram.sock")
		dgramAddr, err := net.ResolveUnixAddr("unixgram", e.dgramSockAddr)
		if err != nil {
			e.t.Fatalf("resolve dgram addr: %v", err)
		}
		uc, err := net.ListenUnixgram("unixgram", dgramAddr)
		if err != nil {
			e.t.Fatalf("listen unixgram: %v", err)
		}
		e.t.Cleanup(func() { uc.Close() })
		go e.server.ServeUnixConn(uc, vnet.ProtocolUnixDGRAM)
	})
}

// ensureCompiled compiles binaries for the given platform and registers them
// with the vnet file server. Safe for concurrent use; only compiles once per platform.
func (e *Env) ensureCompiled(ctx context.Context, goos, goarch string) {
	key := goos + "_" + goarch

	e.compileMu.Lock()
	once, ok := e.compileOnce[key]
	if !ok {
		once = new(sync.Once)
		mak.Set(&e.compileOnce, key, once)
	}
	e.compileMu.Unlock()

	once.Do(func() {
		step := e.Step(fmt.Sprintf("Compile %s_%s binaries", goos, goarch))
		step.Begin()
		if err := e.compileBinariesForOS(ctx, goos, goarch); err != nil {
			step.End(err)
			e.t.Fatalf("compileBinariesForOS(%s, %s): %v", goos, goarch, err)
		}
		step.End(nil)
		e.registerBinaries(goos, goarch)
	})
}

// ensureImage prepares the cloud image for os and returns any error from the
// preparation. Safe for concurrent use; only prepares once per OS name.
func (e *Env) ensureImage(ctx context.Context, os OSImage) error {
	e.compileMu.Lock()
	once, ok := e.imageOnce[os.Name]
	if !ok {
		once = new(sync.Once)
		mak.Set(&e.imageOnce, os.Name, once)
	}
	e.compileMu.Unlock()

	var err error
	once.Do(func() {
		step := e.Step(fmt.Sprintf("Prepare %s image", os.Name))
		step.Begin()
		err = ensureImage(ctx, os)
		step.End(err)
	})
	return err
}

// registerBinaries registers compiled binaries with the vnet file server.
// Safe for concurrent use.
func (e *Env) registerBinaries(goos, goarch string) {
	e.initVnet()
	dir := goos + "_" + goarch
	for _, name := range []string{"tta", "tailscale", "tailscaled"} {
		data, err := os.ReadFile(filepath.Join(e.binDir, dir, name))
		if err != nil {
			e.t.Fatalf("reading compiled %s/%s: %v", dir, name, err)
		}
		e.server.RegisterFile(dir+"/"+name, data)
	}
}

// waitForAgentConn waits for a TTA agent to connect by issuing a simple
// HTTP GET to the root endpoint, without requiring tailscaled.
func (e *Env) waitForAgentConn(ctx context.Context, n *Node) error {
	for {
		reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, "GET", "http://unused/", nil)
		if err != nil {
			cancel()
			return err
		}
		res, err := n.agent.HTTPClient.Do(req)
		cancel()
		if err == nil {
			res.Body.Close()
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// Agent returns the node's TTA agent client, or nil if NoAgent is set.
func (n *Node) Agent() *vnet.NodeAgentClient {
	return n.agent
}

// LANPing pings a LAN IP from the given node using TTA's /ping endpoint.
// It retries for up to 2 minutes, which is enough for a macOS VM to boot
// and acquire a DHCP lease.
func (e *Env) LANPing(from *Node, targetIP netip.Addr) {
	if from.agent == nil {
		e.t.Fatalf("LANPing: node %s has no agent (NoAgent set?)", from.name)
	}
	e.t.Logf("LANPing: %s -> %s", from.name, targetIP)
	deadline := time.Now().Add(2 * time.Minute)
	for attempt := 0; time.Now().Before(deadline); attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		reqURL := fmt.Sprintf("http://unused/ping?host=%s", targetIP)
		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			cancel()
			e.t.Fatalf("LANPing: %v", err)
		}
		res, err := from.agent.HTTPClient.Do(req)
		cancel()
		if err != nil {
			if attempt%10 == 0 {
				e.t.Logf("LANPing attempt %d: %v", attempt+1, err)
			}
			time.Sleep(2 * time.Second)
			continue
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode == 200 {
			e.t.Logf("LANPing: %s -> %s succeeded on attempt %d", from.name, targetIP, attempt+1)
			return
		}
		if attempt%10 == 0 {
			e.t.Logf("LANPing attempt %d: status %d, body: %s", attempt+1, res.StatusCode, string(body))
		}
		time.Sleep(2 * time.Second)
	}
	e.t.Fatalf("LANPing: %s -> %s timed out after 2 minutes", from.name, targetIP)
}

// SendTaildropFile sends a file via Taildrop from one node to another.
// The to node must be on the tailnet. It fatals on error.
func (e *Env) SendTaildropFile(from, to *Node, name string, content []byte) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	st, err := to.agent.Status(ctx)
	if err != nil {
		e.t.Fatalf("SendTaildropFile: status for %s: %v", to.name, err)
	}
	if len(st.Self.TailscaleIPs) == 0 {
		e.t.Fatalf("SendTaildropFile: %s has no Tailscale IPs", to.name)
	}
	target := st.Self.TailscaleIPs[0].String()

	reqURL := fmt.Sprintf("http://unused/taildrop-send?to=%s&name=%s", target, name)
	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewReader(content))
	if err != nil {
		e.t.Fatalf("SendTaildropFile: %v", err)
	}
	res, err := from.agent.HTTPClient.Do(req)
	if err != nil {
		e.t.Fatalf("SendTaildropFile(%s -> %s): %v", from.name, to.name, err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		e.t.Fatalf("SendTaildropFile(%s -> %s): %s: %s", from.name, to.name, res.Status, body)
	}
	if msg := strings.TrimSpace(string(body)); msg != "" {
		e.t.Logf("[%s] %s", from.name, msg)
	}
	e.t.Logf("[%s] sent Taildrop %q (%d bytes) to %s", from.name, name, len(content), to.name)
}

// RecvTaildropFile waits for an incoming Taildrop file on the node and
// returns the filename and contents. The provided context bounds the wait;
// in addition, RecvTaildropFile imposes its own 90s upper bound. It fatals
// on error or timeout.
func (e *Env) RecvTaildropFile(ctx context.Context, n *Node) (name string, content []byte) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "http://unused/taildrop-recv", nil)
	if err != nil {
		e.t.Fatalf("RecvTaildropFile: %v", err)
	}
	res, err := n.agent.HTTPClient.Do(req)
	if err != nil {
		e.t.Fatalf("RecvTaildropFile(%s): %v", n.name, err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		e.t.Fatalf("RecvTaildropFile(%s): %s: %s", n.name, res.Status, body)
	}
	name = res.Header.Get("Taildrop-Filename")
	e.t.Logf("[%s] received Taildrop %q (%d bytes)", n.name, name, len(body))
	return name, body
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

// compileBinariesForOS prepares the tta, tailscale, and tailscaled binaries
// for the given GOOS/GOARCH and places them in e.binDir/<goos>_<goarch>/.
//
// tta is always built from the local source tree (the test agent must match
// the test framework). When --test-version is set, tailscale and tailscaled
// are taken from the downloaded release tarball instead of being compiled
// from source.
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

	// Use downloaded release binaries only on Linux: pkgs.tailscale.com only
	// publishes Linux tarballs, so other GOOS values still build from source.
	useDownloaded := e.testVersion != "" && goos == "linux"

	type binary struct{ name, pkg string }
	buildBins := []binary{{"tta", "./cmd/tta"}}
	if !useDownloaded {
		buildBins = append(buildBins,
			binary{"tailscale", "./cmd/tailscale"},
			binary{"tailscaled", "./cmd/tailscaled"})
	}

	var eg errgroup.Group
	for _, bin := range buildBins {
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

	if useDownloaded {
		eg.Go(func() error {
			srcDir, err := ensureVersionBinaries(ctx, e.testVersion, goarch, e.t.Logf)
			if err != nil {
				return err
			}
			for _, name := range []string{"tailscale", "tailscaled"} {
				if err := copyFile(filepath.Join(srcDir, name), filepath.Join(outDir, name), 0755); err != nil {
					return fmt.Errorf("staging %s/%s: %w", dir, name, err)
				}
			}
			e.t.Logf("staged version %s tailscale & tailscaled for %s", e.testVersion, dir)
			return nil
		})
	}

	return eg.Wait()
}

// copyFile copies src to dst with the given permission bits.
func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return writeAtomic(dst, in, perm)
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

	// Parse go.mod to find kernel version.
	for line := range strings.SplitSeq(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "github.com/gokrazy/kernel.amd64") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return filepath.Join(goModCache, parts[0]+"@"+parts[1], "vmlinuz"), nil
			}
		}
	}
	return "", fmt.Errorf("kernel.amd64 not found in %s", goMod)
}

// PingRoute describes what connection type was used to transfer a Disco ping.
type PingRoute string

const (
	PingRouteDirect PingRoute = "direct"
	PingRouteDERP   PingRoute = "derp"
	PingRouteLocal  PingRoute = "local"
	PingRouteNil    PingRoute = "nil"
)

// classifyPing finds what kind of route has been used on a ping path.
// It is only really relevant for DiscoPings.
func classifyPing(pr *ipnstate.PingResult) PingRoute {
	if pr == nil {
		return PingRouteNil
	}

	if pr.Endpoint == "" {
		return PingRouteDERP
	}

	ap, err := netip.ParseAddrPort(pr.Endpoint)
	if err == nil && ap.Addr().IsPrivate() {
		return PingRouteLocal
	}
	return PingRouteDirect
}

// PingExpect retries disco pings until the result matches wantRoute or the
// timeout is reached. It is using DiscoPings as this is the only ping type
// that can classify the connection type.
func (e *Env) PingExpect(from, to *Node, wantRoute PingRoute, timeout time.Duration) error {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(e.t.Context(), timeout)
	defer cancel()
	var lastRoute PingRoute
	toSt, err := to.agent.Status(ctx)
	if err != nil {
		return fmt.Errorf("ping: can't get %s status: %w", to.name, err)
	}
	if len(toSt.Self.TailscaleIPs) == 0 {
		return fmt.Errorf("ping: %s has no Tailscale IPs", to.name)
	}
	targetIP := toSt.Self.TailscaleIPs[0]
	for ctx.Err() == nil {
		pingCtx, pingCancel := context.WithTimeout(ctx, 3*time.Second)
		pr, err := from.agent.PingWithOpts(pingCtx, targetIP, tailcfg.PingDisco, local.PingOpts{})
		pingCancel()
		if err == nil && pr.Err == "" {
			if got := classifyPing(pr); got == wantRoute {
				e.t.Logf("Saw ping type %q", got)
				return nil
			} else {
				e.t.Logf("Saw ping type %q", got)
				lastRoute = got
			}
		}
		select {
		case <-time.After(500 * time.Millisecond):
		case <-ctx.Done():
		}
	}
	return fmt.Errorf("ping route = %q, want %q (after %v)", lastRoute, wantRoute, timeout)
}

// NumNodes returns the current number of nodes configured in the env.
func (env *Env) NumNodes() int {
	return len(env.nodes)
}
