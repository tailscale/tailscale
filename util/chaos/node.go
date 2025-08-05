package chaos

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"tailscale.com/client/local"
	cc "tailscale.com/control/controlclient"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/multierr"
)

var (
	nodeJoins = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "chaos_node_joins_total",
		Help: "Incremented every time a node joins",
	}, []string{"tags"})
	nodeDisconnects = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "chaos_node_disconnects_total",
		Help: "Incremented when a node disconnects",
	}, []string{"tags"})
	connectedNodes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "chaos_online_nodes",
		Help: "Number of online nodes",
	}, []string{"tags"})
	joining = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "chaos_joining_nodes",
		Help: "Number of nodes in the process of joining the network",
	}, []string{"tags"})
	joinLatencies = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "chaos_join_latency_seconds",
		Help:    "Time it took to join",
		Buckets: prometheus.ExponentialBucketsRange(0.01, 30, 20),
	})
)

// Node is the interface that represent a Tailscale client.
// It can be implemented to use helper functions in this library
// to make it easier to create reusable scenarios.
//
// The standard implementation of Node is based on tsnet, which
// implements a full userspace tailscale client, but it can be
// quite heavy on both memory and cpu usage, so there might be
// cases where you want to implement your own Client via the node
// interface.
type Node interface {
	// Name returns the name of the underlying instance of Tailscale.
	Name() string

	// WaitRunning blocks until the underlying Tailscale reports running.
	WaitRunning(context.Context) error

	// Start starts Tailscale.
	Start(context.Context) error

	// Close stops Tailscale.
	Close(context.Context) error

	// Status returns the current status of the Tailscale client.
	Status(context.Context) (*ipnstate.Status, error)

	// Stats returns the node's connection stats (latency measurements, etc).
	Stats() *NodeStats
}

// NodeStats contains statistics about a Node's
// connection to the Tailscale network.
type NodeStats struct {
	// Name of node
	Name string

	// Durations spent logging in in milliseconds
	LoginDur time.Duration

	// Duration spent to get the first netmap in milliseconds
	FirstNetMapDur time.Duration

	// Number of peers in the first netmap
	PeerCount int
}

// NodeTSNet is a Node implementation based on tsnet,
// a userspace Tailscale client.
type NodeTSNet struct {
	tagsLabel string
	uuid      uuid.UUID
	dir       string

	ts *tsnet.Server
	lc *local.Client
}

// NodeOpts describes configuration options for nodes
// to be used during a chaos scenario. All options might
// not have affect on all implementations of the tailscale
// clients implemented.
type NodeOpts struct {
	loginServer string
	authKey     string
	ephemeral   bool
	tags        []string
	logf        logger.Logf
	userLogf    logger.Logf
}

// NewNodeTSNet returns a Node based on tsnet, a userspace Tailscale
// client.
func NewNodeTSNet(ctx context.Context, opts NodeOpts) (Node, error) {
	n := &NodeTSNet{
		uuid:      uuid.New(),
		ts:        new(tsnet.Server),
		tagsLabel: tagsMetricLabel(opts.tags, baseArgs.FullTagLabels),
	}

	if opts.authKey == "" {
		return nil, fmt.Errorf("AuthKey is required")
	}

	var err error
	if opts.ephemeral {
		n.ts.Store = new(mem.Store)
	} else {
		n.dir, err = os.MkdirTemp("", "chaos-node"+n.uuid.String())
		if err != nil {
			return nil, fmt.Errorf("failed to create temporary directory: %w", err)
		}
		n.ts.Dir = n.dir
	}

	n.ts.Hostname = n.Name()
	n.ts.ControlURL = opts.loginServer
	n.ts.AuthKey = opts.authKey
	n.ts.Ephemeral = opts.ephemeral
	n.ts.Logf = opts.logf
	n.ts.UserLogf = opts.userLogf

	lc, err := n.ts.LocalClient()
	if err != nil {
		return nil, err
	}
	n.lc = lc

	return n, nil
}

// NewNodeTSNetAsync returns a Node based on tsnet, a userspace Tailscale
// client, the function returns a channel which will get a Node or nil
// when it is ready.
func NewNodeTSNetAsync(ctx context.Context, opts NodeOpts) <-chan Node {
	ch := make(chan Node, 1)
	go func() {
		defer close(ch)
		n, err := NewNodeTSNet(ctx, opts)
		if err != nil {
			log.Printf("failed to create node: %v", err)
			return
		}
		ch <- n
	}()
	return ch
}

// waitForNotification waits for a notification that satisfies fn.
func (n *NodeTSNet) waitForNotification(ctx context.Context, fn func(n *ipn.Notify) bool) error {
	if n.lc == nil {
		return fmt.Errorf("LocalClient is nil")
	}

	watcher, err := n.lc.WatchIPNBus(ctx, ipn.NotifyInitialState)
	if err != nil {
		return err
	}

	for {
		n, err := watcher.Next()
		if err != nil {
			return fmt.Errorf("watching ipn: %w", err)
		}

		if fn(&n) {
			return nil
		}
	}
}

// Name returns the name of the node.
func (n *NodeTSNet) Name() string {
	return uuidToHostname(n.uuid)
}

// waitRunning waits for the node to be in the Running state.
func (n *NodeTSNet) WaitRunning(ctx context.Context) error {
	err := n.waitForNotification(ctx, func(n *ipn.Notify) bool {
		return n.State != nil && *n.State == ipn.Running
	})
	if err != nil {
		return fmt.Errorf("node %s failed to get to a running state: %w", n.Name(), err)
	}
	return nil
}

// Start starts the Tailscale client and waits for it to be in the Running state.
func (n *NodeTSNet) Start(_ context.Context) error {
	joining.WithLabelValues(n.tagsLabel).Inc()
	defer joining.WithLabelValues(n.tagsLabel).Dec()
	start := time.Now()

	err := n.ts.Start()
	if err == nil {
		nodeJoins.WithLabelValues(n.tagsLabel).Inc()
		connectedNodes.WithLabelValues(n.tagsLabel).Inc()
		joinLatencies.Observe(time.Since(start).Seconds())
	}
	return err
}

// Close stops the Tailscale client and cleans up any resources used by it.
func (n *NodeTSNet) Close(_ context.Context) error {
	defer nodeDisconnects.WithLabelValues(n.tagsLabel).Inc()
	defer connectedNodes.WithLabelValues(n.tagsLabel).Dec()
	defer func() {
		if n.dir != "" {
			if err := os.RemoveAll(n.dir); err != nil {
				log.Printf("failed to remove temporary directory %q: %v", n.dir, err)
			}
		}
	}()
	return n.ts.Close()
}

// Status returns the current status of the Tailscale client.
func (n *NodeTSNet) Status(ctx context.Context) (*ipnstate.Status, error) {
	return n.lc.Status(ctx)
}

// TODO(kradalby): Implement stats for tsnet
func (n *NodeTSNet) Stats() *NodeStats {
	return &NodeStats{
		Name: n.Name(),
	}
}

// NodeMap is a collection of Nodes and helper functions
// that can be used to do common scenario tasks on a lot
// of nodes.
type NodeMap struct {
	m  map[string]Node
	mu sync.Mutex
}

func (nm *NodeMap) Len() int {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	return len(nm.m)
}

// NewNodeMap creates a new NodeMap.
func NewNodeMap(nodeCount int) *NodeMap {
	return &NodeMap{
		m: make(map[string]Node, nodeCount),
	}
}

type NewNodeFunc func(context.Context, NodeOpts) <-chan Node

// NewNodeMapWithNodes creates N amount of Node instances and returns
// a new NodeMap.
func NewNodeMapWithNodes(ctx context.Context, newNode NewNodeFunc, nodeCount int, opts NodeOpts) (*NodeMap, error) {
	nm := NewNodeMap(nodeCount)

	return nm, nm.AddNodes(ctx, newNode, nodeCount, opts)
}

// AddNodes adds N amount of new nodes to the nodeMap.
func (nm *NodeMap) AddNodes(ctx context.Context, newNode NewNodeFunc, nodeCount int, opts NodeOpts) error {
	var errg errgroup.Group
	for range nodeCount {
		ch := newNode(ctx, opts)

		errg.Go(func() error {
			n, ok := <-ch
			if ok {
				if n == nil {
					return fmt.Errorf("error creating node")
				}
				nm.mu.Lock()
				nm.m[n.Name()] = n
				nm.mu.Unlock()
			}
			return nil
		})
	}

	return errg.Wait()
}

// WaitForReady waits for all nodes in the nodeMap to enter
// a "Running" ready state. An error will return if any of the
// nodes failed to reach that state within the limits of the
// passed context.
func (nm *NodeMap) WaitForReady(ctx context.Context) error {
	var errg errgroup.Group
	for _, n := range nm.m {
		n := n
		errg.Go(func() error {
			return n.WaitRunning(ctx)
		})
	}

	return errg.Wait()
}

// StartAll starts all nodes in the nodeMap. The concurrency limit
// restricts the number of nodes being started at the same time,
func (nm *NodeMap) StartAll(ctx context.Context, concurrency int) error {
	errChan := make(chan error, nm.Len())
	var wg sync.WaitGroup
	sem := semaphore.NewWeighted(int64(concurrency))

	count := 0
	for _, n := range nm.m {
		if err := sem.Acquire(ctx, 1); err != nil {
			errChan <- fmt.Errorf("Failed to acquire semaphore: %v", err)
			break
		}

		count++
		wg.Add(1)
		node := n
		go func() {
			defer sem.Release(1)
			defer wg.Done()
			if err := node.Start(ctx); err != nil {
				errChan <- fmt.Errorf("starting node %q: %w", node.Name(), err)
			}
		}()
	}
	wg.Wait()
	close(errChan)

	// Drain errors and combine
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	return multierr.New(errs...)
}

// SaveStatusToFile saves the stats of all nodes in the NodeMap
// to a JSON file at the specified path.
func (nm *NodeMap) SaveStatusToFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	nm.mu.Lock()
	var stats []*NodeStats
	for _, n := range nm.m {
		stats = append(stats, n.Stats())
	}
	nm.mu.Unlock()

	b, err := json.Marshal(stats)
	if err != nil {
		return fmt.Errorf("marshalling stats: %w", err)
	}

	_, err = f.Write(b)
	if err != nil {
		return fmt.Errorf("writing to file: %w", err)
	}

	return nil
}

// CloseAll closes all running nodes.
func (nm *NodeMap) CloseAll(ctx context.Context) error {
	errChan := make(chan error, nm.Len())
	var wg sync.WaitGroup
	for _, n := range nm.m {
		wg.Add(1)

		node := n
		go func() {
			defer wg.Done()
			if err := node.Close(ctx); err != nil {
				errChan <- fmt.Errorf("closing node %q: %w", node.Name(), err)
			}
		}()
	}
	wg.Wait()
	close(errChan)

	// Drain errors and combine
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	return multierr.New(errs...)
}

// CloseAndDeleteAll closes down all running nodes
// and deletes the from the tailcontrol server if they exists.
func (nm *NodeMap) CloseAndDeleteAll(ctx context.Context, c *Chaos) error {
	errChan := make(chan error, nm.Len())
	var wg sync.WaitGroup
	for _, n := range nm.m {
		wg.Add(1)

		node := n
		go func() {
			defer wg.Done()
			status, err := node.Status(ctx)
			if err != nil {
				errChan <- fmt.Errorf("getting status: %w", err)
				return
			}

			err = node.Close(ctx)
			if err != nil {
				errChan <- fmt.Errorf("closing node %q: %w", node.Name(), err)
				return
			}

			log.Printf("Deleting device %q (%s)", node.Name(), status.Self.ID)
			if err := c.Control.RemoveDevice(ctx, string(status.Self.ID)); err != nil {
				errChan <- fmt.Errorf("deleting device %q (%s): %w", node.Name(), status.Self.ID, err)
			}
		}()
	}
	wg.Wait()
	close(errChan)

	// Drain errors and combine
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	return multierr.New(errs...)
}

type NodeDirect struct {
	*cc.Direct
	ephemeral bool
	loggedIn  bool
	nodeID    tailcfg.NodeID
	stableID  tailcfg.StableNodeID
	nmChan    <-chan *netmap.NetworkMap
	logf      logger.Logf

	uuid      uuid.UUID
	tagsLabel string
	stats     NodeStats
	tracker   *netmapLatencyTracker
}

// NewNodeDirect returns a Node based on cc.Direct, a tiny tailscale
// client made for direct connection and testing.
func NewNodeDirect(nOpts NodeOpts) (Node, error) {
	node := &NodeDirect{
		uuid:      uuid.New(),
		ephemeral: nOpts.ephemeral,
		loggedIn:  false,
		logf:      nOpts.logf,
		tagsLabel: tagsMetricLabel(nOpts.tags, baseArgs.FullTagLabels),
	}
	node.stats = NodeStats{Name: node.Name()}
	if baseArgs.NetmapTracker {
		node.tracker = newLatencyTracker()
	}

	hi := &tailcfg.Hostinfo{
		Hostname: node.Name(),

		// Is required for the node to be able to connect to the tailcontrol server.
		BackendLogID:  "go-test-only",
		FrontendLogID: "go-test-only",
	}
	opts := cc.Options{
		ServerURL:      nOpts.loginServer,
		AuthKey:        nOpts.authKey,
		Hostinfo:       hi,
		Dialer:         tsdial.NewDialer(netmon.NewStatic()),
		DiscoPublicKey: key.NewDisco().Public(),
		HealthTracker:  new(health.Tracker),
		Logf:           nOpts.logf,
	}
	if opts.GetMachinePrivateKey == nil {
		opts.GetMachinePrivateKey = func() (key.MachinePrivate, error) { return key.NewMachine(), nil }
	}

	var err error
	node.Direct, err = cc.NewDirect(opts)
	if err != nil {
		return nil, fmt.Errorf("NewDirect: %w", err)
	}

	return node, nil
}

// NewNodeDirectAsync returns a Node based on cc.Direct, a tiny tailscale
// client made for direct connection and testing.
func NewNodeDirectAsync(_ context.Context, opts NodeOpts) <-chan Node {
	ch := make(chan Node, 1)
	go func() {
		defer close(ch)
		n, err := NewNodeDirect(opts)
		if err != nil {
			return
		}
		ch <- n
	}()
	return ch
}

// Name returns the name of the node.
func (n *NodeDirect) Name() string {
	return uuidToHostname(n.uuid)
}

// WaitRunning blocks until the node is logged in and has received
// the first netmap update.
func (n *NodeDirect) WaitRunning(ctx context.Context) error {
	for !n.loggedIn {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}

	if n.nmChan == nil {
		return fmt.Errorf("nmChan is nil, netmap channel not started")
	}

	return nil
}

// Start starts the node and waits for it to be logged in.
// When the node is logged in it will start listening for netmap updates.
func (n *NodeDirect) Start(ctx context.Context) error {
	joining.WithLabelValues(n.tagsLabel).Inc()
	defer joining.WithLabelValues(n.tagsLabel).Dec()

	loginStart := time.Now()
	loginFlag := cc.LoginDefault
	if n.ephemeral {
		loginFlag |= cc.LoginEphemeral
	}
	_, err := n.Direct.TryLogin(ctx, loginFlag)
	if err != nil {
		return fmt.Errorf("TryLogin: %w", err)
	}

	if n.tracker != nil {
		n.tracker.Start(n.uuid, n.tagsLabel)
	}

	n.loggedIn = true
	loginDone := time.Since(loginStart)

	firstNetMapStart := time.Now()
	nm, nmChan, err := n.waitForNetmapUpdates(ctx)
	if err != nil {
		return fmt.Errorf("getting initial netmap: %w", err)
	}
	firstNetMapStartDone := time.Since(firstNetMapStart)

	n.nmChan = nmChan
	n.stableID = nm.SelfNode.StableID()
	n.nodeID = nm.SelfNode.ID()
	n.stats.LoginDur = loginDone
	n.stats.FirstNetMapDur = firstNetMapStartDone
	n.stats.PeerCount = len(nm.Peers)

	log.Printf("node %q joined, login: %s, firstnm: %s, peercount: %d", n.Name(), loginDone.String(), firstNetMapStartDone.String(), len(nm.Peers))

	nodeJoins.WithLabelValues(n.tagsLabel).Inc()
	connectedNodes.WithLabelValues(n.tagsLabel).Inc()
	joinLatencies.Observe(time.Since(loginStart).Seconds())

	return err
}

func (n *NodeDirect) Close(ctx context.Context) error {
	defer nodeDisconnects.WithLabelValues(n.tagsLabel).Inc()
	defer connectedNodes.WithLabelValues(n.tagsLabel).Dec()
	err := n.Direct.TryLogout(ctx)
	if err != nil {
		return err
	}
	return n.Direct.Close()
}

func (n *NodeDirect) Status(context.Context) (*ipnstate.Status, error) {
	st := &ipnstate.Status{
		Self: &ipnstate.PeerStatus{
			ID: n.stableID,
		},
		BackendState: ipn.Stopped.String(),
	}
	if n.loggedIn {
		st.BackendState = ipn.Running.String()
	}

	return st, nil
}

func (n *NodeDirect) Stats() *NodeStats {
	return &n.stats
}

// NetmapUpdaterFunc implements controlclient.NetmapUpdater using a func.
type NetmapUpdaterFunc func(*netmap.NetworkMap)

func (f NetmapUpdaterFunc) UpdateFullNetmap(nm *netmap.NetworkMap) {
	f(nm)
}

// WaitForNetmapUpdates starts a netmap poll in a new goroutine and returns the
// first netmap and a channel to listen on for future netmap updates. It also
// returns a channel to listen on for errors. The channels are closed after the
// netmap poll returns, and are automatically drained on test completion.
func (n *NodeDirect) waitForNetmapUpdates(ctx context.Context) (*netmap.NetworkMap, <-chan *netmap.NetworkMap, error) {
	// buffered channel with netmaps. 50 is chosen arbitrarily.
	nmChan := make(chan *netmap.NetworkMap, 50)
	name := n.Name()

	go func() {
		defer close(nmChan)
		if n.tracker != nil {
			defer n.tracker.Done(n.uuid)
		}

		count := 0
		n.PollNetMap(ctx, NetmapUpdaterFunc(func(nm *netmap.NetworkMap) {
			count++
			log.Printf("Received %q netmap update (#%d), self: %s, peercount %d", name, count, nm.SelfNode.Name(), len(nm.Peers))

			// Only send the first netmap update, currently there is nothing
			// draining these and only the first one is used to determine if
			// the node is running.
			// TODO(kradalby): Put them back on the channel when there is a use
			// for them.
			if count == 1 {
				nmChan <- nm
			}

			if n.tracker != nil {
				n.tracker.ProcessNetmap(n.uuid, nm)
			}
		}))
	}()
	nm, ok := <-nmChan
	if !ok {
		return nil, nil, fmt.Errorf("did not receive initial netmap")
	}
	return nm, nmChan, nil
}
