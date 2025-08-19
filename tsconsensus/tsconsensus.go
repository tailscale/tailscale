// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tsconsensus implements a consensus algorithm for a group of tsnet.Servers
//
// The Raft consensus algorithm relies on you implementing a state machine that will give the same
// result to a given command as long as the same logs have been applied in the same order.
//
// tsconsensus uses the hashicorp/raft library to implement leader elections and log application.
//
// tsconsensus provides:
//   - cluster peer discovery based on tailscale tags
//   - executing a command on the leader
//   - communication between cluster peers over tailscale using tsnet
//
// Users implement a state machine that satisfies the raft.FSM interface, with the business logic they desire.
// When changes to state are needed any node may
//   - create a Command instance with serialized Args.
//   - call ExecuteCommand with the Command instance
//     this will propagate the command to the leader,
//     and then from the reader to every node via raft.
//   - the state machine then can implement raft.Apply, and dispatch commands via the Command.Name
//     returning a CommandResult with an Err or a serialized Result.
package tsconsensus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
	"tailscale.com/types/views"
)

func raftAddr(host netip.Addr, cfg Config) string {
	return netip.AddrPortFrom(host, cfg.RaftPort).String()
}

func addrFromServerAddress(sa string) (netip.Addr, error) {
	addrPort, err := netip.ParseAddrPort(sa)
	if err != nil {
		return netip.Addr{}, err
	}
	return addrPort.Addr(), nil
}

// A selfRaftNode is the info we need to talk to hashicorp/raft about our node.
// We specify the ID and Addr on Consensus Start, and then use it later for raft
// operations such as BootstrapCluster and AddVoter.
type selfRaftNode struct {
	id       string
	hostAddr netip.Addr
}

// A Config holds configurable values such as ports and timeouts.
// Use DefaultConfig to get a useful Config.
type Config struct {
	CommandPort       uint16
	RaftPort          uint16
	MonitorPort       uint16
	Raft              *raft.Config
	MaxConnPool       int
	ConnTimeout       time.Duration
	ServeDebugMonitor bool
	StateDirPath      string
}

// DefaultConfig returns a Config populated with default values ready for use.
func DefaultConfig() Config {
	raftConfig := raft.DefaultConfig()
	// these values are 2x the raft DefaultConfig
	raftConfig.HeartbeatTimeout = 2000 * time.Millisecond
	raftConfig.ElectionTimeout = 2000 * time.Millisecond
	raftConfig.LeaderLeaseTimeout = 1000 * time.Millisecond

	return Config{
		CommandPort: 6271,
		RaftPort:    6270,
		MonitorPort: 8081,
		Raft:        raftConfig,
		MaxConnPool: 5,
		ConnTimeout: 5 * time.Second,
	}
}

// StreamLayer implements an interface asked for by raft.NetworkTransport.
// It does the raft interprocess communication via tailscale.
type StreamLayer struct {
	net.Listener
	s           *tsnet.Server
	auth        *authorization
	shutdownCtx context.Context
}

// Dial implements the raft.StreamLayer interface with the tsnet.Server's Dial.
func (sl StreamLayer) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(sl.shutdownCtx, timeout)
	defer cancel()
	authorized, err := sl.addrAuthorized(ctx, string(address))
	if err != nil {
		return nil, err
	}
	if !authorized {
		return nil, errors.New("dial: peer is not allowed")
	}
	return sl.s.Dial(ctx, "tcp", string(address))
}

func (sl StreamLayer) addrAuthorized(ctx context.Context, address string) (bool, error) {
	addr, err := addrFromServerAddress(address)
	if err != nil {
		// bad RemoteAddr is not authorized
		return false, nil
	}
	err = sl.auth.Refresh(ctx)
	if err != nil {
		// might be authorized, we couldn't tell
		return false, err
	}
	return sl.auth.AllowsHost(addr), nil
}

func (sl StreamLayer) Accept() (net.Conn, error) {
	ctx, cancel := context.WithCancel(sl.shutdownCtx)
	defer cancel()
	for {
		conn, err := sl.Listener.Accept()
		if err != nil || conn == nil {
			return conn, err
		}
		addr := conn.RemoteAddr()
		if addr == nil {
			conn.Close()
			return nil, errors.New("conn has no remote addr")
		}
		authorized, err := sl.addrAuthorized(ctx, addr.String())
		if err != nil {
			conn.Close()
			return nil, err
		}
		if !authorized {
			log.Printf("StreamLayer accept: unauthorized: %s", addr)
			conn.Close()
			continue
		}
		return conn, err
	}
}

type BootstrapOpts struct {
	Tag        string
	FollowOnly bool
}

// Start returns a pointer to a running Consensus instance.
// Calling it with a *tsnet.Server will cause that server to join or start a consensus cluster
// with other nodes on the tailnet tagged with the clusterTag. The *tsnet.Server will run the state
// machine defined by the raft.FSM also provided, and keep it in sync with the other cluster members'
// state machines using Raft.
func Start(ctx context.Context, ts *tsnet.Server, fsm raft.FSM, bootstrapOpts BootstrapOpts, cfg Config) (*Consensus, error) {
	if bootstrapOpts.Tag == "" {
		return nil, errors.New("cluster tag must be provided")
	}

	cc := commandClient{
		port:       cfg.CommandPort,
		httpClient: ts.HTTPClient(),
	}
	v4, _ := ts.TailscaleIPs()
	// TODO(fran) support tailnets that have ipv4 disabled
	self := selfRaftNode{
		id:       v4.String(),
		hostAddr: v4,
	}
	shutdownCtx, shutdownCtxCancel := context.WithCancel(ctx)
	c := Consensus{
		commandClient:     &cc,
		self:              self,
		config:            cfg,
		shutdownCtxCancel: shutdownCtxCancel,
	}

	auth := newAuthorization(ts, bootstrapOpts.Tag)
	err := auth.Refresh(shutdownCtx)
	if err != nil {
		return nil, fmt.Errorf("auth refresh: %w", err)
	}
	if !auth.SelfAllowed() {
		return nil, errors.New("this node is not tagged with the cluster tag")
	}

	srv, err := c.serveCommandHTTP(ts, auth)
	if err != nil {
		return nil, err
	}
	c.cmdHttpServer = srv

	// after startRaft it's possible some other raft node that has us in their configuration will get
	// in contact, so by the time we do anything else we may already be a functioning member
	// of a consensus
	r, err := startRaft(shutdownCtx, ts, &fsm, c.self, auth, cfg)
	if err != nil {
		return nil, err
	}
	c.raft = r

	// we may already be in a consensus (see comment above before startRaft) but we're going to
	// try to bootstrap anyway in case this is a fresh start.
	err = c.bootstrap(shutdownCtx, auth, bootstrapOpts)
	if err != nil {
		if errors.Is(err, raft.ErrCantBootstrap) {
			// Raft cluster state can be persisted, if we try to call raft.BootstrapCluster when
			// we already have cluster state it will return raft.ErrCantBootstrap. It's safe to
			// ignore (according to the comment in the raft code), and we can expect that the other
			// nodes of the cluster will become available at some point and we can get back into the
			// consensus.
			log.Print("Bootstrap: raft has cluster state, waiting for peers")
		} else {
			return nil, err
		}
	}

	if cfg.ServeDebugMonitor {
		srv, err = serveMonitor(&c, ts, netip.AddrPortFrom(c.self.hostAddr, cfg.MonitorPort).String())
		if err != nil {
			return nil, err
		}
		c.monitorHttpServer = srv
	}

	return &c, nil
}

func startRaft(shutdownCtx context.Context, ts *tsnet.Server, fsm *raft.FSM, self selfRaftNode, auth *authorization, cfg Config) (*raft.Raft, error) {
	cfg.Raft.LocalID = raft.ServerID(self.id)

	var logStore raft.LogStore
	var stableStore raft.StableStore
	var snapStore raft.SnapshotStore

	if cfg.StateDirPath == "" {
		// comments in raft code say to only use for tests
		logStore = raft.NewInmemStore()
		stableStore = raft.NewInmemStore()
		snapStore = raft.NewInmemSnapshotStore()
	} else {
		var err error
		stableStore, logStore, err = boltStore(filepath.Join(cfg.StateDirPath, "store"))
		if err != nil {
			return nil, err
		}
		snaplogger := hclog.New(&hclog.LoggerOptions{
			Name:   "raft-snap",
			Output: cfg.Raft.LogOutput,
			Level:  hclog.LevelFromString(cfg.Raft.LogLevel),
		})
		snapStore, err = raft.NewFileSnapshotStoreWithLogger(filepath.Join(cfg.StateDirPath, "snapstore"), 2, snaplogger)
		if err != nil {
			return nil, err
		}
	}

	// opens the listener on the raft port, raft will close it when it thinks it's appropriate
	ln, err := ts.Listen("tcp", raftAddr(self.hostAddr, cfg))
	if err != nil {
		return nil, err
	}

	transportLogger := hclog.New(&hclog.LoggerOptions{
		Name:   "raft-net",
		Output: cfg.Raft.LogOutput,
		Level:  hclog.LevelFromString(cfg.Raft.LogLevel),
	})

	transport := raft.NewNetworkTransportWithLogger(StreamLayer{
		s:           ts,
		Listener:    ln,
		auth:        auth,
		shutdownCtx: shutdownCtx,
	},
		cfg.MaxConnPool,
		cfg.ConnTimeout,
		transportLogger)

	return raft.NewRaft(cfg.Raft, *fsm, logStore, stableStore, snapStore, transport)
}

// A Consensus is the consensus algorithm for a tsnet.Server
// It wraps a raft.Raft instance and performs the peer discovery
// and command execution on the leader.
type Consensus struct {
	raft              *raft.Raft
	commandClient     *commandClient
	self              selfRaftNode
	config            Config
	cmdHttpServer     *http.Server
	monitorHttpServer *http.Server
	shutdownCtxCancel context.CancelFunc
}

func (c *Consensus) bootstrapTryToJoinAnyTarget(targets views.Slice[*ipnstate.PeerStatus]) bool {
	log.Printf("Bootstrap: Trying to find cluster: num targets to try: %d", targets.Len())
	for _, p := range targets.All() {
		if !p.Online {
			log.Printf("Bootstrap: Trying to find cluster: tailscale reports not online: %s", p.TailscaleIPs[0])
			continue
		}
		log.Printf("Bootstrap: Trying to find cluster: trying %s", p.TailscaleIPs[0])
		err := c.commandClient.join(p.TailscaleIPs[0].String(), joinRequest{
			RemoteHost: c.self.hostAddr.String(),
			RemoteID:   c.self.id,
		})
		if err != nil {
			log.Printf("Bootstrap: Trying to find cluster: could not join %s: %v", p.TailscaleIPs[0], err)
			continue
		}
		log.Printf("Bootstrap: Trying to find cluster: joined %s", p.TailscaleIPs[0])
		return true
	}
	return false
}

func (c *Consensus) retryFollow(ctx context.Context, auth *authorization) bool {
	waitFor := 500 * time.Millisecond
	nRetries := 10
	attemptCount := 1
	for true {
		log.Printf("Bootstrap: trying to follow any cluster member: attempt %v", attemptCount)
		joined := c.bootstrapTryToJoinAnyTarget(auth.AllowedPeers())
		if joined || attemptCount == nRetries {
			return joined
		}
		log.Printf("Bootstrap: Failed to follow. Retrying in %v", waitFor)
		time.Sleep(waitFor)
		waitFor *= 2
		attemptCount++
		auth.Refresh(ctx)
	}
	return false
}

// bootstrap tries to join a raft cluster, or start one.
//
// We need to do the very first raft cluster configuration, but after that raft manages it.
// bootstrap is called at start up, and we may not currently be aware of what the cluster config might be,
// our node may already be in it. Try to join the raft cluster of all the other nodes we know about, and
// if unsuccessful, assume we are the first and try to start our own. If the FollowOnly option is set, only try
// to join, never start our own.
//
// It's possible for bootstrap to start an errant breakaway cluster if for example all nodes are having a fresh
// start, they're racing bootstrap and multiple nodes were unable to join a peer and so start their own new cluster.
// To avoid this operators should either ensure bootstrap is called for a single node first and allow it to become
// leader before starting the other nodes. Or start all but one node with the FollowOnly option.
//
// We have a list of expected cluster members already from control (the members of the tailnet with the tag)
// so we could do the initial configuration with all servers specified.
// Choose to start with just this machine in the raft configuration instead, as:
//   - We want to handle machines joining after start anyway.
//   - Not all tagged nodes tailscale believes are active are necessarily actually responsive right now,
//     so let each node opt in when able.
func (c *Consensus) bootstrap(ctx context.Context, auth *authorization, opts BootstrapOpts) error {
	if opts.FollowOnly {
		joined := c.retryFollow(ctx, auth)
		if !joined {
			return errors.New("unable to join cluster")
		}
		return nil
	}

	joined := c.bootstrapTryToJoinAnyTarget(auth.AllowedPeers())
	if joined {
		return nil
	}
	log.Printf("Bootstrap: Trying to find cluster: unsuccessful, starting as leader: %s", c.self.hostAddr.String())
	f := c.raft.BootstrapCluster(
		raft.Configuration{
			Servers: []raft.Server{
				{
					ID:      raft.ServerID(c.self.id),
					Address: raft.ServerAddress(c.raftAddr(c.self.hostAddr)),
				},
			},
		})
	return f.Error()
}

// ExecuteCommand propagates a Command to be executed on the leader. Which
// uses raft to Apply it to the followers.
func (c *Consensus) ExecuteCommand(cmd Command) (CommandResult, error) {
	b, err := json.Marshal(cmd)
	if err != nil {
		return CommandResult{}, err
	}
	result, err := c.executeCommandLocally(cmd)
	var leErr lookElsewhereError
	for errors.As(err, &leErr) {
		result, err = c.commandClient.executeCommand(leErr.where, b)
	}
	return result, err
}

// Stop attempts to gracefully shutdown various components.
func (c *Consensus) Stop(ctx context.Context) error {
	fut := c.raft.Shutdown()
	err := fut.Error()
	if err != nil {
		log.Printf("Stop: Error in Raft Shutdown: %v", err)
	}
	c.shutdownCtxCancel()
	err = c.cmdHttpServer.Shutdown(ctx)
	if err != nil {
		log.Printf("Stop: Error in command HTTP Shutdown: %v", err)
	}
	if c.monitorHttpServer != nil {
		err = c.monitorHttpServer.Shutdown(ctx)
		if err != nil {
			log.Printf("Stop: Error in monitor HTTP Shutdown: %v", err)
		}
	}
	return nil
}

// A Command is a representation of a state machine action.
type Command struct {
	// The Name can be used to dispatch the command when received.
	Name string
	// The Args are serialized for transport.
	Args json.RawMessage
}

// A CommandResult is a representation of the result of a state
// machine action.
type CommandResult struct {
	// Err is any error that occurred on the node that tried to execute the command,
	// including any error from the underlying operation and deserialization problems etc.
	Err error
	// Result is serialized for transport.
	Result json.RawMessage
}

type lookElsewhereError struct {
	where string
}

func (e lookElsewhereError) Error() string {
	return fmt.Sprintf("not the leader, try: %s", e.where)
}

var errLeaderUnknown = errors.New("leader unknown")

func (c *Consensus) serveCommandHTTP(ts *tsnet.Server, auth *authorization) (*http.Server, error) {
	ln, err := ts.Listen("tcp", c.commandAddr(c.self.hostAddr))
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: c.makeCommandHandler(auth)}
	go func() {
		err := srv.Serve(ln)
		log.Printf("CmdHttp stopped serving with err: %v", err)
	}()
	return srv, nil
}

func (c *Consensus) getLeader() (string, error) {
	raftLeaderAddr, _ := c.raft.LeaderWithID()
	leaderAddr := (string)(raftLeaderAddr)
	if leaderAddr == "" {
		// Raft doesn't know who the leader is.
		return "", errLeaderUnknown
	}
	// Raft gives us the address with the raft port, we don't always want that.
	host, _, err := net.SplitHostPort(leaderAddr)
	return host, err
}

func (c *Consensus) executeCommandLocally(cmd Command) (CommandResult, error) {
	b, err := json.Marshal(cmd)
	if err != nil {
		return CommandResult{}, err
	}
	f := c.raft.Apply(b, 0)
	err = f.Error()
	result := f.Response()
	if errors.Is(err, raft.ErrNotLeader) {
		leader, err := c.getLeader()
		if err != nil {
			// we know we're not leader but we were unable to give the address of the leader
			return CommandResult{}, err
		}
		return CommandResult{}, lookElsewhereError{where: leader}
	}
	if result == nil {
		result = CommandResult{}
	}
	return result.(CommandResult), err
}

func (c *Consensus) handleJoin(jr joinRequest) error {
	addr, err := netip.ParseAddr(jr.RemoteHost)
	if err != nil {
		return err
	}
	remoteAddr := c.raftAddr(addr)
	f := c.raft.AddVoter(raft.ServerID(jr.RemoteID), raft.ServerAddress(remoteAddr), 0, 0)
	if f.Error() != nil {
		return f.Error()
	}
	return nil
}

func (c *Consensus) raftAddr(host netip.Addr) string {
	return raftAddr(host, c.config)
}

func (c *Consensus) commandAddr(host netip.Addr) string {
	return netip.AddrPortFrom(host, c.config.CommandPort).String()
}

// GetClusterConfiguration returns the result of the underlying raft instance's GetConfiguration
func (c *Consensus) GetClusterConfiguration() (raft.Configuration, error) {
	fut := c.raft.GetConfiguration()
	err := fut.Error()
	if err != nil {
		return raft.Configuration{}, err
	}
	return fut.Configuration(), nil
}

// DeleteClusterServer returns the result of the underlying raft instance's RemoveServer
func (c *Consensus) DeleteClusterServer(id raft.ServerID) (uint64, error) {
	fut := c.raft.RemoveServer(id, 0, 1*time.Second)
	err := fut.Error()
	if err != nil {
		return 0, err
	}
	return fut.Index(), nil
}
