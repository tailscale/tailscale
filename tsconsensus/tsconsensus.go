// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

/*
Package tsconsensus implements a consensus algorithm for a group of tsnet.Servers

The Raft consensus algorithm relies on you implementing a state machine that will give the same
result to a give command as long as the same logs have been applied in the same order.

tsconsensus uses the hashicorp/raft library to implement leader elections and log application.

tsconsensus provides:
  - cluster peer discovery based on tailscale tags
  - executing a command on the leader
  - communication between cluster peers over tailscale using tsnet

Users implement a state machine that satisfies the raft.FSM interface, with the business logic they desire.
When changes to state are needed any node may
  - create a Command instance with serialized Args.
  - call ExecuteCommand with the Command instance
    this will propagate the command to the leader,
    and then from the reader to every node via raft.
  - the state machine then can implement raft.Apply, and dispatch commands via the Command.Name
    returning a CommandResult with an Err or a serialized Result.
*/
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
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

func addr(host string, port uint16) string {
	return fmt.Sprintf("%s:%d", host, port)
}

func raftAddr(host string, cfg Config) string {
	return addr(host, cfg.RaftPort)
}

func addrFromServerAddress(sa string) (netip.Addr, error) {
	sAddr, _, err := net.SplitHostPort(sa)
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(sAddr)
}

// A selfRaftNode is the info we need to talk to hashicorp/raft about our node.
// We specify the ID and Addr on Consensus Start, and then use it later for raft
// operations such as BootstrapCluster and AddVoter.
type selfRaftNode struct {
	id   string
	host string
}

// A Config holds configurable values such as ports and timeouts.
// Use DefaultConfig to get a useful Config.
type Config struct {
	CommandPort uint16
	RaftPort    uint16
	MonitorPort uint16
	Raft        *raft.Config
	MaxConnPool int
	ConnTimeout time.Duration
}

// DefaultConfig returns a Config populated with default values ready for use.
func DefaultConfig() Config {
	return Config{
		CommandPort: 6271,
		RaftPort:    6270,
		MonitorPort: 8081,
		Raft:        raft.DefaultConfig(),
		MaxConnPool: 5,
		ConnTimeout: 5 * time.Second,
	}
}

// StreamLayer implements an interface asked for by raft.NetworkTransport.
// It does the raft interprocess communication via tailscale.
type StreamLayer struct {
	net.Listener
	s    *tsnet.Server
	auth *authorization
}

// Dial implements the raft.StreamLayer interface with the tsnet.Server's Dial.
func (sl StreamLayer) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := sl.auth.refresh(ctx)
	if err != nil {
		return nil, err
	}

	addr, err := addrFromServerAddress(string(address))
	if err != nil {
		return nil, err
	}

	if !sl.auth.allowsHost(addr) {
		return nil, errors.New("peer is not allowed")
	}
	return sl.s.Dial(ctx, "tcp", string(address))
}

func (sl StreamLayer) Accept() (net.Conn, error) {
	for {
		conn, err := sl.Listener.Accept()
		if err != nil || conn == nil {
			return conn, err
		}
		ctx := context.Background() // TODO
		err = sl.auth.refresh(ctx)
		if err != nil {
			// TODO should we stay alive here?
			return nil, err
		}

		if conn.RemoteAddr() == nil {
			continue
		}
		addr, err := addrFromServerAddress(conn.RemoteAddr().String())
		if err != nil {
			// TODO should we stay alive here?
			return nil, err
		}

		if !sl.auth.allowsHost(addr) {
			continue
		}
		return conn, err
	}
}

// Start returns a pointer to a running Consensus instance.
// Calling it with a *tsnet.Server will cause that server to join or start a consensus cluster
// with other nodes on the tailnet tagged with the clusterTag. The *tsnet.Server will run the state
// machine defined by the raft.FSM also provided, and keep it in sync with the other cluster members'
// state machines using Raft.
func Start(ctx context.Context, ts *tsnet.Server, fsm raft.FSM, clusterTag string, cfg Config, serveDebugMonitor bool) (*Consensus, error) {
	if clusterTag == "" {
		return nil, errors.New("cluster tag must be provided")
	}

	cc := commandClient{
		port:       cfg.CommandPort,
		httpClient: ts.HTTPClient(),
	}
	v4, _ := ts.TailscaleIPs()
	self := selfRaftNode{
		id:   v4.String(),
		host: v4.String(),
	}
	c := Consensus{
		commandClient: &cc,
		self:          self,
		config:        cfg,
	}

	auth := &authorization{
		tag: clusterTag,
		ts:  ts,
	}
	err := auth.refresh(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth refresh: %w", err)
	}
	if !auth.selfAllowed() {
		return nil, errors.New("this node is not tagged with the cluster tag")
	}

	// after startRaft it's possible some other raft node that has us in their configuration will get
	// in contact, so by the time we do anything else we may already be a functioning member
	// of a consensus
	r, err := startRaft(ts, &fsm, c.self, auth, cfg)
	if err != nil {
		return nil, err
	}
	c.raft = r

	srv, err := c.serveCmdHttp(ts, auth)
	if err != nil {
		return nil, err
	}
	c.cmdHttpServer = srv

	c.bootstrap(auth.allowedPeers())

	if serveDebugMonitor {
		srv, err = serveMonitor(&c, ts, addr(c.self.host, cfg.MonitorPort))
		if err != nil {
			return nil, err
		}
		c.monitorHttpServer = srv
	}

	return &c, nil
}

func startRaft(ts *tsnet.Server, fsm *raft.FSM, self selfRaftNode, auth *authorization, cfg Config) (*raft.Raft, error) {
	config := cfg.Raft
	config.LocalID = raft.ServerID(self.id)

	// no persistence (for now?)
	logStore := raft.NewInmemStore()
	stableStore := raft.NewInmemStore()
	snapshots := raft.NewInmemSnapshotStore()

	// opens the listener on the raft port, raft will close it when it thinks it's appropriate
	ln, err := ts.Listen("tcp", raftAddr(self.host, cfg))
	if err != nil {
		return nil, err
	}

	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "raft-net",
		Output: cfg.Raft.LogOutput,
		Level:  hclog.LevelFromString(cfg.Raft.LogLevel),
	})

	transport := raft.NewNetworkTransportWithLogger(StreamLayer{
		s:        ts,
		Listener: ln,
		auth:     auth,
	},
		cfg.MaxConnPool,
		cfg.ConnTimeout,
		logger)

	return raft.NewRaft(config, *fsm, logStore, stableStore, snapshots, transport)
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
}

// bootstrap tries to join a raft cluster, or start one.
//
// We need to do the very first raft cluster configuration, but after that raft manages it.
// bootstrap is called at start up, and we are not currently aware of what the cluster config might be,
// our node may already be in it. Try to join the raft cluster of all the other nodes we know about, and
// if unsuccessful, assume we are the first and start our own.
//
// It's possible for bootstrap to return an error, or start a errant breakaway cluster.
//
// We have a list of expected cluster members already from control (the members of the tailnet with the tag)
// so we could do the initial configuration with all servers specified.
// Choose to start with just this machine in the raft configuration instead, as:
//   - We want to handle machines joining after start anyway.
//   - Not all tagged nodes tailscale believes are active are necessarily actually responsive right now,
//     so let each node opt in when able.
func (c *Consensus) bootstrap(targets []*ipnstate.PeerStatus) error {
	log.Printf("Trying to find cluster: num targets to try: %d", len(targets))
	for _, p := range targets {
		if !p.Online {
			log.Printf("Trying to find cluster: tailscale reports not online: %s", p.TailscaleIPs[0])
		} else {
			log.Printf("Trying to find cluster: trying %s", p.TailscaleIPs[0])
			err := c.commandClient.join(p.TailscaleIPs[0].String(), joinRequest{
				RemoteHost: c.self.host,
				RemoteID:   c.self.id,
			})
			if err != nil {
				log.Printf("Trying to find cluster: could not join %s: %v", p.TailscaleIPs[0], err)
			} else {
				log.Printf("Trying to find cluster: joined %s", p.TailscaleIPs[0])
				return nil
			}
		}
	}

	log.Printf("Trying to find cluster: unsuccessful, starting as leader: %s", c.self.host)
	f := c.raft.BootstrapCluster(
		raft.Configuration{
			Servers: []raft.Server{
				{
					ID:      raft.ServerID(c.self.id),
					Address: raft.ServerAddress(c.raftAddr(c.self.host)),
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
// The Name can be used to dispatch the command when received.
// The Args are serialized for transport.
type Command struct {
	Name string
	Args []byte
}

// A CommandResult is a representation of the result of a state
// machine action.
// Err is any error that occurred on the node that tried to execute the command,
// including any error from the underlying operation and deserialization problems etc.
// Result is serialized for transport.
type CommandResult struct {
	Err    error
	Result []byte
}

type lookElsewhereError struct {
	where string
}

func (e lookElsewhereError) Error() string {
	return fmt.Sprintf("not the leader, try: %s", e.where)
}

var errLeaderUnknown = errors.New("Leader Unknown")

func (c *Consensus) serveCmdHttp(ts *tsnet.Server, auth *authorization) (*http.Server, error) {
	ln, err := ts.Listen("tcp", c.commandAddr(c.self.host))
	if err != nil {
		return nil, err
	}
	mux := c.makeCommandMux(auth)
	srv := &http.Server{Handler: mux}
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
	f := c.raft.Apply(b, 10*time.Second)
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
	remoteAddr := c.raftAddr(jr.RemoteHost)
	f := c.raft.AddVoter(raft.ServerID(jr.RemoteID), raft.ServerAddress(remoteAddr), 0, 0)
	if f.Error() != nil {
		return f.Error()
	}
	return nil
}

func (c *Consensus) raftAddr(host string) string {
	return raftAddr(host, c.config)
}

func (c *Consensus) commandAddr(host string) string {
	return addr(host, c.config.CommandPort)
}
