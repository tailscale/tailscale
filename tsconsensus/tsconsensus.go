package tsconsensus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/hashicorp/raft"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

/*
Package tsconsensus implements a consensus algorithm for a group of tsnet.Servers

The Raft consensus algorithm relies on you implementing a state machine that will give the same
result to a give command as long as the same logs have been applied in the same order.

tsconsensus uses the hashicorp/raft library to implement leader elections and log application.

tsconsensus provides:
 * cluster peer discovery based on tailscale tags
 * executing a command on the leader
 * communication between cluster peers over tailscale using tsnet

Users implement a state machine that satisfies the raft.FSM interface, with the business logic they desire.
When changes to state are needed any node may
 * create a Command instance with serialized Args.
 * call ExecuteCommand with the Command instance
   this will propagate the command to the leader,
   and then from the reader to every node via raft.
 * the state machine then can implement raft.Apply, and dispatch commands via the Command.Name
   returning a CommandResult with an Err or a serialized Result.
*/

func addr(host string, port uint16) string {
	return fmt.Sprintf("%s:%d", host, port)
}

func raftAddr(host string, cfg Config) string {
	return addr(host, cfg.RaftPort)
}

// A SelfRaftNode is the info we need to talk to hashicorp/raft about our node.
// We specify the ID and Addr on Consensus Start, and then use it later for raft
// operations such as BootstrapCluster and AddVoter.
type SelfRaftNode struct {
	ID   string
	Host string
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
	s *tsnet.Server
}

// Dial implements the raft.StreamLayer interface with the tsnet.Server's Dial.
func (sl StreamLayer) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	ctx, _ := context.WithTimeout(context.Background(), timeout)
	return sl.s.Dial(ctx, "tcp", string(address))
}

// Start returns a pointer to a running Consensus instance.
func Start(ctx context.Context, ts *tsnet.Server, fsm raft.FSM, targetTag string, cfg Config) (*Consensus, error) {
	v4, _ := ts.TailscaleIPs()
	cc := commandClient{
		port:       cfg.CommandPort,
		httpClient: ts.HTTPClient(),
	}
	self := SelfRaftNode{
		ID:   v4.String(),
		Host: v4.String(),
	}
	c := Consensus{
		CommandClient: &cc,
		Self:          self,
		Config:        cfg,
	}

	lc, err := ts.LocalClient()
	if err != nil {
		return nil, err
	}
	tStatus, err := lc.Status(ctx)
	if err != nil {
		return nil, err
	}
	var targets []*ipnstate.PeerStatus
	if targetTag != "" && tStatus.Self.Tags != nil && slices.Contains(tStatus.Self.Tags.AsSlice(), targetTag) {
		for _, v := range tStatus.Peer {
			if v.Tags != nil && slices.Contains(v.Tags.AsSlice(), targetTag) {
				targets = append(targets, v)
			}
		}
	} else {
		return nil, errors.New("targetTag empty, or this node is not tagged with it")
	}

	r, err := startRaft(ts, &fsm, c.Self, cfg)
	if err != nil {
		return nil, err
	}
	c.Raft = r
	srv, err := c.serveCmdHttp(ts)
	if err != nil {
		return nil, err
	}
	c.cmdHttpServer = srv
	c.bootstrap(targets)
	srv, err = serveMonitor(&c, ts, addr(c.Self.Host, cfg.MonitorPort))
	if err != nil {
		return nil, err
	}
	c.monitorHttpServer = srv
	return &c, nil
}

func startRaft(ts *tsnet.Server, fsm *raft.FSM, self SelfRaftNode, cfg Config) (*raft.Raft, error) {
	config := cfg.Raft
	config.LocalID = raft.ServerID(self.ID)

	// no persistence (for now?)
	logStore := raft.NewInmemStore()
	stableStore := raft.NewInmemStore()
	snapshots := raft.NewInmemSnapshotStore()

	// opens the listener on the raft port, raft will close it when it thinks it's appropriate
	ln, err := ts.Listen("tcp", raftAddr(self.Host, cfg))
	if err != nil {
		return nil, err
	}

	transport := raft.NewNetworkTransport(StreamLayer{
		s:        ts,
		Listener: ln,
	},
		cfg.MaxConnPool,
		cfg.ConnTimeout,
		nil) // TODO pass in proper logging

	// after NewRaft it's possible some other raft node that has us in their configuration will get
	// in contact, so by the time we do anything else we may already be a functioning member
	// of a consensus
	return raft.NewRaft(config, *fsm, logStore, stableStore, snapshots, transport)
}

// A Consensus is the consensus algorithm for a tsnet.Server
// It wraps a raft.Raft instance and performs the peer discovery
// and command execution on the leader.
type Consensus struct {
	Raft              *raft.Raft
	CommandClient     *commandClient
	Self              SelfRaftNode
	Config            Config
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
			err := c.CommandClient.Join(p.TailscaleIPs[0].String(), joinRequest{
				RemoteHost: c.Self.Host,
				RemoteID:   c.Self.ID,
			})
			if err != nil {
				log.Printf("Trying to find cluster: could not join %s: %v", p.TailscaleIPs[0], err)
			} else {
				log.Printf("Trying to find cluster: joined %s", p.TailscaleIPs[0])
				return nil
			}
		}
	}

	log.Printf("Trying to find cluster: unsuccessful, starting as leader: %s", c.Self.Host)
	f := c.Raft.BootstrapCluster(
		raft.Configuration{
			Servers: []raft.Server{
				{
					ID:      raft.ServerID(c.Self.ID),
					Address: raft.ServerAddress(c.raftAddr(c.Self.Host)),
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
		result, err = c.CommandClient.ExecuteCommand(leErr.where, b)
	}
	return result, err
}

// Stop attempts to gracefully shutdown various components.
func (c *Consensus) Stop(ctx context.Context) error {
	fut := c.Raft.Shutdown()
	err := fut.Error()
	if err != nil {
		log.Printf("Stop: Error in Raft Shutdown: %v", err)
	}
	err = c.cmdHttpServer.Shutdown(ctx)
	if err != nil {
		log.Printf("Stop: Error in command HTTP Shutdown: %v", err)
	}
	err = c.monitorHttpServer.Shutdown(ctx)
	if err != nil {
		log.Printf("Stop: Error in monitor HTTP Shutdown: %v", err)
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

var ErrLeaderUnknown = errors.New("Leader Unknown")

func (c *Consensus) serveCmdHttp(ts *tsnet.Server) (*http.Server, error) {
	ln, err := ts.Listen("tcp", c.commandAddr(c.Self.Host))
	if err != nil {
		return nil, err
	}
	mux := c.makeCommandMux()
	srv := &http.Server{Handler: mux}
	go func() {
		err := srv.Serve(ln)
		log.Printf("CmdHttp stopped serving with err: %v", err)
	}()
	return srv, nil
}

func (c *Consensus) getLeader() (string, error) {
	raftLeaderAddr, _ := c.Raft.LeaderWithID()
	leaderAddr := (string)(raftLeaderAddr)
	if leaderAddr == "" {
		// Raft doesn't know who the leader is.
		return "", ErrLeaderUnknown
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
	f := c.Raft.Apply(b, 10*time.Second)
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
	f := c.Raft.AddVoter(raft.ServerID(jr.RemoteID), raft.ServerAddress(remoteAddr), 0, 0)
	if f.Error() != nil {
		return f.Error()
	}
	return nil
}

func (c *Consensus) raftAddr(host string) string {
	return raftAddr(host, c.Config)
}

func (c *Consensus) commandAddr(host string) string {
	return addr(host, c.Config.CommandPort)
}
