package main

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
	"time"

	"github.com/hashicorp/raft"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

type consensus struct {
	Raft          *raft.Raft
	CommandClient *commandClient
	Self          selfRaftNode
}

type selfRaftNode struct {
	ID   string
	Addr netip.Addr
}

func (n *selfRaftNode) addrRaftPort() netip.AddrPort {
	return netip.AddrPortFrom(n.Addr, 6311)
}

// StreamLayer implements an interface asked for by raft.NetworkTransport.
// Do the raft interprocess comms via tailscale.
type StreamLayer struct {
	net.Listener
	s *tsnet.Server
}

// Dial is used to create a new outgoing connection
func (sl StreamLayer) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	ctx, _ := context.WithTimeout(context.Background(), timeout)
	return sl.s.Dial(ctx, "tcp", string(address))
}

type listeners struct {
	raft    *StreamLayer // for the raft goroutine
	command net.Listener // for the command http goroutine
}

func NewConsensus(myAddr netip.Addr, httpClient *http.Client) *consensus {
	cc := commandClient{
		port:       6312,
		httpClient: httpClient,
	}
	self := selfRaftNode{
		ID:   myAddr.String(),
		Addr: myAddr,
	}
	return &consensus{
		CommandClient: &cc,
		Self:          self,
	}
}

func (c *consensus) Start(lns *listeners, sm *fsm) error {
	config := raft.DefaultConfig()
	config.LocalID = raft.ServerID(c.Self.ID)
	config.HeartbeatTimeout = 1000 * time.Millisecond
	config.ElectionTimeout = 1000 * time.Millisecond
	logStore := raft.NewInmemStore()
	stableStore := raft.NewInmemStore()
	snapshots := raft.NewInmemSnapshotStore()
	transport := raft.NewNetworkTransport(lns.raft, 5, 5*time.Second, nil)

	ra, err := raft.NewRaft(config, sm, logStore, stableStore, snapshots, transport)
	if err != nil {
		return fmt.Errorf("new raft: %s", err)
	}
	c.Raft = ra

	mux := c.makeCommandMux()
	go func() {
		defer lns.command.Close()
		log.Fatal(http.Serve(lns.command, mux))
	}()
	return nil
}

func (c *consensus) handleJoin(jr joinRequest) error {
	configFuture := c.Raft.GetConfiguration()
	if err := configFuture.Error(); err != nil {
		return err
	}

	for _, srv := range configFuture.Configuration().Servers {
		// If a node already exists with either the joining node's ID or address,
		// that node may need to be removed from the config first.
		if srv.ID == raft.ServerID(jr.RemoteID) || srv.Address == raft.ServerAddress(jr.RemoteAddr) {
			// However if *both* the ID and the address are the same, then nothing -- not even
			// a join operation -- is needed.
			if srv.Address == raft.ServerAddress(jr.RemoteAddr) && srv.ID == raft.ServerID(jr.RemoteID) {
				log.Printf("node %s at %s already member of cluster, ignoring join request", jr.RemoteID, jr.RemoteAddr)
				return nil
			}

			future := c.Raft.RemoveServer(srv.ID, 0, 0)
			if err := future.Error(); err != nil {
				return fmt.Errorf("error removing existing node %s at %s: %s", jr.RemoteID, jr.RemoteAddr, err)
			}
		}
	}

	f := c.Raft.AddVoter(raft.ServerID(jr.RemoteID), raft.ServerAddress(jr.RemoteAddr), 0, 0)
	if f.Error() != nil {
		return f.Error()
	}
	return nil
}

// try to join a raft cluster, or start one
func BootstrapConsensus(sm *fsm, myAddr netip.Addr, lns *listeners, targets []*ipnstate.PeerStatus, httpClient *http.Client) (*consensus, error) {
	cns := NewConsensus(myAddr, httpClient)
	err := cns.Start(lns, sm)
	if err != nil {
		return cns, err
	}
	joined := false
	log.Printf("Trying to find cluster: num targets to try: %d", len(targets))
	for _, p := range targets {
		if !p.Online {
			log.Printf("Trying to find cluster: tailscale reports not online: %s", p.TailscaleIPs[0])
		} else {
			log.Printf("Trying to find cluster: trying %s", p.TailscaleIPs[0])
			err = cns.JoinCluster(p.TailscaleIPs[0])
			if err != nil {
				log.Printf("Trying to find cluster: could not join %s: %v", p.TailscaleIPs[0], err)
			} else {
				log.Printf("Trying to find cluster: joined %s", p.TailscaleIPs[0])
				joined = true
				break
			}
		}
	}

	if !joined {
		log.Printf("Trying to find cluster: unsuccessful, starting as leader: %s", myAddr)
		err = cns.LeadCluster()
		if err != nil {
			return cns, err
		}
	}
	return cns, nil
}

func (c *consensus) JoinCluster(a netip.Addr) error {
	return c.CommandClient.Join(c.CommandClient.ServerAddressFromAddr(a), joinRequest{
		RemoteAddr: c.Self.addrRaftPort().String(),
		RemoteID:   c.Self.ID,
	})

}

func (c *consensus) LeadCluster() error {
	configuration := raft.Configuration{
		Servers: []raft.Server{
			{
				ID:      raft.ServerID(c.Self.ID),
				Address: raft.ServerAddress(fmt.Sprintf("%s:6311", c.Self.Addr)),
			},
		},
	}
	f := c.Raft.BootstrapCluster(configuration)
	return f.Error()
}

// plumbing for executing a command either locally or via http transport
// and telling peers we're not the leader and who we think the leader is
type command struct {
	Name string
	Args []byte
}

type commandResult struct {
	Err    error
	Result []byte
}

type lookElsewhereError struct {
	where string
}

func (e lookElsewhereError) Error() string {
	return fmt.Sprintf("not the leader, try: %s", e.where)
}

func (c *consensus) executeCommandLocally(cmd command) (commandResult, error) {
	b, err := json.Marshal(cmd)
	if err != nil {
		return commandResult{}, err
	}
	f := c.Raft.Apply(b, 10*time.Second)
	err = f.Error()
	result := f.Response()
	if errors.Is(err, raft.ErrNotLeader) {
		raftLeaderAddr, _ := c.Raft.LeaderWithID()
		leaderAddr := (string)(raftLeaderAddr)
		if leaderAddr != "" {
			leaderAddr = leaderAddr[:len(raftLeaderAddr)-1] + "2" // TODO
		}
		return commandResult{}, lookElsewhereError{where: leaderAddr}
	}
	return result.(commandResult), err
}

func (c *consensus) executeCommand(cmd command) (commandResult, error) {
	b, err := json.Marshal(cmd)
	if err != nil {
		return commandResult{}, err
	}
	result, err := c.executeCommandLocally(cmd)
	var leErr lookElsewhereError
	for errors.As(err, &leErr) {
		result, err = c.CommandClient.ExecuteCommand(leErr.where, b)
	}
	return result, err
}

// fulfil the raft lib functional state machine interface
type fsm ipPool
type fsmSnapshot struct{}

func (f *fsm) Apply(l *raft.Log) interface{} {
	var c command
	if err := json.Unmarshal(l.Data, &c); err != nil {
		panic(fmt.Sprintf("failed to unmarshal command: %s", err.Error()))
	}
	switch c.Name {
	case "checkoutAddr":
		return f.executeCheckoutAddr(c.Args)
	case "markLastUsed":
		return f.executeMarkLastUsed(c.Args)
	default:
		panic(fmt.Sprintf("unrecognized command: %s", c.Name))
	}
}

func (f *fsm) Snapshot() (raft.FSMSnapshot, error) {
	panic("Snapshot unexpectedly used")
	return nil, nil
}

func (f *fsm) Restore(rc io.ReadCloser) error {
	panic("Restore unexpectedly used")
	return nil
}

func (f *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	panic("Persist unexpectedly used")
	return nil
}

func (f *fsmSnapshot) Release() {
	panic("Release unexpectedly used")
}
