package tsconsensus

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/tstest/nettest"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

type fsm struct {
	events []map[string]interface{}
	count  int
}
type fsmSnapshot struct{}

func (f *fsm) Apply(l *raft.Log) interface{} {
	f.count++
	f.events = append(f.events, map[string]interface{}{
		"type": "Apply",
		"l":    l,
	})
	return CommandResult{
		Result: []byte{byte(f.count)},
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

var verboseDERP = false
var verboseNodes = false

// TODO copied from sniproxy_test
func startControl(t *testing.T) (control *testcontrol.Server, controlURL string) {
	// Corp#4520: don't use netns for tests.
	netns.SetEnabled(false)
	t.Cleanup(func() {
		netns.SetEnabled(true)
	})

	derpLogf := logger.Discard
	if verboseDERP {
		derpLogf = t.Logf
	}
	derpMap := integration.RunDERPAndSTUN(t, derpLogf, "127.0.0.1")
	control = &testcontrol.Server{
		DERPMap: derpMap,
		DNSConfig: &tailcfg.DNSConfig{
			Proxied: true,
		},
		MagicDNSDomain: "tail-scale.ts.net",
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	controlURL = control.HTTPTestServer.URL
	t.Logf("testcontrol listening on %s", controlURL)
	return control, controlURL
}

// TODO copied from sniproxy_test
func startNode(t *testing.T, ctx context.Context, controlURL, hostname string) (*tsnet.Server, key.NodePublic, netip.Addr) {
	t.Helper()

	tmp := filepath.Join(t.TempDir(), hostname)
	os.MkdirAll(tmp, 0755)
	s := &tsnet.Server{
		Dir:        tmp,
		ControlURL: controlURL,
		Hostname:   hostname,
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	if verboseNodes {
		s.Logf = log.Printf
	}
	t.Cleanup(func() { s.Close() })

	status, err := s.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return s, status.Self.PublicKey, status.TailscaleIPs[0]
}

func pingNode(t *testing.T, control *testcontrol.Server, nodeKey key.NodePublic) {
	t.Helper()
	gotPing := make(chan bool, 1)
	waitPing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPing <- true
	}))
	defer waitPing.Close()

	for try := 0; try < 5; try++ {
		pr := &tailcfg.PingRequest{URL: fmt.Sprintf("%s/ping-%d", waitPing.URL, try), Log: true}
		if !control.AddPingRequest(nodeKey, pr) {
			t.Fatalf("failed to AddPingRequest")
		}
		pingTimeout := time.NewTimer(2 * time.Second)
		defer pingTimeout.Stop()
		select {
		case <-gotPing:
			// ok! the machinery that refreshes the netmap has been nudged
			return
		case <-pingTimeout.C:
			t.Logf("waiting for ping timed out: %d", try)
		}
	}
}

func tagNodes(t *testing.T, control *testcontrol.Server, nodeKeys []key.NodePublic, tag string) {
	t.Helper()
	for _, key := range nodeKeys {
		n := control.Node(key)
		n.Tags = append(n.Tags, tag)
		b := true
		n.Online = &b
		control.UpdateNode(n)
	}

	// all this ping stuff is only to prod the netmap to get updated with the tag we just added to the node
	// ie to actually get the netmap issued to clients that represents the current state of the nodes
	// there _must_ be a better way to do this, but I looked all day and this was the first thing I found that worked.
	for _, key := range nodeKeys {
		pingNode(t, control, key)
	}
}

// TODO test start with al lthe config settings
func TestStart(t *testing.T) {
	nettest.SkipIfNoNetwork(t)
	control, controlURL := startControl(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	one, k, _ := startNode(t, ctx, controlURL, "one")

	clusterTag := "tag:whatever"
	// nodes must be tagged with the cluster tag, to find each other
	tagNodes(t, control, []key.NodePublic{k}, clusterTag)

	sm := &fsm{}
	r, err := Start(ctx, one, (*fsm)(sm), clusterTag, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop(ctx)
}

func waitFor(t *testing.T, msg string, condition func() bool, nTries int, waitBetweenTries time.Duration) {
	for try := 0; try < nTries; try++ {
		done := condition()
		if done {
			t.Logf("waitFor success: %s: after %d tries", msg, try)
			return
		}
		time.Sleep(waitBetweenTries)
	}
	t.Fatalf("waitFor timed out: %s, after %d tries", msg, nTries)
}

type participant struct {
	c   *Consensus
	sm  *fsm
	ts  *tsnet.Server
	key key.NodePublic
}

// starts and tags the *tsnet.Server nodes with the control, waits for the nodes to make successful
// LocalClient Status calls that show the first node as Online.
func startNodesAndWaitForPeerStatus(t *testing.T, ctx context.Context, clusterTag string, nNodes int) ([]*participant, *testcontrol.Server, string) {
	ps := make([]*participant, nNodes)
	keysToTag := make([]key.NodePublic, nNodes)
	localClients := make([]*tailscale.LocalClient, nNodes)
	control, controlURL := startControl(t)
	for i := 0; i < nNodes; i++ {
		ts, key, _ := startNode(t, ctx, controlURL, fmt.Sprintf("node: %d", i))
		ps[i] = &participant{ts: ts, key: key}
		keysToTag[i] = key
		lc, err := ts.LocalClient()
		if err != nil {
			t.Fatalf("%d: error getting local client: %v", i, err)
		}
		localClients[i] = lc
	}
	tagNodes(t, control, keysToTag, clusterTag)
	fxCameOnline := func() bool {
		// all the _other_ nodes see the first as online
		for i := 1; i < nNodes; i++ {
			status, err := localClients[i].Status(ctx)
			if err != nil {
				t.Fatalf("%d: error getting status: %v", i, err)
			}
			if !status.Peer[ps[0].key].Online {
				return false
			}
		}
		return true
	}
	waitFor(t, "other nodes see node 1 online in ts status", fxCameOnline, 10, 2*time.Second)
	return ps, control, controlURL
}

// populates participants with their consensus fields, waits for all nodes to show all nodes
// as part of the same consensus cluster. Starts the first participant first and waits for it to
// become leader before adding other nodes.
func createConsensusCluster(t *testing.T, ctx context.Context, clusterTag string, participants []*participant, cfg Config) {
	participants[0].sm = &fsm{}
	first, err := Start(ctx, participants[0].ts, (*fsm)(participants[0].sm), clusterTag, cfg)
	if err != nil {
		t.Fatal(err)
	}
	fxFirstIsLeader := func() bool {
		return first.Raft.State() == raft.Leader
	}
	waitFor(t, "node 0 is leader", fxFirstIsLeader, 10, 2*time.Second)
	participants[0].c = first

	for i := 1; i < len(participants); i++ {
		participants[i].sm = &fsm{}
		c, err := Start(ctx, participants[i].ts, (*fsm)(participants[i].sm), clusterTag, cfg)
		if err != nil {
			t.Fatal(err)
		}
		participants[i].c = c
	}

	fxRaftConfigContainsAll := func() bool {
		for i := 0; i < len(participants); i++ {
			fut := participants[i].c.Raft.GetConfiguration()
			err = fut.Error()
			if err != nil {
				t.Fatalf("%d: Getting Configuration errored: %v", i, err)
			}
			if len(fut.Configuration().Servers) != len(participants) {
				return false
			}
		}
		return true
	}
	waitFor(t, "all raft machines have all servers in their config", fxRaftConfigContainsAll, 10, time.Second*2)
}

func TestApply(t *testing.T) {
	nettest.SkipIfNoNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	clusterTag := "tag:whatever"
	ps, _, _ := startNodesAndWaitForPeerStatus(t, ctx, clusterTag, 2)
	cfg := DefaultConfig()
	createConsensusCluster(t, ctx, clusterTag, ps, cfg)

	fut := ps[0].c.Raft.Apply([]byte("woo"), 2*time.Second)
	err := fut.Error()
	if err != nil {
		t.Fatalf("Raft Apply Error: %v", err)
	}

	fxBothMachinesHaveTheApply := func() bool {
		return len(ps[0].sm.events) == 1 && len(ps[1].sm.events) == 1
	}
	waitFor(t, "the apply event made it into both state machines", fxBothMachinesHaveTheApply, 10, time.Second*1)
}

// calls ExecuteCommand on each participant and checks that all participants get all commands
func assertCommandsWorkOnAnyNode(t *testing.T, participants []*participant) {
	for i, p := range participants {
		res, err := p.c.ExecuteCommand(Command{Args: []byte{byte(i)}})
		if err != nil {
			t.Fatalf("%d: Error ExecuteCommand: %v", i, err)
		}
		if res.Err != nil {
			t.Fatalf("%d: Result Error ExecuteCommand: %v", i, res.Err)
		}
		retVal := int(res.Result[0])
		// the test implementation of the fsm returns the count of events that have been received
		if retVal != i+1 {
			t.Fatalf("Result, want %d, got %d", i+1, retVal)
		}

		expectedEventsLength := i + 1
		fxEventsInAll := func() bool {
			for _, pOther := range participants {
				if len(pOther.sm.events) != expectedEventsLength {
					return false
				}
			}
			return true
		}
		waitFor(t, "event makes it to all", fxEventsInAll, 10, time.Second*1)
	}
}

func TestConfig(t *testing.T) {
	nettest.SkipIfNoNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	clusterTag := "tag:whatever"
	ps, _, _ := startNodesAndWaitForPeerStatus(t, ctx, clusterTag, 3)
	cfg := DefaultConfig()
	// test all is well with non default ports
	cfg.CommandPort = 12347
	cfg.RaftPort = 11882
	mp := uint16(8798)
	cfg.MonitorPort = mp
	createConsensusCluster(t, ctx, clusterTag, ps, cfg)
	assertCommandsWorkOnAnyNode(t, ps)

	url := fmt.Sprintf("http://%s:%d/", ps[0].c.Self.Host, mp)
	httpClientOnTailnet := ps[1].ts.HTTPClient()
	rsp, err := httpClientOnTailnet.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	if rsp.StatusCode != 200 {
		t.Fatalf("monitor status want %d, got %d", 200, rsp.StatusCode)
	}
	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	// Not a great assertion because it relies on the format of the response.
	line1 := strings.Split(string(body), "\n")[0]
	if line1[:10] != "RaftState:" {
		t.Fatalf("getting monitor status, first line, want something that starts with 'RaftState:', got '%s'", line1)
	}
}

func TestFollowerFailover(t *testing.T) {
	nettest.SkipIfNoNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	clusterTag := "tag:whatever"
	ps, _, _ := startNodesAndWaitForPeerStatus(t, ctx, clusterTag, 3)
	cfg := DefaultConfig()
	createConsensusCluster(t, ctx, clusterTag, ps, cfg)

	smThree := ps[2].sm

	fut := ps[0].c.Raft.Apply([]byte("a"), 2*time.Second)
	futTwo := ps[0].c.Raft.Apply([]byte("b"), 2*time.Second)
	err := fut.Error()
	if err != nil {
		t.Fatalf("Apply Raft error %v", err)
	}
	err = futTwo.Error()
	if err != nil {
		t.Fatalf("Apply Raft error %v", err)
	}

	fxAllMachinesHaveTheApplies := func() bool {
		return len(ps[0].sm.events) == 2 && len(ps[1].sm.events) == 2 && len(smThree.events) == 2
	}
	waitFor(t, "the apply events made it into all state machines", fxAllMachinesHaveTheApplies, 10, time.Second*1)

	//a follower goes loses contact with the cluster
	ps[2].c.Stop(ctx)

	// applies still make it to one and two
	futThree := ps[0].c.Raft.Apply([]byte("c"), 2*time.Second)
	futFour := ps[0].c.Raft.Apply([]byte("d"), 2*time.Second)
	err = futThree.Error()
	if err != nil {
		t.Fatalf("Apply Raft error %v", err)
	}
	err = futFour.Error()
	if err != nil {
		t.Fatalf("Apply Raft error %v", err)
	}
	fxAliveMachinesHaveTheApplies := func() bool {
		return len(ps[0].sm.events) == 4 && len(ps[1].sm.events) == 4 && len(smThree.events) == 2
	}
	waitFor(t, "the apply events made it into eligible state machines", fxAliveMachinesHaveTheApplies, 10, time.Second*1)

	// follower comes back
	smThreeAgain := &fsm{}
	rThreeAgain, err := Start(ctx, ps[2].ts, (*fsm)(smThreeAgain), clusterTag, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer rThreeAgain.Stop(ctx)
	fxThreeGetsCaughtUp := func() bool {
		return len(smThreeAgain.events) == 4
	}
	waitFor(t, "the apply events made it into the third node when it appeared with an empty state machine", fxThreeGetsCaughtUp, 20, time.Second*2)
	if len(smThree.events) != 2 {
		t.Fatalf("Expected smThree to remain on 2 events: got %d", len(smThree.events))
	}
}

func TestRejoin(t *testing.T) {
	nettest.SkipIfNoNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	clusterTag := "tag:whatever"
	ps, control, controlURL := startNodesAndWaitForPeerStatus(t, ctx, clusterTag, 3)
	cfg := DefaultConfig()
	createConsensusCluster(t, ctx, clusterTag, ps, cfg)
	for _, p := range ps {
		defer p.c.Stop(ctx)
	}

	// 1st node gets a redundant second join request from the second node
	ps[0].c.handleJoin(joinRequest{
		RemoteHost: ps[1].c.Self.Host,
		RemoteID:   ps[1].c.Self.ID,
	})

	tsJoiner, keyJoiner, _ := startNode(t, ctx, controlURL, "node: joiner")
	tagNodes(t, control, []key.NodePublic{keyJoiner}, clusterTag)
	smJoiner := &fsm{}
	cJoiner, err := Start(ctx, tsJoiner, (*fsm)(smJoiner), clusterTag, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ps = append(ps, &participant{
		sm:  smJoiner,
		c:   cJoiner,
		ts:  tsJoiner,
		key: keyJoiner,
	})

	assertCommandsWorkOnAnyNode(t, ps)
}
