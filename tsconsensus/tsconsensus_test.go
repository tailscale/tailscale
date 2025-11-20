// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsconsensus

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	"tailscale.com/client/tailscale"
	"tailscale.com/cmd/testwrapper/flakytest"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/tstest/nettest"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/util/cibuild"
	"tailscale.com/util/racebuild"
)

type fsm struct {
	mu          sync.Mutex
	applyEvents []string
}

func commandWith(t *testing.T, s string) []byte {
	jsonArgs, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	bs, err := json.Marshal(Command{
		Args: jsonArgs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return bs
}

func fromCommand(bs []byte) (string, error) {
	var cmd Command
	err := json.Unmarshal(bs, &cmd)
	if err != nil {
		return "", err
	}
	var args string
	err = json.Unmarshal(cmd.Args, &args)
	if err != nil {
		return "", err
	}
	return args, nil
}

func (f *fsm) Apply(lg *raft.Log) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, err := fromCommand(lg.Data)
	if err != nil {
		return CommandResult{
			Err: err,
		}
	}
	f.applyEvents = append(f.applyEvents, s)
	result, err := json.Marshal(len(f.applyEvents))
	if err != nil {
		panic("should be able to Marshal that?")
	}
	return CommandResult{
		Result: result,
	}
}

func (f *fsm) numEvents() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applyEvents)
}

func (f *fsm) eventsMatch(es []string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return cmp.Equal(es, f.applyEvents)
}

func (f *fsm) Snapshot() (raft.FSMSnapshot, error) {
	return nil, nil
}

func (f *fsm) Restore(rc io.ReadCloser) error {
	return nil
}

func testConfig(t *testing.T) {
	if runtime.GOOS == "windows" && cibuild.On() {
		t.Skip("cmd/natc isn't supported on Windows, so skipping tsconsensus tests on CI for now; see https://github.com/tailscale/tailscale/issues/16340")
	}
	// -race AND Parallel makes things start to take too long.
	if !racebuild.On {
		t.Parallel()
	}
	nettest.SkipIfNoNetwork(t)
}

func startControl(t testing.TB) (control *testcontrol.Server, controlURL string) {
	t.Helper()
	// tailscale/corp#4520: don't use netns for tests.
	netns.SetEnabled(false)
	t.Cleanup(func() {
		netns.SetEnabled(true)
	})

	derpLogf := logger.Discard
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

func startNode(t testing.TB, ctx context.Context, controlURL, hostname string) (*tsnet.Server, key.NodePublic, netip.Addr) {
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
	t.Cleanup(func() { s.Close() })

	status, err := s.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return s, status.Self.PublicKey, status.TailscaleIPs[0]
}

func waitForNodesToBeTaggedInStatus(t testing.TB, ctx context.Context, ts *tsnet.Server, nodeKeys []key.NodePublic, tag string) {
	t.Helper()
	waitFor(t, "nodes tagged in status", func() bool {
		lc, err := ts.LocalClient()
		if err != nil {
			t.Fatal(err)
		}
		status, err := lc.Status(ctx)
		if err != nil {
			t.Fatalf("error getting status: %v", err)
		}
		for _, k := range nodeKeys {
			var tags *views.Slice[string]
			if k == status.Self.PublicKey {
				tags = status.Self.Tags
			} else {
				tags = status.Peer[k].Tags
			}
			if tag == "" {
				if tags != nil && tags.Len() != 0 {
					return false
				}
			} else {
				if tags == nil {
					return false
				}
				if tags.Len() != 1 || tags.At(0) != tag {
					return false
				}
			}
		}
		return true
	}, 2*time.Second)
}

func tagNodes(t testing.TB, control *testcontrol.Server, nodeKeys []key.NodePublic, tag string) {
	t.Helper()
	for _, key := range nodeKeys {
		n := control.Node(key)
		if tag == "" {
			if len(n.Tags) != 1 {
				t.Fatalf("expected tags to have one tag")
			}
			n.Tags = nil
		} else {
			if len(n.Tags) != 0 {
				// if we want this to work with multiple tags we'll have to change the logic
				// for checking if a tag got removed yet.
				t.Fatalf("expected tags to be empty")
			}
			n.Tags = append(n.Tags, tag)
		}
		b := true
		n.Online = &b
		control.UpdateNode(n)
	}
}

func addIDedLogger(id string, c Config) Config {
	// logs that identify themselves
	c.Raft.Logger = hclog.New(&hclog.LoggerOptions{
		Name:   fmt.Sprintf("raft: %s", id),
		Output: c.Raft.LogOutput,
		Level:  hclog.LevelFromString(c.Raft.LogLevel),
	})
	return c
}

func warnLogConfig() Config {
	c := DefaultConfig()
	// fewer logs from raft
	c.Raft.LogLevel = "WARN"
	// timeouts long enough that we can form a cluster under -race
	c.Raft.LeaderLeaseTimeout = 2 * time.Second
	c.Raft.HeartbeatTimeout = 4 * time.Second
	c.Raft.ElectionTimeout = 4 * time.Second
	return c
}

func TestStart(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/15627")
	testConfig(t)
	control, controlURL := startControl(t)
	ctx := context.Background()
	one, k, _ := startNode(t, ctx, controlURL, "one")

	clusterTag := "tag:whatever"
	// nodes must be tagged with the cluster tag, to find each other
	tagNodes(t, control, []key.NodePublic{k}, clusterTag)
	waitForNodesToBeTaggedInStatus(t, ctx, one, []key.NodePublic{k}, clusterTag)

	sm := &fsm{}
	r, err := Start(ctx, one, sm, BootstrapOpts{Tag: clusterTag}, warnLogConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop(ctx)
}

func waitFor(t testing.TB, msg string, condition func() bool, waitBetweenTries time.Duration) {
	t.Helper()
	try := 0
	for true {
		try++
		done := condition()
		if done {
			t.Logf("waitFor success: %s: after %d tries", msg, try)
			return
		}
		time.Sleep(waitBetweenTries)
	}
}

type participant struct {
	c   *Consensus
	sm  *fsm
	ts  *tsnet.Server
	key key.NodePublic
}

// starts and tags the *tsnet.Server nodes with the control, waits for the nodes to make successful
// LocalClient Status calls that show the first node as Online.
func startNodesAndWaitForPeerStatus(t testing.TB, ctx context.Context, clusterTag string, nNodes int) ([]*participant, *testcontrol.Server, string) {
	t.Helper()
	ps := make([]*participant, nNodes)
	keysToTag := make([]key.NodePublic, nNodes)
	localClients := make([]*tailscale.LocalClient, nNodes)
	control, controlURL := startControl(t)
	for i := 0; i < nNodes; i++ {
		ts, key, _ := startNode(t, ctx, controlURL, fmt.Sprintf("node %d", i))
		ps[i] = &participant{ts: ts, key: key}
		keysToTag[i] = key
		lc, err := ts.LocalClient()
		if err != nil {
			t.Fatalf("%d: error getting local client: %v", i, err)
		}
		localClients[i] = lc
	}
	tagNodes(t, control, keysToTag, clusterTag)
	waitForNodesToBeTaggedInStatus(t, ctx, ps[0].ts, keysToTag, clusterTag)
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
	waitFor(t, "other nodes see node 1 online in ts status", fxCameOnline, 2*time.Second)
	return ps, control, controlURL
}

// populates participants with their consensus fields, waits for all nodes to show all nodes
// as part of the same consensus cluster. Starts the first participant first and waits for it to
// become leader before adding other nodes.
func createConsensusCluster(t testing.TB, ctx context.Context, clusterTag string, participants []*participant, cfg Config) {
	t.Helper()
	participants[0].sm = &fsm{}
	myCfg := addIDedLogger("0", cfg)
	first, err := Start(ctx, participants[0].ts, participants[0].sm, BootstrapOpts{Tag: clusterTag}, myCfg)
	if err != nil {
		t.Fatal(err)
	}
	fxFirstIsLeader := func() bool {
		return first.raft.State() == raft.Leader
	}
	waitFor(t, "node 0 is leader", fxFirstIsLeader, 2*time.Second)
	participants[0].c = first

	for i := 1; i < len(participants); i++ {
		participants[i].sm = &fsm{}
		myCfg := addIDedLogger(fmt.Sprintf("%d", i), cfg)
		c, err := Start(ctx, participants[i].ts, participants[i].sm, BootstrapOpts{Tag: clusterTag}, myCfg)
		if err != nil {
			t.Fatal(err)
		}
		participants[i].c = c
	}

	fxRaftConfigContainsAll := func() bool {
		for i := 0; i < len(participants); i++ {
			fut := participants[i].c.raft.GetConfiguration()
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
	waitFor(t, "all raft machines have all servers in their config", fxRaftConfigContainsAll, time.Second*2)
}

func TestApply(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/15627")
	testConfig(t)
	ctx := context.Background()
	clusterTag := "tag:whatever"
	ps, _, _ := startNodesAndWaitForPeerStatus(t, ctx, clusterTag, 2)
	cfg := warnLogConfig()
	createConsensusCluster(t, ctx, clusterTag, ps, cfg)
	for _, p := range ps {
		defer p.c.Stop(ctx)
	}

	fut := ps[0].c.raft.Apply(commandWith(t, "woo"), 2*time.Second)
	err := fut.Error()
	if err != nil {
		t.Fatalf("Raft Apply Error: %v", err)
	}

	want := []string{"woo"}
	fxBothMachinesHaveTheApply := func() bool {
		return ps[0].sm.eventsMatch(want) && ps[1].sm.eventsMatch(want)
	}
	waitFor(t, "the apply event made it into both state machines", fxBothMachinesHaveTheApply, time.Second*1)
}

// calls ExecuteCommand on each participant and checks that all participants get all commands
func assertCommandsWorkOnAnyNode(t testing.TB, participants []*participant) {
	t.Helper()
	want := []string{}
	for i, p := range participants {
		si := fmt.Sprintf("%d", i)
		want = append(want, si)
		bs, err := json.Marshal(si)
		if err != nil {
			t.Fatal(err)
		}
		res, err := p.c.ExecuteCommand(Command{Args: bs})
		if err != nil {
			t.Fatalf("%d: Error ExecuteCommand: %v", i, err)
		}
		if res.Err != nil {
			t.Fatalf("%d: Result Error ExecuteCommand: %v", i, res.Err)
		}
		var retVal int
		err = json.Unmarshal(res.Result, &retVal)
		if err != nil {
			t.Fatal(err)
		}
		// the test implementation of the fsm returns the count of events that have been received
		if retVal != i+1 {
			t.Fatalf("Result, want %d, got %d", i+1, retVal)
		}

		fxEventsInAll := func() bool {
			for _, pOther := range participants {
				if !pOther.sm.eventsMatch(want) {
					return false
				}
			}
			return true
		}
		waitFor(t, "event makes it to all", fxEventsInAll, time.Second*1)
	}
}

func TestConfig(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/15627")
	testConfig(t)
	ctx := context.Background()
	clusterTag := "tag:whatever"
	ps, _, _ := startNodesAndWaitForPeerStatus(t, ctx, clusterTag, 3)
	cfg := warnLogConfig()
	// test all is well with non default ports
	cfg.CommandPort = 12347
	cfg.RaftPort = 11882
	mp := uint16(8798)
	cfg.MonitorPort = mp
	cfg.ServeDebugMonitor = true
	createConsensusCluster(t, ctx, clusterTag, ps, cfg)
	for _, p := range ps {
		defer p.c.Stop(ctx)
	}
	assertCommandsWorkOnAnyNode(t, ps)

	url := fmt.Sprintf("http://%s:%d/", ps[0].c.self.hostAddr.String(), mp)
	httpClientOnTailnet := ps[1].ts.HTTPClient()
	rsp, err := httpClientOnTailnet.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	if rsp.StatusCode != 200 {
		t.Fatalf("monitor status want %d, got %d", 200, rsp.StatusCode)
	}
	defer rsp.Body.Close()
	reader := bufio.NewReader(rsp.Body)
	line1, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	// Not a great assertion because it relies on the format of the response.
	if !strings.HasPrefix(line1, "RaftState:") {
		t.Fatalf("getting monitor status, first line, want something that starts with 'RaftState:', got '%s'", line1)
	}
}

func TestFollowerFailover(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/15627")
	testConfig(t)
	ctx := context.Background()
	clusterTag := "tag:whatever"
	ps, _, _ := startNodesAndWaitForPeerStatus(t, ctx, clusterTag, 3)
	cfg := warnLogConfig()
	createConsensusCluster(t, ctx, clusterTag, ps, cfg)
	for _, p := range ps {
		defer p.c.Stop(ctx)
	}

	smThree := ps[2].sm

	fut := ps[0].c.raft.Apply(commandWith(t, "a"), 2*time.Second)
	futTwo := ps[0].c.raft.Apply(commandWith(t, "b"), 2*time.Second)
	err := fut.Error()
	if err != nil {
		t.Fatalf("Apply Raft error %v", err)
	}
	err = futTwo.Error()
	if err != nil {
		t.Fatalf("Apply Raft error %v", err)
	}

	wantFirstTwoEvents := []string{"a", "b"}
	fxAllMachinesHaveTheApplies := func() bool {
		return ps[0].sm.eventsMatch(wantFirstTwoEvents) &&
			ps[1].sm.eventsMatch(wantFirstTwoEvents) &&
			smThree.eventsMatch(wantFirstTwoEvents)
	}
	waitFor(t, "the apply events made it into all state machines", fxAllMachinesHaveTheApplies, time.Second*1)

	//a follower goes loses contact with the cluster
	ps[2].c.Stop(ctx)

	// applies still make it to one and two
	futThree := ps[0].c.raft.Apply(commandWith(t, "c"), 2*time.Second)
	futFour := ps[0].c.raft.Apply(commandWith(t, "d"), 2*time.Second)
	err = futThree.Error()
	if err != nil {
		t.Fatalf("Apply Raft error %v", err)
	}
	err = futFour.Error()
	if err != nil {
		t.Fatalf("Apply Raft error %v", err)
	}
	wantFourEvents := []string{"a", "b", "c", "d"}
	fxAliveMachinesHaveTheApplies := func() bool {
		return ps[0].sm.eventsMatch(wantFourEvents) &&
			ps[1].sm.eventsMatch(wantFourEvents) &&
			smThree.eventsMatch(wantFirstTwoEvents)
	}
	waitFor(t, "the apply events made it into eligible state machines", fxAliveMachinesHaveTheApplies, time.Second*1)

	// follower comes back
	smThreeAgain := &fsm{}
	cfg = addIDedLogger("2 after restarting", warnLogConfig())
	rThreeAgain, err := Start(ctx, ps[2].ts, smThreeAgain, BootstrapOpts{Tag: clusterTag}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer rThreeAgain.Stop(ctx)
	fxThreeGetsCaughtUp := func() bool {
		return smThreeAgain.eventsMatch(wantFourEvents)
	}
	waitFor(t, "the apply events made it into the third node when it appeared with an empty state machine", fxThreeGetsCaughtUp, time.Second*2)
	if !smThree.eventsMatch(wantFirstTwoEvents) {
		t.Fatalf("Expected smThree to remain on 2 events: got %d", smThree.numEvents())
	}
}

func TestRejoin(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/15627")
	testConfig(t)
	ctx := context.Background()
	clusterTag := "tag:whatever"
	ps, control, controlURL := startNodesAndWaitForPeerStatus(t, ctx, clusterTag, 3)
	cfg := warnLogConfig()
	createConsensusCluster(t, ctx, clusterTag, ps, cfg)
	for _, p := range ps {
		defer p.c.Stop(ctx)
	}

	// 1st node gets a redundant second join request from the second node
	ps[0].c.handleJoin(joinRequest{
		RemoteHost: ps[1].c.self.hostAddr.String(),
		RemoteID:   ps[1].c.self.id,
	})

	tsJoiner, keyJoiner, _ := startNode(t, ctx, controlURL, "node joiner")
	tagNodes(t, control, []key.NodePublic{keyJoiner}, clusterTag)
	waitForNodesToBeTaggedInStatus(t, ctx, ps[0].ts, []key.NodePublic{keyJoiner}, clusterTag)
	smJoiner := &fsm{}
	cJoiner, err := Start(ctx, tsJoiner, smJoiner, BootstrapOpts{Tag: clusterTag}, cfg)
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

func TestOnlyTaggedPeersCanDialRaftPort(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/15627")
	testConfig(t)
	ctx := context.Background()
	clusterTag := "tag:whatever"
	ps, control, controlURL := startNodesAndWaitForPeerStatus(t, ctx, clusterTag, 3)
	cfg := warnLogConfig()
	createConsensusCluster(t, ctx, clusterTag, ps, cfg)
	for _, p := range ps {
		defer p.c.Stop(ctx)
	}
	assertCommandsWorkOnAnyNode(t, ps)

	untaggedNode, _, _ := startNode(t, ctx, controlURL, "untagged node")

	taggedNode, taggedKey, _ := startNode(t, ctx, controlURL, "untagged node")
	tagNodes(t, control, []key.NodePublic{taggedKey}, clusterTag)
	waitForNodesToBeTaggedInStatus(t, ctx, ps[0].ts, []key.NodePublic{taggedKey}, clusterTag)

	// surface area: command http, peer tcp
	//untagged
	ipv4, _ := ps[0].ts.TailscaleIPs()
	sAddr := fmt.Sprintf("%s:%d", ipv4, cfg.RaftPort)

	getErrorFromTryingToSend := func(s *tsnet.Server) error {
		ctx := context.Background()
		conn, err := s.Dial(ctx, "tcp", sAddr)
		if err != nil {
			t.Fatalf("unexpected Dial err: %v", err)
		}
		fmt.Fprintf(conn, "hellllllloooooo")
		status, err := bufio.NewReader(conn).ReadString('\n')
		if status != "" {
			t.Fatalf("node sending non-raft message should get empty response, got: '%s' for: %s", status, s.Hostname)
		}
		if err == nil {
			t.Fatalf("node sending non-raft message should get an error but got nil err for: %s", s.Hostname)
		}
		return err
	}

	isNetErr := func(err error) bool {
		var netErr net.Error
		return errors.As(err, &netErr)
	}

	err := getErrorFromTryingToSend(untaggedNode)
	if !isNetErr(err) {
		t.Fatalf("untagged node trying to send should get a net.Error, got: %v", err)
	}
	// we still get an error trying to send but it's EOF the target node was happy to talk
	// to us but couldn't understand what we said.
	err = getErrorFromTryingToSend(taggedNode)
	if isNetErr(err) {
		t.Fatalf("tagged node trying to send should not get a net.Error, got: %v", err)
	}
}

func TestOnlyTaggedPeersCanBeDialed(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/15627")
	testConfig(t)
	ctx := context.Background()
	clusterTag := "tag:whatever"
	ps, control, _ := startNodesAndWaitForPeerStatus(t, ctx, clusterTag, 3)

	// make a StreamLayer for ps[0]
	ts := ps[0].ts
	auth := newAuthorization(ts, clusterTag)

	port := 19841
	lns := make([]net.Listener, 3)
	for i, p := range ps {
		ln, err := p.ts.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			t.Fatal(err)
		}
		lns[i] = ln
	}

	sl := StreamLayer{
		s:           ts,
		Listener:    lns[0],
		auth:        auth,
		shutdownCtx: ctx,
	}

	ip1, _ := ps[1].ts.TailscaleIPs()
	a1 := raft.ServerAddress(fmt.Sprintf("%s:%d", ip1, port))

	ip2, _ := ps[2].ts.TailscaleIPs()
	a2 := raft.ServerAddress(fmt.Sprintf("%s:%d", ip2, port))

	// both can be dialed...
	conn, err := sl.Dial(a1, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	conn, err = sl.Dial(a2, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	// untag ps[2]
	tagNodes(t, control, []key.NodePublic{ps[2].key}, "")
	waitForNodesToBeTaggedInStatus(t, ctx, ps[0].ts, []key.NodePublic{ps[2].key}, "")

	// now only ps[1] can be dialed
	conn, err = sl.Dial(a1, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	_, err = sl.Dial(a2, 2*time.Second)
	if err.Error() != "dial: peer is not allowed" {
		t.Fatalf("expected dial: peer is not allowed, got: %v", err)
	}

}

func TestOnlyTaggedPeersCanJoin(t *testing.T) {
	testConfig(t)
	ctx := context.Background()
	clusterTag := "tag:whatever"
	ps, _, controlURL := startNodesAndWaitForPeerStatus(t, ctx, clusterTag, 3)
	cfg := warnLogConfig()
	createConsensusCluster(t, ctx, clusterTag, ps, cfg)
	for _, p := range ps {
		defer p.c.Stop(ctx)
	}

	tsJoiner, _, _ := startNode(t, ctx, controlURL, "joiner node")

	ipv4, _ := tsJoiner.TailscaleIPs()
	url := fmt.Sprintf("http://%s/join", ps[0].c.commandAddr(ps[0].c.self.hostAddr))
	payload, err := json.Marshal(joinRequest{
		RemoteHost: ipv4.String(),
		RemoteID:   "node joiner",
	})
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.NewBuffer(payload)
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tsJoiner.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("join req when not tagged, expected status: %d, got: %d", http.StatusForbidden, resp.StatusCode)
	}
	rBody, _ := io.ReadAll(resp.Body)
	sBody := strings.TrimSpace(string(rBody))
	expected := "peer not allowed"
	if sBody != expected {
		t.Fatalf("join req when not tagged, expected body: %s, got: %s", expected, sBody)
	}
}

func TestFollowOnly(t *testing.T) {
	testConfig(t)
	ctx := context.Background()
	clusterTag := "tag:whatever"
	ps, _, _ := startNodesAndWaitForPeerStatus(t, ctx, clusterTag, 3)
	cfg := warnLogConfig()

	// start the leader
	_, err := Start(ctx, ps[0].ts, ps[0].sm, BootstrapOpts{Tag: clusterTag}, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// start the follower with FollowOnly
	_, err = Start(ctx, ps[1].ts, ps[1].sm, BootstrapOpts{Tag: clusterTag, FollowOnly: true}, cfg)
	if err != nil {
		t.Fatal(err)
	}
}
