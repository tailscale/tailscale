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
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	"golang.org/x/exp/rand"
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
	"tailscale.com/types/views"
)

type fsm struct {
	events []map[string]any
	count  int
	mu     sync.Mutex
}

func (f *fsm) Apply(l *raft.Log) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.count++
	f.events = append(f.events, map[string]any{
		"type": "Apply",
		"l":    l,
	})
	return CommandResult{
		Result: []byte{byte(f.count)},
	}
}

func (f *fsm) numEvents() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

func (f *fsm) Snapshot() (raft.FSMSnapshot, error) {
	return nil, nil
}

func (f *fsm) Restore(rc io.ReadCloser) error {
	return nil
}

var verboseDERP = false
var verboseNodes = false

var testContextTimeout = 60 * time.Second

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

func waitForNodesToBeTaggedInStatus(t *testing.T, ctx context.Context, ts *tsnet.Server, nodeKeys []key.NodePublic, tag string) {
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
				sliceTags := tags.AsSlice()
				if len(sliceTags) != 1 || sliceTags[0] != tag {
					return false
				}
			}
		}
		return true
	}, 20, 2*time.Second)
}

func tagNodes(t *testing.T, control *testcontrol.Server, nodeKeys []key.NodePublic, tag string) {
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
	// TODO but if I set them to even longer then we have trouble with auth refresh: Get "http://local-tailscaled.sock/localapi/v0/status": context deadline exceeded
	c.Raft.LeaderLeaseTimeout = 2 * time.Second
	c.Raft.HeartbeatTimeout = 4 * time.Second
	c.Raft.ElectionTimeout = 4 * time.Second
	return c
}

func TestStart(t *testing.T) {
	nettest.SkipIfNoNetwork(t)
	control, controlURL := startControl(t)
	ctx, cancel := context.WithTimeout(context.Background(), testContextTimeout)
	defer cancel()
	one, k, _ := startNode(t, ctx, controlURL, "one")

	clusterTag := "tag:whatever"
	// nodes must be tagged with the cluster tag, to find each other
	tagNodes(t, control, []key.NodePublic{k}, clusterTag)
	waitForNodesToBeTaggedInStatus(t, ctx, one, []key.NodePublic{k}, clusterTag)

	sm := &fsm{}
	r, err := Start(ctx, one, (*fsm)(sm), clusterTag, warnLogConfig())
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
	waitFor(t, "other nodes see node 1 online in ts status", fxCameOnline, 10, 2*time.Second)
	return ps, control, controlURL
}

// populates participants with their consensus fields, waits for all nodes to show all nodes
// as part of the same consensus cluster. Starts the first participant first and waits for it to
// become leader before adding other nodes.
func createConsensusCluster(t *testing.T, ctx context.Context, clusterTag string, participants []*participant, cfg Config) {
	participants[0].sm = &fsm{}
	rand.Seed(uint64(time.Now().UnixNano()))
	randomNumber := rand.Intn(8999) + 1000
	myCfg := addIDedLogger(fmt.Sprintf("0(%d)", randomNumber), cfg)
	first, err := Start(ctx, participants[0].ts, (*fsm)(participants[0].sm), clusterTag, myCfg)
	if err != nil {
		t.Fatal(err)
	}
	fxFirstIsLeader := func() bool {
		return first.raft.State() == raft.Leader
	}
	waitFor(t, "node 0 is leader", fxFirstIsLeader, 20, 2*time.Second)
	participants[0].c = first

	for i := 1; i < len(participants); i++ {
		participants[i].sm = &fsm{}
		randomNumber := rand.Intn(8999) + 1000
		myCfg := addIDedLogger(fmt.Sprintf("%d(%d)", i, randomNumber), cfg)
		c, err := Start(ctx, participants[i].ts, (*fsm)(participants[i].sm), clusterTag, myCfg)
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
	waitFor(t, "all raft machines have all servers in their config", fxRaftConfigContainsAll, 15, time.Second*2)
}

func TestApply(t *testing.T) {
	nettest.SkipIfNoNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), testContextTimeout)
	defer cancel()
	clusterTag := "tag:whatever"
	ps, _, _ := startNodesAndWaitForPeerStatus(t, ctx, clusterTag, 2)
	cfg := warnLogConfig()
	createConsensusCluster(t, ctx, clusterTag, ps, cfg)
	for _, p := range ps {
		defer p.c.Stop(ctx)
	}

	fut := ps[0].c.raft.Apply([]byte("woo"), 2*time.Second)
	err := fut.Error()
	if err != nil {
		t.Fatalf("Raft Apply Error: %v", err)
	}

	fxBothMachinesHaveTheApply := func() bool {
		return ps[0].sm.numEvents() == 1 && ps[1].sm.numEvents() == 1
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
				if pOther.sm.numEvents() != expectedEventsLength {
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
	ctx, cancel := context.WithTimeout(context.Background(), testContextTimeout)
	defer cancel()
	clusterTag := "tag:whatever"
	ps, _, _ := startNodesAndWaitForPeerStatus(t, ctx, clusterTag, 3)
	cfg := warnLogConfig()
	// test all is well with non default ports
	cfg.CommandPort = 12347
	cfg.RaftPort = 11882
	mp := uint16(8798)
	cfg.MonitorPort = mp
	createConsensusCluster(t, ctx, clusterTag, ps, cfg)
	for _, p := range ps {
		defer p.c.Stop(ctx)
	}
	assertCommandsWorkOnAnyNode(t, ps)

	url := fmt.Sprintf("http://%s:%d/", ps[0].c.self.host, mp)
	httpClientOnTailnet := ps[1].ts.HTTPClient()
	rsp, err := httpClientOnTailnet.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	if rsp.StatusCode != 200 {
		t.Fatalf("monitor status want %d, got %d", 200, rsp.StatusCode)
	}
	defer rsp.Body.Close()
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
	ctx, cancel := context.WithTimeout(context.Background(), testContextTimeout)
	defer cancel()
	clusterTag := "tag:whatever"
	ps, _, _ := startNodesAndWaitForPeerStatus(t, ctx, clusterTag, 3)
	cfg := warnLogConfig()
	createConsensusCluster(t, ctx, clusterTag, ps, cfg)
	for _, p := range ps {
		defer p.c.Stop(ctx)
	}

	smThree := ps[2].sm

	fut := ps[0].c.raft.Apply([]byte("a"), 2*time.Second)
	futTwo := ps[0].c.raft.Apply([]byte("b"), 2*time.Second)
	err := fut.Error()
	if err != nil {
		t.Fatalf("Apply Raft error %v", err)
	}
	err = futTwo.Error()
	if err != nil {
		t.Fatalf("Apply Raft error %v", err)
	}

	fxAllMachinesHaveTheApplies := func() bool {
		return ps[0].sm.numEvents() == 2 && ps[1].sm.numEvents() == 2 && smThree.numEvents() == 2
	}
	waitFor(t, "the apply events made it into all state machines", fxAllMachinesHaveTheApplies, 10, time.Second*1)

	//a follower goes loses contact with the cluster
	ps[2].c.Stop(ctx)

	// applies still make it to one and two
	futThree := ps[0].c.raft.Apply([]byte("c"), 2*time.Second)
	futFour := ps[0].c.raft.Apply([]byte("d"), 2*time.Second)
	err = futThree.Error()
	if err != nil {
		t.Fatalf("Apply Raft error %v", err)
	}
	err = futFour.Error()
	if err != nil {
		t.Fatalf("Apply Raft error %v", err)
	}
	fxAliveMachinesHaveTheApplies := func() bool {
		return ps[0].sm.numEvents() == 4 && ps[1].sm.numEvents() == 4 && smThree.numEvents() == 2
	}
	waitFor(t, "the apply events made it into eligible state machines", fxAliveMachinesHaveTheApplies, 10, time.Second*1)

	// follower comes back
	smThreeAgain := &fsm{}
	cfg = addIDedLogger("2 after restarting", warnLogConfig())
	rThreeAgain, err := Start(ctx, ps[2].ts, (*fsm)(smThreeAgain), clusterTag, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer rThreeAgain.Stop(ctx)
	fxThreeGetsCaughtUp := func() bool {
		return smThreeAgain.numEvents() == 4
	}
	waitFor(t, "the apply events made it into the third node when it appeared with an empty state machine", fxThreeGetsCaughtUp, 20, time.Second*2)
	if smThree.numEvents() != 2 {
		t.Fatalf("Expected smThree to remain on 2 events: got %d", smThree.numEvents())
	}
}

func TestRejoin(t *testing.T) {
	nettest.SkipIfNoNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), testContextTimeout)
	defer cancel()
	clusterTag := "tag:whatever"
	ps, control, controlURL := startNodesAndWaitForPeerStatus(t, ctx, clusterTag, 3)
	cfg := warnLogConfig()
	createConsensusCluster(t, ctx, clusterTag, ps, cfg)
	for _, p := range ps {
		defer p.c.Stop(ctx)
	}

	// 1st node gets a redundant second join request from the second node
	ps[0].c.handleJoin(joinRequest{
		RemoteHost: ps[1].c.self.host,
		RemoteID:   ps[1].c.self.id,
	})

	tsJoiner, keyJoiner, _ := startNode(t, ctx, controlURL, "node: joiner")
	tagNodes(t, control, []key.NodePublic{keyJoiner}, clusterTag)
	waitForNodesToBeTaggedInStatus(t, ctx, ps[0].ts, []key.NodePublic{keyJoiner}, clusterTag)
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

func TestOnlyTaggedPeersCanDialRaftPort(t *testing.T) {
	nettest.SkipIfNoNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), testContextTimeout)
	defer cancel()
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

	isNetTimeoutErr := func(err error) bool {
		var netErr net.Error
		if !errors.As(err, &netErr) {
			return false
		}
		return netErr.Timeout()
	}

	getErrorFromTryingToSend := func(s *tsnet.Server) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := s.Dial(ctx, "tcp", sAddr)
		if err != nil {
			t.Fatalf("unexpected Dial err: %v", err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
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

	err := getErrorFromTryingToSend(untaggedNode)
	if !isNetTimeoutErr(err) {
		t.Fatalf("untagged node trying to send should time out, got: %v", err)
	}
	// we still get an error trying to send but it's EOF the target node was happy to talk
	// to us but couldn't understand what we said.
	err = getErrorFromTryingToSend(taggedNode)
	if isNetTimeoutErr(err) {
		t.Fatalf("tagged node trying to send should not time out, got: %v", err)
	}
}

func TestOnlyTaggedPeersCanBeDialed(t *testing.T) {
	nettest.SkipIfNoNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), testContextTimeout)
	defer cancel()
	clusterTag := "tag:whatever"
	ps, control, _ := startNodesAndWaitForPeerStatus(t, ctx, clusterTag, 3)

	// make a StreamLayer for ps[0]
	ts := ps[0].ts
	auth := &authorization{
		tag: clusterTag,
		ts:  ts,
	}

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
		s:        ts,
		Listener: lns[0],
		auth:     auth,
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
	if err.Error() != "peer is not allowed" {
		t.Fatalf("expected peer is not allowed, got: %v", err)
	}

}

func TestOnlyTaggedPeersCanJoin(t *testing.T) {
	nettest.SkipIfNoNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), testContextTimeout)
	defer cancel()
	clusterTag := "tag:whatever"
	ps, _, controlURL := startNodesAndWaitForPeerStatus(t, ctx, clusterTag, 3)
	cfg := warnLogConfig()
	createConsensusCluster(t, ctx, clusterTag, ps, cfg)
	for _, p := range ps {
		defer p.c.Stop(ctx)
	}

	tsJoiner, _, _ := startNode(t, ctx, controlURL, "joiner node")

	ipv4, _ := tsJoiner.TailscaleIPs()
	url := fmt.Sprintf("http://%s/join", ps[0].c.commandAddr(ps[0].c.self.host))
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
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("join req when not tagged, expected status: %d, got: %d", http.StatusBadRequest, resp.StatusCode)
	}
	rBody, _ := io.ReadAll(resp.Body)
	sBody := strings.TrimSpace(string(rBody))
	expected := "peer not allowed"
	if sBody != expected {
		t.Fatalf("join req when not tagged, expected body: %s, got: %s", expected, sBody)
	}
}
