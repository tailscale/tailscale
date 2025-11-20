// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package testcontrol contains a minimal control plane server for testing purposes.
package testcontrol

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/tsaddr"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
	"tailscale.com/util/httpm"
	"tailscale.com/util/mak"
	"tailscale.com/util/must"
	"tailscale.com/util/rands"
	"tailscale.com/util/set"
	"tailscale.com/util/zstdframe"
)

const msgLimit = 1 << 20 // encrypted message length limit

// Server is a control plane server. Its zero value is ready for use.
// Everything is stored in-memory in one tailnet.
type Server struct {
	Logf               logger.Logf      // nil means to use the log package
	DERPMap            *tailcfg.DERPMap // nil means to use prod DERP map
	RequireAuth        bool
	RequireAuthKey     string // required authkey for all nodes
	RequireMachineAuth bool
	Verbose            bool
	DNSConfig          *tailcfg.DNSConfig // nil means no DNS config
	MagicDNSDomain     string
	C2NResponses       syncs.Map[string, func(*http.Response)] // token => onResponse func

	// PeerRelayGrants, if true, inserts relay capabilities into the wildcard
	// grants rules.
	PeerRelayGrants bool

	// AllNodesSameUser, if true, makes all created nodes
	// belong to the same user.
	AllNodesSameUser bool

	// DefaultNodeCapabilities overrides the capability map sent to each client.
	DefaultNodeCapabilities *tailcfg.NodeCapMap

	// CollectServices, if non-empty, sets whether the control server asks
	// for service updates. If empty, the default is "true".
	CollectServices opt.Bool

	// ExplicitBaseURL or HTTPTestServer must be set.
	ExplicitBaseURL string           // e.g. "http://127.0.0.1:1234" with no trailing URL
	HTTPTestServer  *httptest.Server // if non-nil, used to get BaseURL

	initMuxOnce sync.Once
	mux         *http.ServeMux

	mu         sync.Mutex
	inServeMap int
	cond       *sync.Cond // lazily initialized by condLocked
	pubKey     key.MachinePublic
	privKey    key.ControlPrivate // not strictly needed vs. MachinePrivate, but handy to test type interactions.

	// nodeSubnetRoutes is a list of subnet routes that are served
	// by the specified node.
	nodeSubnetRoutes map[key.NodePublic][]netip.Prefix

	// peerIsJailed is the set of peers that are jailed for a node.
	peerIsJailed map[key.NodePublic]map[key.NodePublic]bool // node => peer => isJailed

	// masquerades is the set of masquerades that should be applied to
	// MapResponses sent to clients. It is keyed by the requesting nodes
	// public key, and then the peer node's public key. The value is the
	// masquerade address to use for that peer.
	masquerades map[key.NodePublic]map[key.NodePublic]netip.Addr // node => peer => SelfNodeV{4,6}MasqAddrForThisPeer IP

	// nodeCapMaps overrides the capability map sent down to a client.
	nodeCapMaps map[key.NodePublic]tailcfg.NodeCapMap

	// suppressAutoMapResponses is the set of nodes that should not be sent
	// automatic map responses from serveMap. (They should only get manually sent ones)
	suppressAutoMapResponses set.Set[key.NodePublic]

	noisePubKey  key.MachinePublic
	noisePrivKey key.MachinePrivate

	nodes         map[key.NodePublic]*tailcfg.Node
	users         map[key.NodePublic]*tailcfg.User
	logins        map[key.NodePublic]*tailcfg.Login
	updates       map[tailcfg.NodeID]chan updateType
	authPath      map[string]*AuthPath
	nodeKeyAuthed set.Set[key.NodePublic]
	msgToSend     map[key.NodePublic]any // value is *tailcfg.PingRequest or entire *tailcfg.MapResponse
	allExpired    bool                   // All nodes will be told their node key is expired.
}

// BaseURL returns the server's base URL, without trailing slash.
func (s *Server) BaseURL() string {
	if e := s.ExplicitBaseURL; e != "" {
		return e
	}
	if hs := s.HTTPTestServer; hs != nil {
		if hs.URL != "" {
			return hs.URL
		}
		panic("Server.HTTPTestServer not started")
	}
	panic("Server ExplicitBaseURL and HTTPTestServer both unset")
}

// NumNodes returns the number of nodes in the testcontrol server.
//
// This is useful when connecting a bunch of virtual machines to a testcontrol
// server to see how many of them connected successfully.
func (s *Server) NumNodes() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.nodes)
}

// condLocked lazily initializes and returns s.cond.
// s.mu must be held.
func (s *Server) condLocked() *sync.Cond {
	if s.cond == nil {
		s.cond = sync.NewCond(&s.mu)
	}
	return s.cond
}

// AwaitNodeInMapRequest waits for node k to be stuck in a map poll.
// It returns an error if and only if the context is done first.
func (s *Server) AwaitNodeInMapRequest(ctx context.Context, k key.NodePublic) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cond := s.condLocked()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
		case <-ctx.Done():
			cond.Broadcast()
		}
	}()

	for {
		node := s.nodeLocked(k)
		if node == nil {
			return errors.New("unknown node key")
		}
		if _, ok := s.updates[node.ID]; ok {
			return nil
		}
		cond.Wait()
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

// AddPingRequest sends the ping pr to nodeKeyDst.
//
// It reports whether the message was enqueued. That is, it reports whether
// nodeKeyDst was connected.
func (s *Server) AddPingRequest(nodeKeyDst key.NodePublic, pr *tailcfg.PingRequest) bool {
	return s.addDebugMessage(nodeKeyDst, pr)
}

// c2nRoundTripper is an http.RoundTripper that sends requests to a node via C2N.
type c2nRoundTripper struct {
	s *Server
	n key.NodePublic
}

func (s *Server) NodeRoundTripper(n key.NodePublic) http.RoundTripper {
	return c2nRoundTripper{s, n}
}

func (rt c2nRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	resc := make(chan *http.Response, 1)
	if err := rt.s.SendC2N(rt.n, req, func(r *http.Response) { resc <- r }); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-resc:
		return r, nil
	}
}

// SendC2N sends req to node. When the response is received, onRes is called.
func (s *Server) SendC2N(node key.NodePublic, req *http.Request, onRes func(*http.Response)) error {
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		return err
	}

	token := rands.HexString(10)
	pr := &tailcfg.PingRequest{
		URL:     "https://unused/c2n/" + token,
		Log:     true,
		Types:   "c2n",
		Payload: buf.Bytes(),
	}
	s.C2NResponses.Store(token, onRes)
	if !s.AddPingRequest(node, pr) {
		s.C2NResponses.Delete(token)
		return fmt.Errorf("node %v not connected", node)
	}
	return nil
}

// AddRawMapResponse delivers the raw MapResponse mr to nodeKeyDst. It's meant
// for testing incremental map updates.
//
// Once AddRawMapResponse has been sent to a node, all future automatic
// MapResponses to that node will be suppressed and only explicit MapResponses
// injected via AddRawMapResponse will be sent.
//
// It reports whether the message was enqueued. That is, it reports whether
// nodeKeyDst was connected.
func (s *Server) AddRawMapResponse(nodeKeyDst key.NodePublic, mr *tailcfg.MapResponse) bool {
	return s.addDebugMessage(nodeKeyDst, mr)
}

func (s *Server) addDebugMessage(nodeKeyDst key.NodePublic, msg any) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.msgToSend == nil {
		s.msgToSend = map[key.NodePublic]any{}
	}
	// Now send the update to the channel
	node := s.nodeLocked(nodeKeyDst)
	if node == nil {
		return false
	}

	if _, ok := msg.(*tailcfg.MapResponse); ok {
		if s.suppressAutoMapResponses == nil {
			s.suppressAutoMapResponses = set.Set[key.NodePublic]{}
		}
		s.suppressAutoMapResponses.Add(nodeKeyDst)
	}

	s.msgToSend[nodeKeyDst] = msg
	nodeID := node.ID
	oldUpdatesCh := s.updates[nodeID]
	return sendUpdate(oldUpdatesCh, updateDebugInjection)
}

// Mark the Node key of every node as expired
func (s *Server) SetExpireAllNodes(expired bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.allExpired = expired

	for _, node := range s.nodes {
		sendUpdate(s.updates[node.ID], updateSelfChanged)
	}
}

type AuthPath struct {
	nodeKey key.NodePublic

	closeOnce sync.Once
	ch        chan struct{}
	success   bool
}

func (ap *AuthPath) completeSuccessfully() {
	ap.success = true
	close(ap.ch)
}

// CompleteSuccessfully completes the login path successfully, as if
// the user did the whole auth dance.
func (ap *AuthPath) CompleteSuccessfully() {
	ap.closeOnce.Do(ap.completeSuccessfully)
}

func (s *Server) logf(format string, a ...any) {
	if s.Logf != nil {
		s.Logf(format, a...)
	} else {
		log.Printf(format, a...)
	}
}

func (s *Server) initMux() {
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("/", s.serveUnhandled)
	s.mux.HandleFunc("/generate_204", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	s.mux.HandleFunc("/key", s.serveKey)
	s.mux.HandleFunc("/machine/", s.serveMachine)
	s.mux.HandleFunc("/ts2021", s.serveNoiseUpgrade)
	s.mux.HandleFunc("/c2n/", s.serveC2N)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.initMuxOnce.Do(s.initMux)
	s.mux.ServeHTTP(w, r)
}

func (s *Server) serveUnhandled(w http.ResponseWriter, r *http.Request) {
	var got bytes.Buffer
	r.Write(&got)
	go panic(fmt.Sprintf("testcontrol.Server received unhandled request: %s", got.Bytes()))
}

// serveC2N handles a POST from a node containing a c2n response.
func (s *Server) serveC2N(w http.ResponseWriter, r *http.Request) {
	if err := func() error {
		if r.Method != httpm.POST {
			return errors.New("POST required")
		}
		token, ok := strings.CutPrefix(r.URL.Path, "/c2n/")
		if !ok {
			return fmt.Errorf("invalid path %q", r.URL.Path)
		}

		onRes, ok := s.C2NResponses.Load(token)
		if !ok {
			return fmt.Errorf("unknown c2n token %q", token)
		}
		s.C2NResponses.Delete(token)

		res, err := http.ReadResponse(bufio.NewReader(r.Body), nil)
		if err != nil {
			return fmt.Errorf("error reading c2n response: %w", err)
		}
		onRes(res)
		return nil
	}(); err != nil {
		s.logf("testcontrol: %s", err)
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type peerMachinePublicContextKey struct{}

func (s *Server) serveNoiseUpgrade(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != "POST" {
		http.Error(w, "POST required", 400)
		return
	}

	s.mu.Lock()
	noisePrivate := s.noisePrivKey
	s.mu.Unlock()
	cc, err := controlhttpserver.AcceptHTTP(ctx, w, r, noisePrivate, nil)
	if err != nil {
		log.Printf("AcceptHTTP: %v", err)
		return
	}
	defer cc.Close()

	var h2srv http2.Server
	peerPub := cc.Peer()

	h2srv.ServeConn(cc, &http2.ServeConnOpts{
		Context: context.WithValue(ctx, peerMachinePublicContextKey{}, peerPub),
		BaseConfig: &http.Server{
			Handler: s.mux,
		},
	})
}

func (s *Server) publicKeys() (noiseKey, pubKey key.MachinePublic) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureKeyPairLocked()
	return s.noisePubKey, s.pubKey
}

func (s *Server) ensureKeyPairLocked() {
	if !s.pubKey.IsZero() {
		return
	}
	s.noisePrivKey = key.NewMachine()
	s.noisePubKey = s.noisePrivKey.Public()
	s.privKey = key.NewControl()
	s.pubKey = s.privKey.Public()
}

func (s *Server) serveKey(w http.ResponseWriter, r *http.Request) {
	noiseKey, legacyKey := s.publicKeys()
	if r.FormValue("v") == "" {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, legacyKey.UntypedHexString())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&tailcfg.OverTLSPublicKeyResponse{
		LegacyPublicKey: legacyKey,
		PublicKey:       noiseKey,
	})
}

func (s *Server) serveMachine(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 400)
		return
	}
	ctx := r.Context()

	mkey, ok := ctx.Value(peerMachinePublicContextKey{}).(key.MachinePublic)
	if !ok {
		panic("no peer machine public key in context")
	}

	switch r.URL.Path {
	case "/machine/map":
		s.serveMap(w, r, mkey)
	case "/machine/register":
		s.serveRegister(w, r, mkey)
	case "/machine/update-health":
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	default:
		s.serveUnhandled(w, r)
	}
}

// SetSubnetRoutes sets the list of subnet routes which a node is routing.
func (s *Server) SetSubnetRoutes(nodeKey key.NodePublic, routes []netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logf("Setting subnet routes for %s: %v", nodeKey.ShortString(), routes)
	mak.Set(&s.nodeSubnetRoutes, nodeKey, routes)
}

// MasqueradePair is a pair of nodes and the IP address that the
// Node masquerades as for the Peer.
//
// Setting this will have future MapResponses for Node to have
// Peer.SelfNodeV{4,6}MasqAddrForThisPeer set to NodeMasqueradesAs.
// MapResponses for the Peer will now see Node.Addresses as
// NodeMasqueradesAs.
type MasqueradePair struct {
	Node              key.NodePublic
	Peer              key.NodePublic
	NodeMasqueradesAs netip.Addr
}

// SetJailed sets b to be jailed when it is a peer of a.
func (s *Server) SetJailed(a, b key.NodePublic, jailed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.peerIsJailed == nil {
		s.peerIsJailed = map[key.NodePublic]map[key.NodePublic]bool{}
	}
	if s.peerIsJailed[a] == nil {
		s.peerIsJailed[a] = map[key.NodePublic]bool{}
	}
	s.peerIsJailed[a][b] = jailed
	s.updateLocked("SetJailed", s.nodeIDsLocked(0))
}

// SetMasqueradeAddresses sets the masquerade addresses for the server.
// See MasqueradePair for more details.
func (s *Server) SetMasqueradeAddresses(pairs []MasqueradePair) {
	m := make(map[key.NodePublic]map[key.NodePublic]netip.Addr)
	for _, p := range pairs {
		if m[p.Node] == nil {
			m[p.Node] = make(map[key.NodePublic]netip.Addr)
		}
		m[p.Node][p.Peer] = p.NodeMasqueradesAs
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.masquerades = m
	s.updateLocked("SetMasqueradeAddresses", s.nodeIDsLocked(0))
}

// SetNodeCapMap overrides the capability map the specified client receives.
func (s *Server) SetNodeCapMap(nodeKey key.NodePublic, capMap tailcfg.NodeCapMap) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mak.Set(&s.nodeCapMaps, nodeKey, capMap)
	s.updateLocked("SetNodeCapMap", s.nodeIDsLocked(0))
}

// nodeIDsLocked returns the node IDs of all nodes in the server, except
// for the node with the given ID.
func (s *Server) nodeIDsLocked(except tailcfg.NodeID) []tailcfg.NodeID {
	var ids []tailcfg.NodeID
	for _, n := range s.nodes {
		if n.ID == except {
			continue
		}
		ids = append(ids, n.ID)
	}
	return ids
}

// Node returns the node for nodeKey. It's always nil or cloned memory.
func (s *Server) Node(nodeKey key.NodePublic) *tailcfg.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nodeLocked(nodeKey)
}

// nodeLocked returns the node for nodeKey. It's always nil or cloned memory.
//
// s.mu must be held.
func (s *Server) nodeLocked(nodeKey key.NodePublic) *tailcfg.Node {
	return s.nodes[nodeKey].Clone()
}

// AddFakeNode injects a fake node into the server.
func (s *Server) AddFakeNode() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nodes == nil {
		s.nodes = make(map[key.NodePublic]*tailcfg.Node)
	}
	nk := key.NewNode().Public()
	mk := key.NewMachine().Public()
	dk := key.NewDisco().Public()
	r := nk.Raw32()
	id := int64(binary.LittleEndian.Uint64(r[:]))
	ip := netaddr.IPv4(r[0], r[1], r[2], r[3])
	addr := netip.PrefixFrom(ip, 32)
	s.nodes[nk] = &tailcfg.Node{
		ID:                tailcfg.NodeID(id),
		StableID:          tailcfg.StableNodeID(fmt.Sprintf("TESTCTRL%08x", id)),
		User:              tailcfg.UserID(id),
		Machine:           mk,
		Key:               nk,
		MachineAuthorized: true,
		DiscoKey:          dk,
		Addresses:         []netip.Prefix{addr},
		AllowedIPs:        []netip.Prefix{addr},
	}
	// TODO: send updates to other (non-fake?) nodes
}

func (s *Server) allUserProfiles() (res []tailcfg.UserProfile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, u := range s.users {
		up := tailcfg.UserProfile{
			ID:          u.ID,
			DisplayName: u.DisplayName,
		}
		if login, ok := s.logins[k]; ok {
			up.LoginName = login.LoginName
			up.ProfilePicURL = cmp.Or(up.ProfilePicURL, login.ProfilePicURL)
			up.DisplayName = cmp.Or(up.DisplayName, login.DisplayName)
		}
		res = append(res, up)
	}
	return res
}

func (s *Server) AllNodes() (nodes []*tailcfg.Node) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.nodes {
		nodes = append(nodes, n.Clone())
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].StableID < nodes[j].StableID
	})
	return nodes
}

const domain = "fake-control.example.net"

func (s *Server) getUser(nodeKey key.NodePublic) (*tailcfg.User, *tailcfg.Login) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.users == nil {
		s.users = map[key.NodePublic]*tailcfg.User{}
	}
	if s.logins == nil {
		s.logins = map[key.NodePublic]*tailcfg.Login{}
	}
	if u, ok := s.users[nodeKey]; ok {
		return u, s.logins[nodeKey]
	}
	id := tailcfg.UserID(len(s.users) + 1)
	if s.AllNodesSameUser {
		id = 123
	}
	s.logf("Created user %v for node %s", id, nodeKey)
	loginName := fmt.Sprintf("user-%d@%s", id, domain)
	displayName := fmt.Sprintf("User %d", id)
	login := &tailcfg.Login{
		ID:            tailcfg.LoginID(id),
		Provider:      "testcontrol",
		LoginName:     loginName,
		DisplayName:   displayName,
		ProfilePicURL: "https://tailscale.com/static/images/marketing/team-carney.jpg",
	}
	user := &tailcfg.User{
		ID:          id,
		DisplayName: displayName,
	}
	s.users[nodeKey] = user
	s.logins[nodeKey] = login
	return user, login
}

// authPathDone returns a close-only struct that's closed when the
// authPath ("/auth/XXXXXX") has authenticated.
func (s *Server) authPathDone(authPath string) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.authPath[authPath]; ok {
		return a.ch
	}
	return nil
}

func (s *Server) addAuthPath(authPath string, nodeKey key.NodePublic) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.authPath == nil {
		s.authPath = map[string]*AuthPath{}
	}
	s.authPath[authPath] = &AuthPath{
		ch:      make(chan struct{}),
		nodeKey: nodeKey,
	}
}

// CompleteAuth marks the provided path or URL (containing
// "/auth/...")  as successfully authenticated, unblocking any
// requests blocked on that in serveRegister.
func (s *Server) CompleteAuth(authPathOrURL string) bool {
	i := strings.Index(authPathOrURL, "/auth/")
	if i == -1 {
		return false
	}
	authPath := authPathOrURL[i:]

	s.mu.Lock()
	defer s.mu.Unlock()
	ap, ok := s.authPath[authPath]
	if !ok {
		return false
	}
	if ap.nodeKey.IsZero() {
		panic("zero AuthPath.NodeKey")
	}
	s.nodeKeyAuthed.Make()
	s.nodeKeyAuthed.Add(ap.nodeKey)
	ap.CompleteSuccessfully()
	return true
}

// Complete the device approval for this node.
//
// This function returns false if the node does not exist, or you try to
// approve a device against a different control server.
func (s *Server) CompleteDeviceApproval(controlUrl string, urlStr string, nodeKey *key.NodePublic) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[*nodeKey]
	if !ok {
		return false
	}

	if urlStr != controlUrl+"/admin" {
		return false
	}

	sendUpdate(s.updates[node.ID], updateSelfChanged)

	node.MachineAuthorized = true
	return true
}

func (s *Server) serveRegister(w http.ResponseWriter, r *http.Request, mkey key.MachinePublic) {
	msg, err := io.ReadAll(io.LimitReader(r.Body, msgLimit))
	r.Body.Close()
	if err != nil {
		http.Error(w, fmt.Sprintf("bad map request read: %v", err), 400)
		return
	}

	var req tailcfg.RegisterRequest
	if err := s.decode(msg, &req); err != nil {
		go panic(fmt.Sprintf("serveRegister: decode: %v", err))
	}
	if req.Version == 0 {
		panic("serveRegister: zero Version")
	}
	if req.NodeKey.IsZero() {
		go panic("serveRegister: request has zero node key")
	}
	if s.Verbose {
		j, _ := json.MarshalIndent(req, "", "\t")
		log.Printf("Got %T: %s", req, j)
	}
	if s.RequireAuthKey != "" && (req.Auth == nil || req.Auth.AuthKey != s.RequireAuthKey) {
		res := must.Get(s.encode(false, tailcfg.RegisterResponse{
			Error: "invalid authkey",
		}))
		w.WriteHeader(200)
		w.Write(res)
		return
	}

	// If this is a followup request, wait until interactive followup URL visit complete.
	if req.Followup != "" {
		followupURL, err := url.Parse(req.Followup)
		if err != nil {
			panic(err)
		}
		doneCh := s.authPathDone(followupURL.Path)
		select {
		case <-r.Context().Done():
			return
		case <-doneCh:
		}
		// TODO(bradfitz): support a side test API to mark an
		// auth as failed so we can send an error response in
		// some follow-ups? For now all are successes.
	}

	// The in-memory list of nodes, users, and logins is keyed by
	// the node key.  If the node key changes, update all the data stores
	// to use the new node key.
	s.mu.Lock()
	if _, oldNodeKeyOk := s.nodes[req.OldNodeKey]; oldNodeKeyOk {
		if _, newNodeKeyOk := s.nodes[req.NodeKey]; !newNodeKeyOk {
			s.nodes[req.OldNodeKey].Key = req.NodeKey
			s.nodes[req.NodeKey] = s.nodes[req.OldNodeKey]

			s.users[req.NodeKey] = s.users[req.OldNodeKey]
			s.logins[req.NodeKey] = s.logins[req.OldNodeKey]

			delete(s.nodes, req.OldNodeKey)
			delete(s.users, req.OldNodeKey)
			delete(s.logins, req.OldNodeKey)
		}
	}
	s.mu.Unlock()

	nk := req.NodeKey

	user, login := s.getUser(nk)
	s.mu.Lock()
	if s.nodes == nil {
		s.nodes = map[key.NodePublic]*tailcfg.Node{}
	}
	_, ok := s.nodes[nk]
	machineAuthorized := !s.RequireMachineAuth
	if !ok {

		nodeID := len(s.nodes) + 1
		v4Prefix := netip.PrefixFrom(netaddr.IPv4(100, 64, uint8(nodeID>>8), uint8(nodeID)), 32)
		v6Prefix := netip.PrefixFrom(tsaddr.Tailscale4To6(v4Prefix.Addr()), 128)

		allowedIPs := []netip.Prefix{
			v4Prefix,
			v6Prefix,
		}

		var capMap tailcfg.NodeCapMap
		if s.DefaultNodeCapabilities != nil {
			capMap = *s.DefaultNodeCapabilities
		} else {
			capMap = tailcfg.NodeCapMap{
				tailcfg.CapabilityHTTPS:                           []tailcfg.RawMessage{},
				tailcfg.NodeAttrFunnel:                            []tailcfg.RawMessage{},
				tailcfg.CapabilityFileSharing:                     []tailcfg.RawMessage{},
				tailcfg.CapabilityFunnelPorts + "?ports=8080,443": []tailcfg.RawMessage{},
			}
		}

		node := &tailcfg.Node{
			ID:                tailcfg.NodeID(nodeID),
			StableID:          tailcfg.StableNodeID(fmt.Sprintf("TESTCTRL%08x", int(nodeID))),
			User:              user.ID,
			Machine:           mkey,
			Key:               req.NodeKey,
			MachineAuthorized: machineAuthorized,
			Addresses:         allowedIPs,
			AllowedIPs:        allowedIPs,
			Hostinfo:          req.Hostinfo.View(),
			Name:              req.Hostinfo.Hostname,
			Cap:               req.Version,
			CapMap:            capMap,
			Capabilities:      slices.Collect(maps.Keys(capMap)),
		}
		s.nodes[nk] = node
	}
	requireAuth := s.RequireAuth
	if requireAuth && s.nodeKeyAuthed.Contains(nk) {
		requireAuth = false
	}
	allExpired := s.allExpired
	s.mu.Unlock()

	authURL := ""
	if requireAuth {
		authPath := fmt.Sprintf("/auth/%s", rands.HexString(20))
		s.addAuthPath(authPath, nk)
		authURL = s.BaseURL() + authPath
	}

	res, err := s.encode(false, tailcfg.RegisterResponse{
		User:              *user,
		Login:             *login,
		NodeKeyExpired:    allExpired,
		MachineAuthorized: machineAuthorized,
		AuthURL:           authURL,
	})
	if err != nil {
		go panic(fmt.Sprintf("serveRegister: encode: %v", err))
	}
	w.WriteHeader(200)
	w.Write(res)
}

// updateType indicates why a long-polling map request is being woken
// up for an update.
type updateType int

const (
	// updatePeerChanged is an update that a peer has changed.
	updatePeerChanged updateType = iota + 1

	// updateSelfChanged is an update that the node changed itself
	// via a lite endpoint update. These ones are never dup-suppressed,
	// as the client is expecting an answer regardless.
	updateSelfChanged

	// updateDebugInjection is an update used for PingRequests
	// or a raw MapResponse.
	updateDebugInjection
)

func (s *Server) updateLocked(source string, peers []tailcfg.NodeID) {
	for _, peer := range peers {
		sendUpdate(s.updates[peer], updatePeerChanged)
	}
}

// sendUpdate sends updateType to dst if dst is non-nil and
// has capacity. It reports whether a value was sent.
func sendUpdate(dst chan<- updateType, updateType updateType) bool {
	if dst == nil {
		return false
	}
	// The dst channel has a buffer size of 1.
	// If we fail to insert an update into the buffer that
	// means there is already an update pending.
	select {
	case dst <- updateType:
		return true
	default:
		return false
	}
}

func (s *Server) UpdateNode(n *tailcfg.Node) (peersToUpdate []tailcfg.NodeID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n.Key.IsZero() {
		panic("zero nodekey")
	}
	s.nodes[n.Key] = n.Clone()
	return s.nodeIDsLocked(n.ID)
}

func (s *Server) incrInServeMap(delta int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inServeMap += delta
}

// InServeMap returns the number of clients currently in a MapRequest HTTP handler.
func (s *Server) InServeMap() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inServeMap
}

func (s *Server) serveMap(w http.ResponseWriter, r *http.Request, mkey key.MachinePublic) {
	s.incrInServeMap(1)
	defer s.incrInServeMap(-1)
	ctx := r.Context()

	msg, err := io.ReadAll(io.LimitReader(r.Body, msgLimit))
	if err != nil {
		r.Body.Close()
		http.Error(w, fmt.Sprintf("bad map request read: %v", err), 400)
		return
	}
	r.Body.Close()

	req := new(tailcfg.MapRequest)
	if err := s.decode(msg, req); err != nil {
		go panic(fmt.Sprintf("bad map request: %v", err))
	}

	jitter := rand.N(8 * time.Second)
	keepAlive := 50*time.Second + jitter

	node := s.Node(req.NodeKey)
	if node == nil {
		http.Error(w, "node not found", 400)
		return
	}
	if node.Machine != mkey {
		http.Error(w, "node doesn't match machine key", 400)
		return
	}

	var peersToUpdate []tailcfg.NodeID
	if !req.ReadOnly {
		endpoints := filterInvalidIPv6Endpoints(req.Endpoints)
		node.Endpoints = endpoints
		node.DiscoKey = req.DiscoKey
		node.Cap = req.Version
		if req.Hostinfo != nil {
			node.Hostinfo = req.Hostinfo.View()
			if ni := node.Hostinfo.NetInfo(); ni.Valid() {
				if ni.PreferredDERP() != 0 {
					node.HomeDERP = ni.PreferredDERP()
				}
			}
		}
		peersToUpdate = s.UpdateNode(node)
	}

	nodeID := node.ID

	s.mu.Lock()
	updatesCh := make(chan updateType, 1)
	oldUpdatesCh := s.updates[nodeID]
	if breakSameNodeMapResponseStreams(req) {
		if oldUpdatesCh != nil {
			close(oldUpdatesCh)
		}
		if s.updates == nil {
			s.updates = map[tailcfg.NodeID]chan updateType{}
		}
		s.updates[nodeID] = updatesCh
	} else {
		sendUpdate(oldUpdatesCh, updateSelfChanged)
	}
	s.updateLocked("serveMap", peersToUpdate)
	s.condLocked().Broadcast()
	s.mu.Unlock()

	// ReadOnly implies no streaming, as it doesn't
	// register an updatesCh to get updates.
	streaming := req.Stream && !req.ReadOnly
	compress := req.Compress != ""

	w.WriteHeader(200)
	for {
		// Only send raw map responses to the streaming poll, to avoid a
		// non-streaming map request beating the streaming poll in a race and
		// potentially dropping the map response.
		if streaming {
			if resBytes, ok := s.takeRawMapMessage(req.NodeKey); ok {
				if err := s.sendMapMsg(w, compress, resBytes); err != nil {
					s.logf("sendMapMsg of raw message: %v", err)
					return
				}
				continue
			}
		}

		if s.canGenerateAutomaticMapResponseFor(req.NodeKey) {
			res, err := s.MapResponse(req)
			if err != nil {
				// TODO: log
				return
			}
			if res == nil {
				return // done
			}

			s.mu.Lock()
			allExpired := s.allExpired
			s.mu.Unlock()
			if allExpired {
				res.Node.KeyExpiry = time.Now().Add(-1 * time.Minute)
			}
			// TODO: add minner if/when needed
			resBytes, err := json.Marshal(res)
			if err != nil {
				s.logf("json.Marshal: %v", err)
				return
			}
			if err := s.sendMapMsg(w, compress, resBytes); err != nil {
				return
			}
		}
		if !streaming {
			return
		}
		if s.hasPendingRawMapMessage(req.NodeKey) {
			continue
		}
	keepAliveLoop:
		for {
			var keepAliveTimer *time.Timer
			var keepAliveTimerCh <-chan time.Time
			if keepAlive > 0 {
				keepAliveTimer = time.NewTimer(keepAlive)
				keepAliveTimerCh = keepAliveTimer.C
			}
			select {
			case <-ctx.Done():
				if keepAliveTimer != nil {
					keepAliveTimer.Stop()
				}
				return
			case _, ok := <-updatesCh:
				if !ok {
					// replaced by new poll request
					return
				}
				break keepAliveLoop
			case <-keepAliveTimerCh:
				if err := s.sendMapMsg(w, compress, keepAliveMsg); err != nil {
					return
				}
			}
		}
	}
}

var keepAliveMsg = &struct {
	KeepAlive bool
}{
	KeepAlive: true,
}

func packetFilterWithIngress(addRelayCaps bool) []tailcfg.FilterRule {
	out := slices.Clone(tailcfg.FilterAllowAll)
	caps := []tailcfg.PeerCapability{
		tailcfg.PeerCapabilityIngress,
	}
	if addRelayCaps {
		caps = append(caps, tailcfg.PeerCapabilityRelay)
		caps = append(caps, tailcfg.PeerCapabilityRelayTarget)
	}
	out = append(out, tailcfg.FilterRule{
		SrcIPs: []string{"*"},
		CapGrant: []tailcfg.CapGrant{
			{
				Dsts: []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()},
				Caps: caps,
			},
		},
	})
	return out
}

// MapResponse generates a MapResponse for a MapRequest.
//
// No updates to s are done here.
func (s *Server) MapResponse(req *tailcfg.MapRequest) (res *tailcfg.MapResponse, err error) {
	nk := req.NodeKey
	node := s.Node(nk)
	if node == nil {
		// node key rotated away (once test server supports that)
		return nil, nil
	}

	s.mu.Lock()
	nodeCapMap := maps.Clone(s.nodeCapMaps[nk])
	s.mu.Unlock()

	node.CapMap = nodeCapMap
	node.Capabilities = append(node.Capabilities, tailcfg.NodeAttrDisableUPnP)

	t := time.Date(2020, 8, 3, 0, 0, 0, 1, time.UTC)
	dns := s.DNSConfig
	if dns != nil && s.MagicDNSDomain != "" {
		dns = dns.Clone()
		dns.CertDomains = []string{
			node.Hostinfo.Hostname() + "." + s.MagicDNSDomain,
		}
	}

	res = &tailcfg.MapResponse{
		Node:            node,
		DERPMap:         s.DERPMap,
		Domain:          domain,
		CollectServices: cmp.Or(s.CollectServices, opt.True),
		PacketFilter:    packetFilterWithIngress(s.PeerRelayGrants),
		DNSConfig:       dns,
		ControlTime:     &t,
	}

	s.mu.Lock()
	nodeMasqs := s.masquerades[node.Key]
	jailed := maps.Clone(s.peerIsJailed[node.Key])
	s.mu.Unlock()
	for _, p := range s.AllNodes() {
		if p.StableID == node.StableID {
			continue
		}
		if masqIP := nodeMasqs[p.Key]; masqIP.IsValid() {
			if masqIP.Is6() {
				p.SelfNodeV6MasqAddrForThisPeer = ptr.To(masqIP)
			} else {
				p.SelfNodeV4MasqAddrForThisPeer = ptr.To(masqIP)
			}
		}
		p.IsJailed = jailed[p.Key]

		s.mu.Lock()
		peerAddress := s.masquerades[p.Key][node.Key]
		routes := s.nodeSubnetRoutes[p.Key]
		peerCapMap := maps.Clone(s.nodeCapMaps[p.Key])
		s.mu.Unlock()
		if peerCapMap != nil {
			p.CapMap = peerCapMap
		}
		if peerAddress.IsValid() {
			if peerAddress.Is6() {
				p.Addresses[1] = netip.PrefixFrom(peerAddress, peerAddress.BitLen())
				p.AllowedIPs[1] = netip.PrefixFrom(peerAddress, peerAddress.BitLen())
			} else {
				p.Addresses[0] = netip.PrefixFrom(peerAddress, peerAddress.BitLen())
				p.AllowedIPs[0] = netip.PrefixFrom(peerAddress, peerAddress.BitLen())
			}
		}
		if len(routes) > 0 {
			p.PrimaryRoutes = routes
			p.AllowedIPs = append(p.AllowedIPs, routes...)
		}
		res.Peers = append(res.Peers, p)
	}

	sort.Slice(res.Peers, func(i, j int) bool {
		return res.Peers[i].ID < res.Peers[j].ID
	})
	res.UserProfiles = s.allUserProfiles()

	v4Prefix := netip.PrefixFrom(netaddr.IPv4(100, 64, uint8(node.ID>>8), uint8(node.ID)), 32)
	v6Prefix := netip.PrefixFrom(tsaddr.Tailscale4To6(v4Prefix.Addr()), 128)

	res.Node.Addresses = []netip.Prefix{
		v4Prefix,
		v6Prefix,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	res.Node.PrimaryRoutes = s.nodeSubnetRoutes[nk]
	res.Node.AllowedIPs = append(res.Node.Addresses, s.nodeSubnetRoutes[nk]...)

	// Consume a PingRequest while protected by mutex if it exists
	switch m := s.msgToSend[nk].(type) {
	case *tailcfg.PingRequest:
		res.PingRequest = m
		delete(s.msgToSend, nk)
	}
	return res, nil
}

func (s *Server) canGenerateAutomaticMapResponseFor(nk key.NodePublic) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.suppressAutoMapResponses.Contains(nk)
}

func (s *Server) hasPendingRawMapMessage(nk key.NodePublic) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.msgToSend[nk]
	return ok
}

func (s *Server) takeRawMapMessage(nk key.NodePublic) (mapResJSON []byte, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mr, ok := s.msgToSend[nk]
	if !ok {
		return nil, false
	}
	delete(s.msgToSend, nk)

	// If it's a bare PingRequest, wrap it in a MapResponse.
	switch pr := mr.(type) {
	case *tailcfg.PingRequest:
		mr = &tailcfg.MapResponse{PingRequest: pr}
	}

	var err error
	mapResJSON, err = json.Marshal(mr)
	if err != nil {
		panic(err)
	}
	return mapResJSON, true
}

func (s *Server) sendMapMsg(w http.ResponseWriter, compress bool, msg any) error {
	resBytes, err := s.encode(compress, msg)
	if err != nil {
		return err
	}
	if len(resBytes) > 16<<20 {
		return fmt.Errorf("map message too big: %d", len(resBytes))
	}
	var siz [4]byte
	binary.LittleEndian.PutUint32(siz[:], uint32(len(resBytes)))
	if _, err := w.Write(siz[:]); err != nil {
		return err
	}
	if _, err := w.Write(resBytes); err != nil {
		return err
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	} else {
		s.logf("[unexpected] ResponseWriter %T is not a Flusher", w)
	}
	return nil
}

func (s *Server) decode(msg []byte, v any) error {
	if len(msg) == msgLimit {
		return errors.New("encrypted message too long")
	}
	return json.Unmarshal(msg, v)
}

func (s *Server) encode(compress bool, v any) (b []byte, err error) {
	var isBytes bool
	if b, isBytes = v.([]byte); !isBytes {
		b, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}
	if compress {
		b = zstdframe.AppendEncode(nil, b, zstdframe.FastestCompression)
	}
	return b, nil
}

// filterInvalidIPv6Endpoints removes invalid IPv6 endpoints from eps,
// modify the slice in place, returning the potentially smaller subset (aliasing
// the original memory).
//
// Two types of IPv6 endpoints are considered invalid: link-local
// addresses, and anything with a zone.
func filterInvalidIPv6Endpoints(eps []netip.AddrPort) []netip.AddrPort {
	clean := eps[:0]
	for _, ep := range eps {
		if keepClientEndpoint(ep) {
			clean = append(clean, ep)
		}
	}
	return clean
}

func keepClientEndpoint(ipp netip.AddrPort) bool {
	ip := ipp.Addr()
	if ip.Zone() != "" {
		return false
	}
	if ip.Is6() && ip.IsLinkLocalUnicast() {
		// We let clients send these for now, but
		// tailscaled doesn't know how to use them yet
		// so we filter them out for now. A future
		// MapRequest.Version might signal that
		// clients know how to use them (e.g. try all
		// local scopes).
		return false
	}
	return true
}

// breakSameNodeMapResponseStreams reports whether req should break a
// prior long-polling MapResponse stream (if active) from the same
// node ID.
func breakSameNodeMapResponseStreams(req *tailcfg.MapRequest) bool {
	if req.ReadOnly {
		// Don't register our updatesCh for closability
		// nor close another peer's if we're a read-only request.
		return false
	}
	if !req.Stream && req.OmitPeers {
		// Likewise, if we're not streaming and not asking for peers,
		// (but still mutable, without Readonly set), consider this an endpoint
		// update request only, and don't close any existing map response
		// for this nodeID. It's likely the same client with a built-up
		// compression context. We want to let them update their
		// new endpoints with us without breaking that other long-running
		// map response.
		return false
	}
	return true
}
