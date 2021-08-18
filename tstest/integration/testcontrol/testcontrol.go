// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package testcontrol contains a minimal control plane server for testing purposes.
package testcontrol

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/nacl/box"
	"inet.af/netaddr"
	"tailscale.com/net/tsaddr"
	"tailscale.com/smallzstd"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/wgkey"
)

// Server is a control plane server. Its zero value is ready for use.
// Everything is stored in-memory in one tailnet.
type Server struct {
	Logf        logger.Logf      // nil means to use the log package
	DERPMap     *tailcfg.DERPMap // nil means to use prod DERP map
	RequireAuth bool
	Verbose     bool

	// ExplicitBaseURL or HTTPTestServer must be set.
	ExplicitBaseURL string           // e.g. "http://127.0.0.1:1234" with no trailing URL
	HTTPTestServer  *httptest.Server // if non-nil, used to get BaseURL

	initMuxOnce sync.Once
	mux         *http.ServeMux

	mu            sync.Mutex
	inServeMap    int
	cond          *sync.Cond // lazily initialized by condLocked
	pubKey        wgkey.Key
	privKey       wgkey.Private
	nodes         map[tailcfg.NodeKey]*tailcfg.Node
	users         map[tailcfg.NodeKey]*tailcfg.User
	logins        map[tailcfg.NodeKey]*tailcfg.Login
	updates       map[tailcfg.NodeID]chan updateType
	authPath      map[string]*AuthPath
	nodeKeyAuthed map[tailcfg.NodeKey]bool // key => true once authenticated
	pingReqsToAdd map[tailcfg.NodeKey]*tailcfg.PingRequest
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
func (s *Server) AwaitNodeInMapRequest(ctx context.Context, k tailcfg.NodeKey) error {
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

// AddPingRequest sends the ping pr to nodeKeyDst. It reports whether it did so. That is,
// it reports whether nodeKeyDst was connected.
func (s *Server) AddPingRequest(nodeKeyDst tailcfg.NodeKey, pr *tailcfg.PingRequest) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pingReqsToAdd == nil {
		s.pingReqsToAdd = map[tailcfg.NodeKey]*tailcfg.PingRequest{}
	}
	// Now send the update to the channel
	node := s.nodeLocked(nodeKeyDst)
	if node == nil {
		return false
	}

	s.pingReqsToAdd[nodeKeyDst] = pr
	nodeID := node.ID
	oldUpdatesCh := s.updates[nodeID]
	return sendUpdate(oldUpdatesCh, updateDebugInjection)
}

type AuthPath struct {
	nodeKey tailcfg.NodeKey

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

func (s *Server) logf(format string, a ...interface{}) {
	if s.Logf != nil {
		s.Logf(format, a...)
	} else {
		log.Printf(format, a...)
	}
}

func (s *Server) initMux() {
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("/", s.serveUnhandled)
	s.mux.HandleFunc("/key", s.serveKey)
	s.mux.HandleFunc("/machine/", s.serveMachine)
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

func (s *Server) publicKey() wgkey.Key {
	pub, _ := s.keyPair()
	return pub
}

func (s *Server) privateKey() wgkey.Private {
	_, priv := s.keyPair()
	return priv
}

func (s *Server) keyPair() (pub wgkey.Key, priv wgkey.Private) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pubKey.IsZero() {
		var err error
		s.privKey, err = wgkey.NewPrivate()
		if err != nil {
			go panic(err) // bring down test, even if in http.Handler
		}
		s.pubKey = s.privKey.Public()
	}
	return s.pubKey, s.privKey
}

func (s *Server) serveKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(200)
	io.WriteString(w, s.publicKey().HexString())
}

func (s *Server) serveMachine(w http.ResponseWriter, r *http.Request) {
	mkeyStr := strings.TrimPrefix(r.URL.Path, "/machine/")
	rem := ""
	if i := strings.IndexByte(mkeyStr, '/'); i != -1 {
		rem = mkeyStr[i:]
		mkeyStr = mkeyStr[:i]
	}

	key, err := wgkey.ParseHex(mkeyStr)
	if err != nil {
		http.Error(w, "bad machine key hex", 400)
		return
	}
	mkey := tailcfg.MachineKey(key)

	if r.Method != "POST" {
		http.Error(w, "POST required", 400)
		return
	}

	switch rem {
	case "":
		s.serveRegister(w, r, mkey)
	case "/map":
		s.serveMap(w, r, mkey)
	default:
		s.serveUnhandled(w, r)
	}
}

// Node returns the node for nodeKey. It's always nil or cloned memory.
func (s *Server) Node(nodeKey tailcfg.NodeKey) *tailcfg.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nodeLocked(nodeKey)
}

// nodeLocked returns the node for nodeKey. It's always nil or cloned memory.
//
// s.mu must be held.
func (s *Server) nodeLocked(nodeKey tailcfg.NodeKey) *tailcfg.Node {
	return s.nodes[nodeKey].Clone()
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

func (s *Server) getUser(nodeKey tailcfg.NodeKey) (*tailcfg.User, *tailcfg.Login) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.users == nil {
		s.users = map[tailcfg.NodeKey]*tailcfg.User{}
	}
	if s.logins == nil {
		s.logins = map[tailcfg.NodeKey]*tailcfg.Login{}
	}
	if u, ok := s.users[nodeKey]; ok {
		return u, s.logins[nodeKey]
	}
	id := tailcfg.UserID(len(s.users) + 1)
	domain := "fake-control.example.net"
	loginName := fmt.Sprintf("user-%d@%s", id, domain)
	displayName := fmt.Sprintf("User %d", id)
	login := &tailcfg.Login{
		ID:            tailcfg.LoginID(id),
		Provider:      "testcontrol",
		LoginName:     loginName,
		DisplayName:   displayName,
		ProfilePicURL: "https://tailscale.com/static/images/marketing/team-carney.jpg",
		Domain:        domain,
	}
	user := &tailcfg.User{
		ID:          id,
		LoginName:   loginName,
		DisplayName: displayName,
		Domain:      domain,
		Logins:      []tailcfg.LoginID{login.ID},
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

func (s *Server) addAuthPath(authPath string, nodeKey tailcfg.NodeKey) {
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
	if s.nodeKeyAuthed == nil {
		s.nodeKeyAuthed = map[tailcfg.NodeKey]bool{}
	}
	s.nodeKeyAuthed[ap.nodeKey] = true
	ap.CompleteSuccessfully()
	return true
}

func (s *Server) serveRegister(w http.ResponseWriter, r *http.Request, mkey tailcfg.MachineKey) {
	var req tailcfg.RegisterRequest
	if err := s.decode(mkey, r.Body, &req); err != nil {
		panic(fmt.Sprintf("serveRegister: decode: %v", err))
	}
	if req.Version != 1 {
		panic(fmt.Sprintf("serveRegister: unsupported version: %d", req.Version))
	}
	if req.NodeKey.IsZero() {
		panic("serveRegister: request has zero node key")
	}
	if s.Verbose {
		j, _ := json.MarshalIndent(req, "", "\t")
		log.Printf("Got %T: %s", req, j)
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
		// auth as failued so we can send an error response in
		// some follow-ups? For now all are successes.
	}

	user, login := s.getUser(req.NodeKey)
	s.mu.Lock()
	if s.nodes == nil {
		s.nodes = map[tailcfg.NodeKey]*tailcfg.Node{}
	}

	machineAuthorized := true // TODO: add Server.RequireMachineAuth

	v4Prefix := netaddr.IPPrefixFrom(netaddr.IPv4(100, 64, uint8(tailcfg.NodeID(user.ID)>>8), uint8(tailcfg.NodeID(user.ID))), 32)
	v6Prefix := netaddr.IPPrefixFrom(tsaddr.Tailscale4To6(v4Prefix.IP()), 128)

	allowedIPs := []netaddr.IPPrefix{
		v4Prefix,
		v6Prefix,
	}

	s.nodes[req.NodeKey] = &tailcfg.Node{
		ID:                tailcfg.NodeID(user.ID),
		StableID:          tailcfg.StableNodeID(fmt.Sprintf("TESTCTRL%08x", int(user.ID))),
		User:              user.ID,
		Machine:           mkey,
		Key:               req.NodeKey,
		MachineAuthorized: machineAuthorized,
		Addresses:         allowedIPs,
		AllowedIPs:        allowedIPs,
	}
	requireAuth := s.RequireAuth
	if requireAuth && s.nodeKeyAuthed[req.NodeKey] {
		requireAuth = false
	}
	s.mu.Unlock()

	authURL := ""
	if requireAuth {
		randHex := make([]byte, 10)
		crand.Read(randHex)
		authPath := fmt.Sprintf("/auth/%x", randHex)
		s.addAuthPath(authPath, req.NodeKey)
		authURL = s.BaseURL() + authPath
	}

	res, err := s.encode(mkey, false, tailcfg.RegisterResponse{
		User:              *user,
		Login:             *login,
		NodeKeyExpired:    false,
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
	for _, n2 := range s.nodes {
		if n.ID != n2.ID {
			peersToUpdate = append(peersToUpdate, n2.ID)
		}
	}
	return peersToUpdate
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

func (s *Server) serveMap(w http.ResponseWriter, r *http.Request, mkey tailcfg.MachineKey) {
	s.incrInServeMap(1)
	defer s.incrInServeMap(-1)
	ctx := r.Context()

	req := new(tailcfg.MapRequest)
	if err := s.decode(mkey, r.Body, req); err != nil {
		go panic(fmt.Sprintf("bad map request: %v", err))
	}

	jitter := time.Duration(rand.Intn(8000)) * time.Millisecond
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
		res, err := s.MapResponse(req)
		if err != nil {
			// TODO: log
			return
		}
		if res == nil {
			return // done
		}
		// TODO: add minner if/when needed
		resBytes, err := json.Marshal(res)
		if err != nil {
			s.logf("json.Marshal: %v", err)
			return
		}
		if err := s.sendMapMsg(w, mkey, compress, resBytes); err != nil {
			return
		}
		if !streaming {
			return
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
				if err := s.sendMapMsg(w, mkey, compress, keepAliveMsg); err != nil {
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

// MapResponse generates a MapResponse for a MapRequest.
//
// No updates to s are done here.
func (s *Server) MapResponse(req *tailcfg.MapRequest) (res *tailcfg.MapResponse, err error) {
	node := s.Node(req.NodeKey)
	if node == nil {
		// node key rotated away (once test server supports that)
		return nil, nil
	}
	user, _ := s.getUser(req.NodeKey)
	res = &tailcfg.MapResponse{
		Node:            node,
		DERPMap:         s.DERPMap,
		Domain:          string(user.Domain),
		CollectServices: "true",
		PacketFilter:    tailcfg.FilterAllowAll,
		Debug: &tailcfg.Debug{
			DisableUPnP: "true",
		},
	}
	for _, p := range s.AllNodes() {
		if p.StableID != node.StableID {
			res.Peers = append(res.Peers, p)
		}
	}
	sort.Slice(res.Peers, func(i, j int) bool {
		return res.Peers[i].ID < res.Peers[j].ID
	})

	v4Prefix := netaddr.IPPrefixFrom(netaddr.IPv4(100, 64, uint8(tailcfg.NodeID(user.ID)>>8), uint8(tailcfg.NodeID(user.ID))), 32)
	v6Prefix := netaddr.IPPrefixFrom(tsaddr.Tailscale4To6(v4Prefix.IP()), 128)

	res.Node.Addresses = []netaddr.IPPrefix{
		v4Prefix,
		v6Prefix,
	}
	res.Node.AllowedIPs = res.Node.Addresses

	// Consume the PingRequest while protected by mutex if it exists
	s.mu.Lock()
	if pr, ok := s.pingReqsToAdd[node.Key]; ok {
		res.PingRequest = pr
		delete(s.pingReqsToAdd, node.Key)
	}
	s.mu.Unlock()
	return res, nil
}

func (s *Server) sendMapMsg(w http.ResponseWriter, mkey tailcfg.MachineKey, compress bool, msg interface{}) error {
	resBytes, err := s.encode(mkey, compress, msg)
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

func (s *Server) decode(mkey tailcfg.MachineKey, r io.Reader, v interface{}) error {
	if c, _ := r.(io.Closer); c != nil {
		defer c.Close()
	}
	const msgLimit = 1 << 20
	msg, err := ioutil.ReadAll(io.LimitReader(r, msgLimit))
	if err != nil {
		return err
	}
	if len(msg) == msgLimit {
		return errors.New("encrypted message too long")
	}

	var nonce [24]byte
	if len(msg) < len(nonce)+1 {
		return errors.New("missing nonce")
	}
	copy(nonce[:], msg)
	msg = msg[len(nonce):]

	priv := s.privateKey()
	pub, pri := (*[32]byte)(&mkey), (*[32]byte)(&priv)
	decrypted, ok := box.Open(nil, msg, &nonce, pub, pri)
	if !ok {
		return errors.New("can't decrypt request")
	}
	return json.Unmarshal(decrypted, v)
}

var zstdEncoderPool = &sync.Pool{
	New: func() interface{} {
		encoder, err := smallzstd.NewEncoder(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
		if err != nil {
			panic(err)
		}
		return encoder
	},
}

func (s *Server) encode(mkey tailcfg.MachineKey, compress bool, v interface{}) (b []byte, err error) {
	var isBytes bool
	if b, isBytes = v.([]byte); !isBytes {
		b, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}
	if compress {
		encoder := zstdEncoderPool.Get().(*zstd.Encoder)
		b = encoder.EncodeAll(b, nil)
		encoder.Close()
		zstdEncoderPool.Put(encoder)
	}
	var nonce [24]byte
	if _, err := io.ReadFull(crand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	priv := s.privateKey()
	pub, pri := (*[32]byte)(&mkey), (*[32]byte)(&priv)
	msgData := box.Seal(nonce[:], b, &nonce, pub, pri)
	return msgData, nil
}

// filterInvalidIPv6Endpoints removes invalid IPv6 endpoints from eps,
// modify the slice in place, returning the potentially smaller subset (aliasing
// the original memory).
//
// Two types of IPv6 endpoints are considered invalid: link-local
// addresses, and anything with a zone.
func filterInvalidIPv6Endpoints(eps []string) []string {
	clean := eps[:0]
	for _, ep := range eps {
		if keepClientEndpoint(ep) {
			clean = append(clean, ep)
		}
	}
	return clean
}

func keepClientEndpoint(ep string) bool {
	ipp, err := netaddr.ParseIPPort(ep)
	if err != nil {
		// Shouldn't have made it this far if we unmarshalled
		// the incoming JSON response.
		return false
	}
	ip := ipp.IP()
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
