// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package derpserver implements a DERP server.
package derpserver

// TODO(crawshaw): with predefined serverKey in clients and HMAC on packets we could skip TLS

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"math/bits"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/axiomhq/hyperloglog"
	"github.com/go4org/hashtriemap"
	"go4.org/mem"
	xrate "golang.org/x/time/rate"
	"tailscale.com/client/local"
	"tailscale.com/derp"
	"tailscale.com/derp/derpconst"
	"tailscale.com/disco"
	"tailscale.com/envknob"
	"tailscale.com/metrics"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/tstime/rate"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/bufiox"
	"tailscale.com/util/ctxkey"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
	"tailscale.com/util/slicesx"
	"tailscale.com/version"
)

// verboseDropKeys is the set of destination public keys that should
// verbosely log whenever DERP drops a packet.
var verboseDropKeys = map[key.NodePublic]bool{}

// IdealNodeContextKey is the context key used to pass the IdealNodeHeader value
// from the HTTP handler to the DERP server's Accept method.
var IdealNodeContextKey = ctxkey.New("ideal-node", "")

func init() {
	keys := envknob.String("TS_DEBUG_VERBOSE_DROPS")
	if keys == "" {
		return
	}
	for keyStr := range strings.SplitSeq(keys, ",") {
		k, err := key.ParseNodePublicUntyped(mem.S(keyStr))
		if err != nil {
			log.Printf("ignoring invalid debug key %q: %v", keyStr, err)
		} else {
			verboseDropKeys[k] = true
		}
	}
}

const (
	defaultPerClientSendQueueDepth = 32 // default packets buffered for sending
	DefaultTCPWiteTimeout          = 2 * time.Second
	privilegedWriteTimeout         = 30 * time.Second // for clients with the mesh key
)

// getPerClientSendQueueDepth returns the per-client send queue depth,
// from TS_DEBUG_DERP_PER_CLIENT_SEND_QUEUE_DEPTH if set to a positive
// value, else defaultPerClientSendQueueDepth. Zero and negative values
// are treated as unset.
func getPerClientSendQueueDepth() int {
	if v, ok := envknob.LookupInt("TS_DEBUG_DERP_PER_CLIENT_SEND_QUEUE_DEPTH"); ok && v > 0 {
		return v
	}
	return defaultPerClientSendQueueDepth
}

// dupPolicy is a temporary (2021-08-30) mechanism to change the policy
// of how duplicate connection for the same key are handled.
type dupPolicy int8

const (
	// lastWriterIsActive is a dupPolicy where the connection
	// to send traffic for a peer is the active one.
	lastWriterIsActive dupPolicy = iota

	// disableFighters is a dupPolicy that detects if peers
	// are trying to send interleaved with each other and
	// then disables all of them.
	disableFighters
)

// packetKind is the kind of packet being sent through DERP
type packetKind string

const (
	packetKindDisco packetKind = "disco"
	packetKindOther packetKind = "other"
)

type align64 [0]atomic.Int64 // for side effect of its 64-bit alignment

// Server is a DERP server.
type Server struct {
	// WriteTimeout, if non-zero, specifies how long to wait
	// before failing when writing to a client.
	WriteTimeout time.Duration

	privateKey  key.NodePrivate
	publicKey   key.NodePublic
	logf        logger.Logf
	memSys0     uint64 // runtime.MemStats.Sys at start (or early-ish)
	meshKey     key.DERPMesh
	limitedLogf logger.Logf
	metaCert    []byte // the encoded x509 cert to send after LetsEncrypt cert+intermediate
	dupPolicy   dupPolicy
	debug       bool
	localClient local.Client

	// trackSenderCardinality reports whether each client should keep a
	// HyperLogLog estimate of how many unique peers have sent it packets.
	// It is off by default and enabled by the TS_DERP_SENDER_CARDINALITY
	// environment variable, since the sketch costs memory and time on
	// the packet path for every connected client.
	trackSenderCardinality bool

	// onClientInfoForTest, if non-nil, is called with each connecting
	// client's key and ClientInfo. It is set (before the server accepts
	// any connections) via forTest.SetOnClientInfo and is nil outside
	// of tests.
	onClientInfoForTest func(key.NodePublic, derp.ClientInfo)

	// Counters:
	packetsSent, bytesSent     expvar.Int
	packetsRecv, bytesRecv     expvar.Int
	packetsRecvByKind          metrics.LabelMap
	packetsRecvDisco           *expvar.Int
	packetsRecvOther           *expvar.Int
	_                          align64
	packetsForwardedOut        expvar.Int
	packetsForwardedIn         expvar.Int
	peerGoneDisconnectedFrames expvar.Int // number of peer disconnected frames sent
	peerGoneNotHereFrames      expvar.Int // number of peer not here frames sent
	gotPing                    expvar.Int // number of ping frames from client
	sentPong                   expvar.Int // number of pong frames enqueued to client
	accepts                    expvar.Int
	curClients                 expvar.Int
	curClientsNotIdeal         expvar.Int
	curHomeClients             expvar.Int // ones with preferred
	dupClientKeys              expvar.Int // current number of public keys we have 2+ connections for
	dupClientConns             expvar.Int // current number of connections sharing a public key
	dupClientConnTotal         expvar.Int // total number of accepted connections when a dup key existed
	unknownFrames              expvar.Int
	homeMovesIn                expvar.Int // established clients announce home server moves in
	homeMovesOut               expvar.Int // established clients announce home server moves out
	multiForwarderCreated      expvar.Int
	multiForwarderDeleted      expvar.Int
	removePktForwardOther      expvar.Int
	sclientWriteTimeouts       expvar.Int
	avgQueueDuration           *uint64          // In milliseconds; accessed atomically
	tcpRtt                     metrics.LabelMap // histogram
	meshUpdateBatchSize        *metrics.Histogram
	meshUpdateLoopCount        *metrics.Histogram
	bufferedWriteFrames        *metrics.Histogram // how many frames (or groups of related frames) the writer writes per flush
	rateLimitPerClientWaited   expvar.Int         // number of times per-client rate limit caused a wait
	// TODO(illotum): add metrics for rate limited wait time, consider total seconds vs a histogram.

	// verifyClientsLocalTailscaled only accepts client connections to the DERP
	// server if the clientKey is a known peer in the network, as specified by a
	// running tailscaled's client's LocalAPI.
	verifyClientsLocalTailscaled bool

	verifyClientsURL         string
	verifyClientsURLFailOpen bool

	// disallowedAppNames, if non-nil, is the set of ClientInfo.AppName
	// values that are not allowed to connect. Mesh peers are exempt.
	disallowedAppNames set.Set[string]

	perClientSendQueueDepth int // Sets the client send queue depth for the server.
	tcpWriteTimeout         time.Duration
	clock                   tstime.Clock

	// sendQueueRingPool holds released pktQueue ring buffers, each a
	// *[]pkt of length perClientSendQueueDepth. Most clients are idle
	// at any given moment, so pooling the rings and allocating them
	// only while packets are actually queued keeps the standing
	// per-client memory low; see pktQueue.
	sendQueueRingPool sync.Pool

	// packetBufPools holds released packet payload buffers, one pool
	// per power-of-two size class from 1<<packetBufMinClass bytes up
	// to derp.MaxPacketSize. See getPacketBuf.
	packetBufPools [numPacketBufClasses]sync.Pool

	mu       syncs.Mutex // guards the following fields
	closed   bool
	netConns map[derp.Conn]chan struct{} // chan is closed when conn closes
	// clients holds the set of clients connected locally to this server,
	// keyed by their public key. Writes happen under Server.mu so they
	// stay consistent with clientsMesh, watchers, dup tracking, and the
	// numLocalClientKeys counter. Reads on the packet send hot path
	// are performed lock-free; see lookupDest.
	clients hashtriemap.HashTrieMap[key.NodePublic, *clientSet]
	// numLocalClientKeys is the number of distinct keys in clients.
	// HashTrieMap has no Len, so the count is tracked here.
	numLocalClientKeys int
	watchers           set.Set[*sclient] // mesh peers
	// clientsMesh tracks all clients in the cluster, both locally
	// and to mesh peers.  If the value is nil, that means the
	// peer is only local (and thus in the clients Map, but not
	// remote). If the value is non-nil, it's remote (+ maybe also
	// local).
	clientsMesh map[key.NodePublic]PacketForwarder
	// peerGoneWatchers is the set of watchers that subscribed to a
	// peer disconnecting from the region overall. When a peer
	// is gone from the region, we notify all of these watchers,
	// calling their funcs in a new goroutine.
	peerGoneWatchers map[key.NodePublic]set.HandleSet[func(key.NodePublic)]
	// maps from netip.AddrPort to a client's public key
	keyOfAddr  map[netip.AddrPort]key.NodePublic
	rateConfig RateConfig // per-client DERP frame rate limiting config
}

// clientSet represents 1 or more *sclients.
//
// In the common case, client should only have one connection to the
// DERP server for a given key. When they're connected multiple times,
// we record their set of connections in dupClientSet and keep their
// connections open to make them happy (to keep them from spinning,
// etc) and keep track of which is the latest connection. If only the last
// is sending traffic, that last one is the active connection and it
// gets traffic.  Otherwise, in the case of a cloned node key, the
// whole set of dups doesn't receive data frames.
//
// All methods should only be called while holding Server.mu.
//
// TODO(bradfitz): Issue 2746: in the future we'll send some sort of
// "health_error" frame to them that'll communicate to the end users
// that they cloned a device key, and we'll also surface it in the
// admin panel, etc.
type clientSet struct {
	// activeClient holds the currently active connection for the set. It's nil
	// if there are no connections or the connection is disabled.
	//
	activeClient atomic.Pointer[sclient]

	// dup is non-nil if there are multiple connections for the
	// public key. It's nil in the common case of only one
	// client being connected.
	//
	// dup is guarded by Server.mu.
	dup *dupClientSet
}

// Len returns the number of clients in s, which can be
// 0, 1 (the common case), or more (for buggy or transiently
// reconnecting clients).
func (s *clientSet) Len() int {
	if s.dup != nil {
		return len(s.dup.set)
	}
	if s.activeClient.Load() != nil {
		return 1
	}
	return 0
}

// ForeachClient calls f for each client in the set.
//
// The Server.mu must be held.
func (s *clientSet) ForeachClient(f func(*sclient)) {
	if s.dup != nil {
		for c := range s.dup.set {
			f(c)
		}
	} else if c := s.activeClient.Load(); c != nil {
		f(c)
	}
}

// A dupClientSet is a clientSet of more than 1 connection.
//
// This can occur in some reasonable cases (temporarily while users
// are changing networks) or in the case of a cloned key. In the
// cloned key case, both peers are speaking and the clients get
// disabled.
//
// All fields are guarded by Server.mu.
type dupClientSet struct {
	// set is the set of connected clients for sclient.key,
	// including the clientSet's active one.
	set set.Set[*sclient]

	// last is the most recent addition to set, or nil if the most
	// recent one has since disconnected and nobody else has sent
	// data since.
	last *sclient

	// sendHistory records which members of set have sent frames to
	// the DERP server, ordered from least to most recently active.
	// Each member appears at most once: recording a member that is
	// already present moves it to the end instead of appending a
	// duplicate. That keeps the slice bounded by the size of set.
	// Without the bound, two connections sharing a key and taking
	// turns sending could grow it without limit. When a member of
	// set is removed, it is also removed from sendHistory.
	sendHistory []*sclient
}

func (s *clientSet) pickActiveClient() *sclient {
	d := s.dup
	if d == nil {
		return s.activeClient.Load()
	}
	if d.last != nil && !d.last.isDisabled.Load() {
		return d.last
	}
	return nil
}

// removeClient removes c from s and reports whether it was in s
// to begin with.
func (s *dupClientSet) removeClient(c *sclient) bool {
	n := len(s.set)
	delete(s.set, c)
	if s.last == c {
		s.last = nil
	}
	if len(s.set) == n {
		return false
	}

	trim := s.sendHistory[:0]
	for _, v := range s.sendHistory {
		if s.set.Contains(v) && (len(trim) == 0 || trim[len(trim)-1] != v) {
			trim = append(trim, v)
		}
	}
	for i := len(trim); i < len(s.sendHistory); i++ {
		s.sendHistory[i] = nil
	}
	s.sendHistory = trim
	if s.last == nil && len(s.sendHistory) > 0 {
		s.last = s.sendHistory[len(s.sendHistory)-1]
	}
	return true
}

// PacketForwarder is something that can forward packets.
//
// It's mostly an interface for circular dependency reasons; the
// typical implementation is derphttp.Client. The other implementation
// is a multiForwarder, which this package creates as needed if a
// public key gets more than one PacketForwarder registered for it.
type PacketForwarder interface {
	// ForwardPacket forwards payload from src to dst. The payload is
	// only on loan for the duration of the call; the Server reuses
	// the memory once it returns.
	ForwardPacket(src, dst key.NodePublic, payload derp.LoanedBytes) error
	String() string
}

var packetsDropped = metrics.NewMultiLabelMap[dropReasonKindLabels](
	"derp_packets_dropped",
	"counter",
	"DERP packets dropped by reason and by kind")

var bytesDropped = metrics.NewMultiLabelMap[dropReasonKindLabels](
	"derp_bytes_dropped",
	"counter",
	"DERP bytes dropped by reason and by kind",
)

// New returns a new DERP server. It doesn't listen on its own.
// Connections are given to it via Server.Accept.
func New(privateKey key.NodePrivate, logf logger.Logf) *Server {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	s := &Server{
		debug:               envknob.Bool("DERP_DEBUG_LOGS"),
		privateKey:          privateKey,
		publicKey:           privateKey.Public(),
		logf:                logf,
		limitedLogf:         logger.RateLimitedFn(logf, 30*time.Second, 5, 100),
		packetsRecvByKind:   metrics.LabelMap{Label: "kind"},
		clientsMesh:         map[key.NodePublic]PacketForwarder{},
		netConns:            map[derp.Conn]chan struct{}{},
		memSys0:             ms.Sys,
		watchers:            set.Set[*sclient]{},
		peerGoneWatchers:    map[key.NodePublic]set.HandleSet[func(key.NodePublic)]{},
		avgQueueDuration:    new(uint64),
		tcpRtt:              metrics.LabelMap{Label: "le"},
		meshUpdateBatchSize: metrics.NewHistogram([]float64{0, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000}),
		meshUpdateLoopCount: metrics.NewHistogram([]float64{0, 1, 2, 5, 10, 20, 50, 100}),
		bufferedWriteFrames: metrics.NewHistogram([]float64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20, 25, 50, 100}),
		keyOfAddr:           map[netip.AddrPort]key.NodePublic{},
		clock:               tstime.StdClock{},
		tcpWriteTimeout:     DefaultTCPWiteTimeout,
	}
	s.trackSenderCardinality = envknob.Bool("TS_DERP_SENDER_CARDINALITY")
	s.initMetacert()
	s.packetsRecvDisco = s.packetsRecvByKind.Get(string(packetKindDisco))
	s.packetsRecvOther = s.packetsRecvByKind.Get(string(packetKindOther))

	genDroppedCounters()

	s.perClientSendQueueDepth = getPerClientSendQueueDepth()
	return s
}

// getSendQueueRing returns a send queue ring buffer from
// s.sendQueueRingPool, or a fresh one if the pool is empty.
func (s *Server) getSendQueueRing() *[]pkt {
	if ring, ok := s.sendQueueRingPool.Get().(*[]pkt); ok {
		return ring
	}
	ring := make([]pkt, s.perClientSendQueueDepth)
	return &ring
}

// Pooled packet payload buffers come in power-of-two size classes.
// Class i holds 1<<(packetBufMinClass+i) bytes, from 1 KiB up to
// derp.MaxPacketSize.
const (
	packetBufMinClass   = 10
	packetBufMaxClass   = 16
	numPacketBufClasses = packetBufMaxClass - packetBufMinClass + 1
)

// The largest size class must be exactly derp.MaxPacketSize or
// getPacketBuf could index past packetBufPools. This fails to compile
// if the two disagree in either direction.
var _ [0]struct{} = [1<<packetBufMaxClass - derp.MaxPacketSize]struct{}{}

// packetBufClass returns the index into Server.packetBufPools of the
// smallest size class that holds n bytes. ok is false if n is
// negative or exceeds derp.MaxPacketSize.
func packetBufClass(n int) (class int, ok bool) {
	if n < 0 || n > derp.MaxPacketSize {
		return 0, false
	}
	if n <= 1<<packetBufMinClass {
		return 0, true
	}
	return bits.Len(uint(n-1)) - packetBufMinClass, true
}

// getPacketBuf returns a packet payload buffer of length n from
// s.packetBufPools, or a fresh one if the pool for n's size class is
// empty. The caller must release it with putPacketBuf once the packet
// has been written, forwarded, or dropped. It panics if n is
// negative or exceeds derp.MaxPacketSize.
func (s *Server) getPacketBuf(n int) *[]byte {
	class, ok := packetBufClass(n)
	if !ok {
		panic(fmt.Sprintf("getPacketBuf: size %d out of range [0, %d]", n, derp.MaxPacketSize))
	}
	if buf, ok := s.packetBufPools[class].Get().(*[]byte); ok {
		*buf = (*buf)[:n]
		return buf
	}
	buf := make([]byte, n, 1<<(packetBufMinClass+class))
	return &buf
}

// putPacketBuf returns a buffer from getPacketBuf to its size class
// pool. A nil buf is a no-op, so callers can release a pkt regardless
// of whether its bytes came from the pool. It panics if buf's
// capacity is not one of the pool's size classes, which means it
// didn't come from getPacketBuf.
func (s *Server) putPacketBuf(buf *[]byte) {
	if buf == nil {
		return
	}
	c := cap(*buf)
	class, ok := packetBufClass(c)
	if !ok || 1<<(packetBufMinClass+class) != c {
		panic(fmt.Sprintf("putPacketBuf: cap %d is not a pool size class", c))
	}
	s.packetBufPools[class].Put(buf)
}

func genDroppedCounters() {
	initMetrics := func(reason dropReason) {
		packetsDropped.Add(dropReasonKindLabels{
			Kind:   string(packetKindDisco),
			Reason: string(reason),
		}, 0)
		packetsDropped.Add(dropReasonKindLabels{
			Kind:   string(packetKindOther),
			Reason: string(reason),
		}, 0)
		bytesDropped.Add(dropReasonKindLabels{
			Kind:   string(packetKindDisco),
			Reason: string(reason),
		}, 0)
		bytesDropped.Add(dropReasonKindLabels{
			Kind:   string(packetKindOther),
			Reason: string(reason),
		}, 0)
	}
	getMetrics := func(reason dropReason) []expvar.Var {
		return []expvar.Var{
			packetsDropped.Get(dropReasonKindLabels{
				Kind:   string(packetKindDisco),
				Reason: string(reason),
			}),
			packetsDropped.Get(dropReasonKindLabels{
				Kind:   string(packetKindOther),
				Reason: string(reason),
			}),
			bytesDropped.Get(dropReasonKindLabels{
				Kind:   string(packetKindDisco),
				Reason: string(reason),
			}),
			bytesDropped.Get(dropReasonKindLabels{
				Kind:   string(packetKindOther),
				Reason: string(reason),
			}),
		}
	}

	dropReasons := []dropReason{
		dropReasonUnknownDest,
		dropReasonUnknownDestOnFwd,
		dropReasonGoneDisconnected,
		dropReasonQueueHead,
		dropReasonQueueTail,
		dropReasonWriteError,
		dropReasonDupClient,
	}

	for _, dr := range dropReasons {
		initMetrics(dr)
		m := getMetrics(dr)
		if len(m) != 4 {
			panic("dropReason metrics out of sync")
		}

		for _, v := range m {
			if v == nil {
				panic("dropReason metrics out of sync")
			}
		}
	}
}

// SetMesh sets the pre-shared key that regional DERP servers used to mesh
// amongst themselves.
//
// It must be called before serving begins.
func (s *Server) SetMeshKey(v string) error {
	k, err := key.ParseDERPMesh(v)
	if err != nil {
		return err
	}
	s.meshKey = k
	return nil
}

// SetVerifyClients sets whether this DERP server verifies clients through tailscaled.
//
// It must be called before serving begins.
func (s *Server) SetVerifyClient(v bool) {
	s.verifyClientsLocalTailscaled = v
}

// SetVerifyClientURL sets the admission controller URL to use for verifying clients.
// If empty, all clients are accepted (unless restricted by SetVerifyClient checking
// against tailscaled).
func (s *Server) SetVerifyClientURL(v string) {
	s.verifyClientsURL = v
}

// SetVerifyClientURLFailOpen sets whether to allow clients to connect if the
// admission controller URL is unreachable.
func (s *Server) SetVerifyClientURLFailOpen(v bool) {
	s.verifyClientsURLFailOpen = v
}

// SetDisallowedAppNames sets the list of client app names (as advertised
// in their ClientInfo.AppName) that are not allowed to connect.
// Trusted mesh peers are exempt.
//
// It must be called before serving begins.
func (s *Server) SetDisallowedAppNames(names []string) {
	s.disallowedAppNames = set.Of(names...)
}

// SetTailscaledSocketPath sets the unix socket path to use to talk to
// tailscaled if client verification is enabled.
//
// If unset or set to the empty string, the default path for the operating
// system is used.
func (s *Server) SetTailscaledSocketPath(path string) {
	s.localClient.Socket = path
	s.localClient.UseSocketOnly = path != ""
}

// SetTCPWriteTimeout sets the timeout for writing to connected clients.
// This timeout does not apply to mesh connections.
// Defaults to 2 seconds.
func (s *Server) SetTCPWriteTimeout(d time.Duration) {
	s.tcpWriteTimeout = d
}

// minRateLimitTokenBucketSize represents the minimum size of a token bucket
// applied for the purposes of rate limiting a DERP connection per received DERP
// frame.
//
// Note: The DERP protocol supports frames larger than this ([math.MaxUint32] length),
// but a [derp.FrameSendPacket] cannot exceed this value, which is what we optimize
// our token bucket calls for.
const minRateLimitTokenBucketSize = derp.MaxPacketSize + derp.KeyLen

// RateConfig is a JSON-serializable configuration for rate limits. Values are
// in bytes.
type RateConfig struct {
	// PerClientRateLimitBytesPerSec represents the per-client
	// rate limit in bytes per second. A zero value disables all rate limiting.
	PerClientRateLimitBytesPerSec uint64 `json:",omitzero"`
	// PerClientRateBurstBytes represents the per-client token bucket depth,
	// or burst, in bytes. Any value lower than [minRateLimitTokenBucketSize]
	// will be increased to [minRateLimitTokenBucketSize] before application. Only
	// relevant if PerClientRateLimitBytesPerSec is nonzero.
	PerClientRateBurstBytes uint64 `json:",omitzero"`
}

// LoadRateConfig reads and JSON-unmarshals a [RateConfig] from the file at path.
func LoadRateConfig(path string) (RateConfig, error) {
	if path == "" {
		return RateConfig{}, errors.New("rate config path is empty")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return RateConfig{}, fmt.Errorf("error reading rate config: %w", err)
	}
	var rc RateConfig
	if err := json.Unmarshal(b, &rc); err != nil {
		return RateConfig{}, fmt.Errorf("error parsing rate config: %w", err)
	}
	return rc, nil
}

// LoadAndApplyRateConfig reads a [RateConfig] from the file at path and
// applies it to the server via [Server.UpdateRateLimits].
func (s *Server) LoadAndApplyRateConfig(path string) error {
	rc, err := LoadRateConfig(path)
	if err != nil {
		return err
	}
	applied := s.UpdateRateLimits(rc)
	s.logf("rate config applied: client-rate=%d bytes/sec, client-burst=%d bytes",
		applied.PerClientRateLimitBytesPerSec, applied.PerClientRateBurstBytes)
	return nil
}

// UpdateRateLimits sets the receive rate limits, updating all existing client
// connections. It returns the applied config, which may differ from rc. If the
// per-client rate limits is 0, rate limiting is disabled. Mesh peers are always
// exempt from rate limiting.
func (s *Server) UpdateRateLimits(rc RateConfig) (applied RateConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rc.PerClientRateLimitBytesPerSec == 0 {
		// all rate limiting is disabled
		rc = RateConfig{}
	} else {
		rc.PerClientRateBurstBytes = max(rc.PerClientRateBurstBytes, minRateLimitTokenBucketSize)
	}
	s.rateConfig = rc
	for _, cs := range s.clients.All() {
		cs.ForeachClient(func(c *sclient) {
			c.setRateLimit(rc.PerClientRateLimitBytesPerSec, rc.PerClientRateBurstBytes)
		})
	}
	return rc
}

// HasMeshKey reports whether the server is configured with a mesh key.
func (s *Server) HasMeshKey() bool { return !s.meshKey.IsZero() }

// MeshKey returns the configured mesh key, if any.
func (s *Server) MeshKey() key.DERPMesh { return s.meshKey }

// PrivateKey returns the server's private key.
func (s *Server) PrivateKey() key.NodePrivate { return s.privateKey }

// PublicKey returns the server's public key.
func (s *Server) PublicKey() key.NodePublic { return s.publicKey }

// Close closes the server and waits for the connections to disconnect.
func (s *Server) Close() error {
	s.mu.Lock()
	wasClosed := s.closed
	s.closed = true
	s.mu.Unlock()
	if wasClosed {
		return nil
	}

	var closedChs []chan struct{}

	s.mu.Lock()
	for nc, closed := range s.netConns {
		nc.Close()
		closedChs = append(closedChs, closed)
	}
	s.mu.Unlock()

	for _, closed := range closedChs {
		<-closed
	}

	return nil
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// IsClientConnectedForTest reports whether the client with specified key is connected.
// This is used in tests to verify that nodes are connected.
func (s *Server) IsClientConnectedForTest(k key.NodePublic) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.clients.Load(k)
	if !ok {
		return false
	}
	return x.activeClient.Load() != nil
}

// Accept adds a new connection to the server and serves it.
//
// The provided bufio ReadWriter must be already connected to nc.
// brw.Writer may be nil, in which case Accept writes to nc through
// pooled buffers held only during writes, which keeps the per-client
// standing memory lower for mostly idle connections.
// Accept blocks until the Server is closed or the connection closes
// on its own.
//
// Accept closes nc.
func (s *Server) Accept(ctx context.Context, nc derp.Conn, brw *bufio.ReadWriter, remoteAddr string) {
	closed := make(chan struct{})

	s.mu.Lock()
	s.accepts.Add(1)             // while holding s.mu for connNum read on next line
	connNum := s.accepts.Value() // expvar sadly doesn't return new value on Add(1)
	s.netConns[nc] = closed
	s.mu.Unlock()

	defer func() {
		nc.Close()
		close(closed)

		s.mu.Lock()
		delete(s.netConns, nc)
		s.mu.Unlock()
	}()

	if err := s.accept(ctx, nc, brw, remoteAddr, connNum); err != nil && !s.isClosed() {
		s.logf("derp: %s: %v", remoteAddr, err)
	}
}

// initMetacert initialized s.metaCert with a self-signed x509 cert
// encoding this server's public key and protocol version. cmd/derper
// then sends this after the Let's Encrypt leaf + intermediate certs
// after the ServerHello (encrypted in TLS 1.3, not that it matters
// much).
//
// Then the client can save a round trip getting that and can start
// speaking DERP right away. (We don't use ALPN because that's sent in
// the clear and we're being paranoid to not look too weird to any
// middleboxes, given that DERP is an ultimate fallback path). But
// since the post-ServerHello certs are encrypted we can have the
// client also use them as a signal to be able to start speaking DERP
// right away, starting with its identity proof, encrypted to the
// server's public key.
//
// This RTT optimization fails where there's a corp-mandated
// TLS proxy with corp-mandated root certs on employee machines and
// and TLS proxy cleans up unnecessary certs. In that case we just fall
// back to the extra RTT.
func (s *Server) initMetacert() {
	pub, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(derp.ProtocolVersion),
		Subject: pkix.Name{
			CommonName: derpconst.MetaCertCommonNamePrefix + s.publicKey.UntypedHexString(),
		},
		// Windows requires NotAfter and NotBefore set:
		NotAfter:  s.clock.Now().Add(30 * 24 * time.Hour),
		NotBefore: s.clock.Now().Add(-30 * 24 * time.Hour),
		// Per https://github.com/golang/go/issues/51759#issuecomment-1071147836,
		// macOS requires BasicConstraints when subject == issuer:
		BasicConstraintsValid: true,
	}
	cert, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		log.Fatalf("CreateCertificate: %v", err)
	}
	s.metaCert = cert
}

// MetaCert returns the server metadata cert that can be sent by the
// TLS server to let the client skip a round trip during start-up.
func (s *Server) MetaCert() []byte { return s.metaCert }

// ModifyTLSConfigToAddMetaCert modifies c.GetCertificate to make
// it append s.MetaCert to the returned certificates. The certificate
// returned by the underlying GetCertificate is not mutated; a copy
// with the meta cert appended is returned instead.
//
// It panics if c or c.GetCertificate is nil.
func (s *Server) ModifyTLSConfigToAddMetaCert(c *tls.Config) {
	getCert := c.GetCertificate
	if getCert == nil {
		panic("c.GetCertificate is nil")
	}
	c.GetCertificate = func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := getCert(hi)
		if err != nil {
			return nil, err
		}
		if cert == nil {
			// Underlying GetCertificate returned (nil, nil) to signal
			// fallback to Config.Certificates et al. Pass that through.
			return nil, nil
		}
		// Don't mutate the *tls.Certificate pointed to by cert: the
		// underlying GetCertificate implementation may return a shared
		// cached value. Return a shallow copy with the meta cert
		// appended to a freshly allocated chain slice.
		certCopy := *cert
		certCopy.Certificate = append(slices.Clip(cert.Certificate), s.MetaCert())
		return &certCopy, nil
	}
}

// registerClient notes that client c is now authenticated and ready for packets.
//
// If c.key is connected more than once, the earlier connection(s) are
// placed in a non-active state where we read from them (primarily to
// observe EOFs/timeouts) but won't send them frames on the assumption
// that they're dead.
func (s *Server) registerClient(c *sclient) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c.setRateLimit(s.rateConfig.PerClientRateLimitBytesPerSec, s.rateConfig.PerClientRateBurstBytes)

	cs, ok := s.clients.Load(c.key)
	if !ok {
		c.debugLogf("register single client")
		cs = &clientSet{}
		s.clients.Store(c.key, cs)
		s.numLocalClientKeys++
	}
	was := cs.activeClient.Load()
	if was == nil {
		// Common case.
	} else {
		was.isDup.Store(true)
		c.isDup.Store(true)
	}

	dup := cs.dup
	if dup == nil && was != nil {
		s.dupClientKeys.Add(1)
		s.dupClientConns.Add(2) // both old and new count
		s.dupClientConnTotal.Add(1)
		dup = &dupClientSet{
			set:         set.Of(c, was),
			last:        c,
			sendHistory: []*sclient{was},
		}
		cs.dup = dup
		c.debugLogf("register duplicate client")
	} else if dup != nil {
		s.dupClientConns.Add(1)     // the gauge
		s.dupClientConnTotal.Add(1) // the counter
		dup.set.Add(c)
		dup.last = c
		dup.sendHistory = append(dup.sendHistory, c)
		c.debugLogf("register another duplicate client")
	}

	cs.activeClient.Store(c)

	if _, ok := s.clientsMesh[c.key]; !ok {
		s.clientsMesh[c.key] = nil // just for varz of total users in cluster
	}
	s.keyOfAddr[c.remoteIPPort] = c.key
	s.curClients.Add(1)
	if c.isNotIdealConn {
		s.curClientsNotIdeal.Add(1)
	}
	s.broadcastPeerStateChangeLocked(c.key, c.remoteIPPort, c.presentFlags(), c.info.AppName, true)
}

// broadcastPeerStateChangeLocked enqueues a message to all watchers
// (other DERP nodes in the region, or trusted clients) that peer's
// presence changed.
//
// s.mu must be held.
func (s *Server) broadcastPeerStateChangeLocked(peer key.NodePublic, ipPort netip.AddrPort, flags derp.PeerPresentFlags, appName string, present bool) {
	for w := range s.watchers {
		w.peerStateChange = append(w.peerStateChange, peerConnState{
			peer:    peer,
			present: present,
			ipPort:  ipPort,
			flags:   flags,
			appName: appName,
		})
		w.requestMeshUpdate()
	}
}

// unregisterClient removes a client from the server.
func (s *Server) unregisterClient(c *sclient) {
	s.mu.Lock()
	defer s.mu.Unlock()

	set, ok := s.clients.Load(c.key)
	if !ok {
		c.logf("[unexpected]; clients map is empty")
		return
	}

	dup := set.dup
	if dup == nil {
		// The common case.
		cur := set.activeClient.Load()
		if cur == nil {
			c.logf("[unexpected]; active client is nil")
			return
		}
		if cur != c {
			c.logf("[unexpected]; active client is not c")
			return
		}
		c.debugLogf("removed connection")
		set.activeClient.Store(nil)
		if s.clients.CompareAndDelete(c.key, set) {
			s.numLocalClientKeys--
		}
		if v, ok := s.clientsMesh[c.key]; ok && v == nil {
			delete(s.clientsMesh, c.key)
			s.notePeerGoneFromRegionLocked(c.key)
		}
		s.broadcastPeerStateChangeLocked(c.key, netip.AddrPort{}, 0, "", false)
	} else {
		c.debugLogf("removed duplicate client")
		if dup.removeClient(c) {
			s.dupClientConns.Add(-1)
		} else {
			c.logf("[unexpected]; dup client set didn't shrink")
		}
		if dup.set.Len() == 1 {
			// If we drop down to one connection, demote it down
			// to a regular single client (a nil dup set).
			set.dup = nil
			s.dupClientConns.Add(-1) // again; for the original one's
			s.dupClientKeys.Add(-1)
			var remain *sclient
			for remain = range dup.set {
				break
			}
			if remain == nil {
				panic("unexpected nil remain from single element dup set")
			}
			remain.isDisabled.Store(false)
			remain.isDup.Store(false)
			set.activeClient.Store(remain)
		} else {
			// Still a duplicate. Pick a winner.
			set.activeClient.Store(set.pickActiveClient())
		}
	}

	if c.canMesh {
		delete(s.watchers, c)
	}

	delete(s.keyOfAddr, c.remoteIPPort)

	s.curClients.Add(-1)
	if c.preferred {
		s.curHomeClients.Add(-1)
	}
	if c.isNotIdealConn {
		s.curClientsNotIdeal.Add(-1)
	}
}

// addPeerGoneFromRegionWatcher adds a function to be called when peer is gone
// from the region overall. It returns a handle that can be used to remove the
// watcher later.
//
// The provided f func is usually [sclient.onPeerGoneFromRegion], added by
// [sclient.noteSendFromSrc]; this func doesn't take a whole *sclient to make it
// clear what has access to what.
func (s *Server) addPeerGoneFromRegionWatcher(peer key.NodePublic, f func(key.NodePublic)) set.Handle {
	s.mu.Lock()
	defer s.mu.Unlock()
	hset, ok := s.peerGoneWatchers[peer]
	if !ok {
		hset = set.HandleSet[func(key.NodePublic)]{}
		s.peerGoneWatchers[peer] = hset
	}
	return hset.Add(f)
}

// removePeerGoneFromRegionWatcher removes a peer watcher previously added by
// addPeerGoneFromRegionWatcher, using the handle returned by
// addPeerGoneFromRegionWatcher.
func (s *Server) removePeerGoneFromRegionWatcher(peer key.NodePublic, h set.Handle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hset, ok := s.peerGoneWatchers[peer]
	if !ok {
		return
	}
	delete(hset, h)
	if len(hset) == 0 {
		delete(s.peerGoneWatchers, peer)
	}
}

// notePeerGoneFromRegionLocked sends peerGone frames to parties that
// key has sent to previously (whether those sends were from a local
// client or forwarded).  It must only be called after the key has
// been removed from clientsMesh.
func (s *Server) notePeerGoneFromRegionLocked(key key.NodePublic) {
	if _, ok := s.clientsMesh[key]; ok {
		panic("usage")
	}

	// Find still-connected peers and either notify that we've gone away
	// so they can drop their route entries to us (issue 150)
	// or move them over to the active client (in case a replaced client
	// connection is being unregistered).
	//
	// The watchers (sclient.onPeerGoneFromRegion) don't block, so
	// they run inline, holding s.mu.
	set := s.peerGoneWatchers[key]
	for _, f := range set {
		f(key)
	}
	delete(s.peerGoneWatchers, key)
}

// requestPeerGoneWriteLimited sends a request to write a "peer gone"
// frame, but only in reply to a disco packet, and only if we haven't
// sent one recently.
func (c *sclient) requestPeerGoneWriteLimited(peer key.NodePublic, contents []byte, reason derp.PeerGoneReasonType) {
	if disco.LooksLikeDiscoWrapper(contents) != true {
		return
	}

	if c.peerGoneLim.Allow() {
		c.requestPeerGoneWrite(peer, reason)
	}
}

func (s *Server) addWatcher(c *sclient) {
	if !c.canMesh {
		panic("invariant: addWatcher called without permissions")
	}

	if c.key == s.publicKey {
		// We're connecting to ourself. Do nothing.
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Queue messages for each already-connected client.
	for peer, clientSet := range s.clients.All() {
		ac := clientSet.activeClient.Load()
		if ac == nil {
			continue
		}
		c.peerStateChange = append(c.peerStateChange, peerConnState{
			peer:    peer,
			present: true,
			ipPort:  ac.remoteIPPort,
			flags:   ac.presentFlags(),
			appName: ac.info.AppName,
		})
	}

	// And enroll the watcher in future updates (of both
	// connections & disconnections).
	s.watchers.Add(c)

	c.requestMeshUpdate()
}

func (s *Server) accept(ctx context.Context, nc derp.Conn, brw *bufio.ReadWriter, remoteAddr string, connNum int64) error {
	br := brw.Reader
	nc.SetDeadline(time.Now().Add(10 * time.Second))
	bw := &lazyBufioWriter{w: nc, lbw: brw.Writer}
	if err := s.sendServerKey(bw); err != nil {
		return fmt.Errorf("send server key: %v", err)
	}
	nc.SetDeadline(time.Now().Add(10 * time.Second))
	clientKey, clientInfo, err := s.recvClientKey(br)
	if err != nil {
		return fmt.Errorf("receive client key: %v", err)
	}

	remoteIPPort, _ := netip.ParseAddrPort(remoteAddr)
	if err := s.verifyClient(ctx, clientKey, clientInfo, remoteIPPort.Addr()); err != nil {
		return fmt.Errorf("client %v rejected: %v", clientKey, err)
	}

	// At this point we trust the client so we don't time out.
	nc.SetDeadline(time.Time{})

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	c := &sclient{
		connNum:        connNum,
		s:              s,
		key:            clientKey,
		nc:             nc,
		br:             br,
		bw:             bw,
		logf:           logger.WithPrefix(s.logf, fmt.Sprintf("derp client %v%s: ", remoteAddr, clientKey.ShortString())),
		ctx:            ctx,
		remoteIPPort:   remoteIPPort,
		connectedAt:    s.clock.Now(),
		canMesh:        s.isMeshPeer(clientInfo),
		isNotIdealConn: IdealNodeContextKey.Value(ctx) != "",
		peerGoneLim:    rate.NewLimiter(rate.Every(time.Second), 3),
	}
	c.runWriterFunc = c.runWriter // allocate the method value once, not per wake

	if clientInfo != nil {
		c.info = *clientInfo
		if envknob.Bool("DERP_PROBER_DEBUG_LOGS") && clientInfo.IsProber {
			c.debug = true
		}
	}
	if s.debug {
		c.debug = true
	}
	if f := s.onClientInfoForTest; f != nil {
		f(clientKey, c.info)
	}

	// Until run takes over, this goroutine is the client's writer (see
	// wakeWriter): the ServerInfo frame goes out on c.bw below, and
	// work that other goroutines publish for the client once it's
	// registered (packets, peer gone notices) waits until then.
	c.writerState.Store(packWriterState(writerRunning, 0))

	s.registerClient(c)
	defer s.unregisterClient(c)

	err = s.sendServerInfo(c.bw, clientKey)
	if err != nil {
		c.writerState.Store(packWriterState(writerStopped, 0))
		return fmt.Errorf("send server info: %v", err)
	}
	// Write anything published during the handshake, then park.
	c.runWriter()

	return c.run(ctx)
}

// debugLogf logs only when the server has debug logging enabled.
// Callers on the per-packet path must check s.debug themselves first,
// since Go evaluates and boxes the arguments before the call.
func (s *Server) debugLogf(format string, v ...any) {
	if s.debug {
		s.logf(format, v...)
	}
}

// run serves the client until there's an error.
// If the client hangs up or the server is closed, run returns nil, otherwise run returns an error.
//
// run is the client's reader goroutine, and the only goroutine the
// connection pins while idle. Writes to the client happen on a writer
// goroutine that exists only while there is something to write; see
// [sclient.wakeWriter].
func (c *sclient) run(ctx context.Context) error {
	defer c.stopWriter()

	// Allow disabling RTT stats collection to reduce
	// CPU and syscalls on servers with high connection
	// counts
	if !envknob.Bool("TS_DERP_DISABLE_RTT_STATS") {
		c.startStatsLoop(ctx)
	}

	c.keepAliveTimer = c.s.clock.AfterFunc(keepAliveInterval(), c.onKeepAliveTimer)

	for {
		ft, fl, err := derp.ReadFrameHeader(c.br)
		if c.debug {
			c.debugLogf("read frame type %d len %d err %v", ft, fl, err)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				c.debugLogf("read EOF")
				return nil
			}
			if c.s.isClosed() {
				c.logf("closing; server closed")
				return nil
			}
			return fmt.Errorf("client %s: readFrameHeader: %w", c.key.ShortString(), err)
		}
		// Rate-limit by DERP frame length (fl), which excludes TLS protocol and
		// DERP frame length field overheads.
		// Note: meshed clients are exempt from rate limits.
		if err := c.rateLimit(int(fl)); err != nil {
			return err // context canceled, connection closing
		}

		c.s.noteClientActivity(c)
		switch ft {
		case derp.FrameNotePreferred:
			err = c.handleFrameNotePreferred(ft, fl)
		case derp.FrameSendPacket:
			err = c.handleFrameSendPacket(ft, fl)
		case derp.FrameForwardPacket:
			err = c.handleFrameForwardPacket(ft, fl)
		case derp.FrameWatchConns:
			err = c.handleFrameWatchConns(ft, fl)
		case derp.FrameClosePeer:
			err = c.handleFrameClosePeer(ft, fl)
		case derp.FramePing:
			err = c.handleFramePing(ft, fl)
		default:
			err = c.handleUnknownFrame(ft, fl)
		}
		if err != nil {
			return err
		}
	}
}

// maxUnknownFrameLen is the largest declared length of an unknown frame type
// that the server is willing to read and discard. It is the size of the
// largest frame a regular (non-mesh) client can send today, a
// [derp.FrameSendPacket] with a full-size packet, which leaves room for
// future frame types without letting a client make the server drain an
// arbitrary amount of data.
//
// It must not exceed [minRateLimitTokenBucketSize]: [sclient.rateLimit] charges
// at most that many tokens per frame on the assumption that any larger frame
// closes the connection, and this bound is what makes that true for unknown
// frame types.
const maxUnknownFrameLen = derp.MaxPacketSize + derp.KeyLen

// handleUnknownFrame discards the body of a frame of a type the server doesn't
// know, so that newer clients can send new frame types to older servers. It
// closes the connection if the frame is unreasonably large, since otherwise a
// client could have the server read (and be charged rate-limit tokens for)
// far less than the frame's actual length.
func (c *sclient) handleUnknownFrame(ft derp.FrameType, fl uint32) error {
	if fl > maxUnknownFrameLen {
		return fmt.Errorf("unknown frame type %d too large: %d bytes", ft, fl)
	}
	_, err := io.CopyN(io.Discard, c.br, int64(fl))
	return err
}

func (c *sclient) handleFrameNotePreferred(ft derp.FrameType, fl uint32) error {
	if fl != 1 {
		return fmt.Errorf("frameNotePreferred wrong size")
	}
	v, err := c.br.ReadByte()
	if err != nil {
		return fmt.Errorf("frameNotePreferred ReadByte: %v", err)
	}
	c.setPreferred(v != 0)
	return nil
}

func (c *sclient) handleFrameWatchConns(ft derp.FrameType, fl uint32) error {
	if fl != 0 {
		return fmt.Errorf("handleFrameWatchConns wrong size")
	}
	if !c.canMesh {
		return fmt.Errorf("insufficient permissions")
	}
	c.s.addWatcher(c)
	return nil
}

func (c *sclient) handleFramePing(ft derp.FrameType, fl uint32) error {
	c.s.gotPing.Add(1)
	var m derp.PingMessage
	if fl < uint32(len(m)) {
		return fmt.Errorf("short ping: %v", fl)
	}
	if fl > 1000 {
		// unreasonably extra large. We leave some extra
		// space for future extensibility, but not too much.
		return fmt.Errorf("ping body too large: %v", fl)
	}
	if _, err := bufiox.ReadFull(c.br, m[:]); err != nil {
		return err
	}
	var err error
	if extra := int64(fl) - int64(len(m)); extra > 0 {
		_, err = io.CopyN(io.Discard, c.br, extra)
	}

	c.queuePong([8]byte(m))
	return err
}

func (c *sclient) handleFrameClosePeer(ft derp.FrameType, fl uint32) error {
	if fl != derp.KeyLen {
		return fmt.Errorf("handleFrameClosePeer wrong size")
	}
	if !c.canMesh {
		return fmt.Errorf("insufficient permissions")
	}
	var targetKey key.NodePublic
	if err := targetKey.ReadRawWithoutAllocating(c.br); err != nil {
		return err
	}
	s := c.s

	s.mu.Lock()
	defer s.mu.Unlock()

	if set, ok := s.clients.Load(targetKey); ok {
		if set.Len() == 1 {
			c.logf("frameClosePeer closing peer %x", targetKey)
		} else {
			c.logf("frameClosePeer closing peer %x (%d connections)", targetKey, set.Len())
		}
		set.ForeachClient(func(target *sclient) {
			go target.nc.Close()
		})
	} else {
		c.logf("frameClosePeer failed to find peer %x", targetKey)
	}

	return nil
}

// handleFrameForwardPacket reads a "forward packet" frame from the client
// (which must be a trusted client, a peer in our mesh).
func (c *sclient) handleFrameForwardPacket(_ derp.FrameType, fl uint32) error {
	if !c.canMesh {
		return fmt.Errorf("insufficient permissions")
	}
	s := c.s

	srcKey, dstKey, buf, err := s.recvForwardPacket(c.br, fl)
	if err != nil {
		return fmt.Errorf("client %v: recvForwardPacket: %v", c.key, err)
	}
	contents := *buf
	s.packetsForwardedIn.Add(1)

	// Use the same lock-free fast path as the local send path. The mesh
	// forwarder return is intentionally discarded: we never re-forward an
	// already-forwarded packet.
	dst, _, dstLen := c.lookupDest(dstKey)

	if dst == nil {
		reason := dropReasonUnknownDestOnFwd
		if dstLen > 1 {
			reason = dropReasonDupClient
		} else {
			c.requestPeerGoneWriteLimited(dstKey, contents, derp.PeerGoneReasonNotHere)
		}
		s.recordDrop(contents, srcKey, dstKey, reason)
		s.putPacketBuf(buf)
		return nil
	}

	if dst.debug {
		dst.debugLogf("received forwarded packet from %s via %s", srcKey.ShortString(), c.key.ShortString())
	}

	return c.sendPkt(dst, pkt{
		bs:         contents,
		buf:        buf,
		enqueuedAt: c.s.clock.Now(),
		src:        srcKey,
	})
}

// lookupDest returns the local client, mesh forwarder, or duplicate-client
// count for dst. dstLen is only meaningful when the returned local client is
// nil; when a local client is returned, dstLen is just non-zero.
//
// The fast path reads Server.clients lock-free: if a *clientSet is present
// for dst and has an active client, we return that without taking Server.mu.
// Misses, inactive clientSets, duplicate-client accounting, and mesh
// forwarder lookups fall through to a slow path under Server.mu. At most
// one local client and PacketForwarder can be non-nil: local clients win
// over mesh forwarding, and mesh forwarding is considered only when there
// is no local clientSet.
func (c *sclient) lookupDest(dst key.NodePublic) (_ *sclient, fwd PacketForwarder, dstLen int) {
	s := c.s
	if set, ok := s.clients.Load(dst); ok {
		if dst := set.activeClient.Load(); dst != nil {
			return dst, nil, 1
		}
	}
	// Slow path: no active local client. Take Server.mu to read the
	// duplicate-client count and clientsMesh consistently.
	s.mu.Lock()
	defer s.mu.Unlock()
	if set, ok := s.clients.Load(dst); ok {
		if dst := set.activeClient.Load(); dst != nil {
			return dst, nil, 1
		}
		dstLen = set.Len()
	}
	if dstLen < 1 {
		fwd = s.clientsMesh[dst]
	}
	return nil, fwd, dstLen
}

// handleFrameSendPacket reads a "send packet" frame from the client.
func (c *sclient) handleFrameSendPacket(_ derp.FrameType, fl uint32) error {
	s := c.s

	dstKey, buf, err := s.recvPacket(c.br, fl)
	if err != nil {
		return fmt.Errorf("client %v: recvPacket: %v", c.key, err)
	}
	contents := *buf

	dst, fwd, dstLen := c.lookupDest(dstKey)

	if dst == nil {
		defer s.putPacketBuf(buf)
		if fwd != nil {
			s.packetsForwardedOut.Add(1)
			err := fwd.ForwardPacket(c.key, dstKey, derp.LoanBytes(contents))
			if c.debug {
				c.debugLogf("SendPacket for %s, forwarding via %s: %v", dstKey.ShortString(), fwd, err)
			}
			if err != nil {
				// TODO:
				return nil
			}
			return nil
		}
		reason := dropReasonUnknownDest
		if dstLen > 1 {
			reason = dropReasonDupClient
		} else {
			c.requestPeerGoneWriteLimited(dstKey, contents, derp.PeerGoneReasonNotHere)
		}
		s.recordDrop(contents, c.key, dstKey, reason)
		if c.debug {
			c.debugLogf("SendPacket for %s, dropping with reason=%s", dstKey.ShortString(), reason)
		}
		return nil
	}
	if c.debug {
		c.debugLogf("SendPacket for %s, sending directly", dstKey.ShortString())
	}

	p := pkt{
		bs:         contents,
		buf:        buf,
		enqueuedAt: c.s.clock.Now(),
		src:        c.key,
	}
	return c.sendPkt(dst, p)
}

// setRateLimit updates the receive rate limiter. When bytesPerSec is 0, or the
// client is a mesh peer, the limiter is set to nil so that [sclient.rateLimit] is a no-op.
func (c *sclient) setRateLimit(bytesPerSec, burst uint64) {
	if c.canMesh || bytesPerSec == 0 {
		c.recvLim.Store(nil)
		return
	}
	limiter := xrate.NewLimiter(xrate.Limit(bytesPerSec), int(burst))
	c.recvLim.Store(limiter)
}

// rateLimitWait is a reimplementation of [xrate.Limiter.WaitN] via [xrate.Limiter.ReserveN].
// It returns the duration waited for tokens to become available.
func rateLimitWait(ctx context.Context, lim *xrate.Limiter, n int, now time.Time, newTimer func(time.Duration) (<-chan time.Time, func() bool)) (time.Duration, error) {
	r := lim.ReserveN(now, n)
	if !r.OK() {
		return 0, fmt.Errorf("rate: Wait(n=%d) exceeds limiter's burst %d", n, lim.Burst())
	}
	delay := r.DelayFrom(now)
	if delay == 0 {
		return 0, nil
	}
	ch, stop := newTimer(delay)
	defer stop()
	select {
	case <-ch:
		// Note: We return the predicted delay as wall-clock duration. May be not the same.
		return delay, nil
	case <-ctx.Done():
		r.Cancel()
		return 0, ctx.Err()
	}
}

// rateLimit applies the receive rate limit.
// By limiting here we prevent reading from the buffered reader
// [sclient.br] if the limit has been exceeded. Any reads done here provide space
// within the buffered reader to fill back in with data from
// the TCP socket. Pacing reads acts as a form of natural
// backpressure via TCP flow control.
// When rate limiting is disabled or the client is a mesh peer, recvLim is nil
// and this is a no-op.
func (c *sclient) rateLimit(n int) error {
	if lim := c.recvLim.Load(); lim != nil {
		newTimer := func(d time.Duration) (<-chan time.Time, func() bool) {
			tc, ch := c.s.clock.NewTimer(d)
			return ch, tc.Stop
		}
		// If n exceeds the capacity of the bucket, then WaitN will return
		// an error and consume zero tokens. To prevent this, clamp n to
		// [minRateLimitTokenBucketSize].
		//
		// While we could call WaitN multiple times and/or more precisely for
		// lim.Burst(), it's better to return early as a larger DERP frame:
		//   1. is unexpected
		//   2. is only partially read off the socket (bufio)
		//   3. would cause the connection to close shortly after rate limiting, anyway.
		clampedN := min(n, minRateLimitTokenBucketSize)
		now := c.s.clock.Now()
		var (
			durationWaited time.Duration
			err            error
		)
		durationWaited, err = rateLimitWait(c.ctx, lim, clampedN, now, newTimer)
		if err != nil {
			return err
		}
		if durationWaited > 0 {
			c.s.rateLimitPerClientWaited.Add(1)
		}
	}
	return nil
}

// debugLogf logs only when the client has debug logging enabled.
// Callers on the per-packet path must check c.debug themselves first,
// since Go evaluates and boxes the arguments before the call.
func (c *sclient) debugLogf(format string, v ...any) {
	if c.debug {
		c.logf(format, v...)
	}
}

type dropReasonKindLabels struct {
	Reason string // metric label corresponding to a given dropReason
	Kind   string // either `disco` or `other`
}

// dropReason is why we dropped a DERP frame.
type dropReason string

const (
	dropReasonUnknownDest      dropReason = "unknown_dest"        // unknown destination pubkey
	dropReasonUnknownDestOnFwd dropReason = "unknown_dest_on_fwd" // unknown destination pubkey on a derp-forwarded packet
	dropReasonGoneDisconnected dropReason = "gone_disconnected"   // destination tailscaled disconnected before we could send
	dropReasonQueueHead        dropReason = "queue_head"          // destination queue is full, dropped packet at queue head
	dropReasonQueueTail        dropReason = "queue_tail"          // destination queue is full, dropped packet at queue tail
	dropReasonWriteError       dropReason = "write_error"         // OS write() failed
	dropReasonDupClient        dropReason = "dup_client"          // the public key is connected 2+ times (active/active, fighting)
)

func (s *Server) recordDrop(packetBytes []byte, srcKey, dstKey key.NodePublic, reason dropReason) {
	labels := dropReasonKindLabels{
		Reason: string(reason),
	}
	looksDisco := disco.LooksLikeDiscoWrapper(packetBytes)
	if looksDisco {
		labels.Kind = string(packetKindDisco)
	} else {
		labels.Kind = string(packetKindOther)
	}
	packetsDropped.Add(labels, 1)
	bytesDropped.Add(labels, int64(len(packetBytes)))

	if verboseDropKeys[dstKey] {
		// Preformat the log string prior to calling limitedLogf. The
		// limiter acts based on the format string, and we want to
		// rate-limit per src/dst keys, not on the generic "dropped
		// stuff" message.
		msg := fmt.Sprintf("drop (%s) %s -> %s", srcKey.ShortString(), reason, dstKey.ShortString())
		s.limitedLogf(msg)
	}
	if s.debug {
		s.debugLogf("dropping packet reason=%s dst=%s disco=%v", reason, dstKey, looksDisco)
	}
}

func (c *sclient) sendPkt(dst *sclient, p pkt) error {
	s := c.s
	dstKey := dst.key

	q, pend := &dst.sendQueue, pendSendQueue
	if disco.LooksLikeDiscoWrapper(p.bs) {
		q, pend = &dst.discoSendQueue, pendDiscoQueue
	}
	dropped, wasEmpty, ok := q.enqueue(s, p)
	if !ok {
		// The queue is closed (the client is gone) or, on a Server
		// not built by New, has zero capacity.
		reason := dropReasonGoneDisconnected
		if s.perClientSendQueueDepth == 0 {
			reason = dropReasonQueueTail
		}
		s.recordDrop(p.bs, c.key, dstKey, reason)
		s.putPacketBuf(p.buf)
		if dst.debug {
			dst.debugLogf("sendPkt dropped, reason=%s", reason)
		}
		return nil
	}
	if dropped.bs != nil {
		// The queue was full; the packet at its head was dropped to
		// make room, prioritizing fresher packets.
		s.recordDrop(dropped.bs, dropped.src, dstKey, dropReasonQueueHead)
		s.putPacketBuf(dropped.buf)
		c.recordQueueTime(dropped.enqueuedAt)
	}
	if wasEmpty {
		// Wake dst's writer, which may have parked. This is only
		// needed when p made the queue non-empty: otherwise the
		// writer is either mid-drain and will get to p before it
		// parks, or the wake from the packet that made the queue
		// non-empty is still pending.
		dst.wakeWriter(pend)
	}
	dst.debugLogf("sendPkt enqueued")
	return nil
}

// onPeerGoneFromRegion is the callback registered with the Server to be
// notified whenever a peer has disconnected from all DERP nodes in the
// current region. It is called with Server.mu held and must not block.
func (c *sclient) onPeerGoneFromRegion(peer key.NodePublic) {
	c.requestPeerGoneWrite(peer, derp.PeerGoneReasonDisconnected)
}

// requestPeerGoneWrite asks the writer to send a "peer gone" frame with
// an explanation of why it is gone. It does not block.
//
// The pending list is not capped: it is bounded by the number of
// distinct peers the client has heard from, each of whose watchers
// fires at most once, plus the rate-limited "not here" replies from
// [sclient.requestPeerGoneWriteLimited].
func (c *sclient) requestPeerGoneWrite(peer key.NodePublic, reason derp.PeerGoneReasonType) {
	c.peerGoneMu.Lock()
	c.peerGonePending = append(c.peerGonePending, peerGoneMsg{peer: peer, reason: reason})
	c.peerGoneMu.Unlock()
	c.wakeWriter(pendPeerGone)
}

// takePeerGonePending returns and clears the pending peer gone
// requests. It is called by the writer ([sclient.writePending]).
func (c *sclient) takePeerGonePending() []peerGoneMsg {
	c.peerGoneMu.Lock()
	defer c.peerGoneMu.Unlock()
	msgs := c.peerGonePending
	c.peerGonePending = nil
	return msgs
}

// requestMeshUpdate notes that a c's peerStateChange has been appended to and
// should now be written. It does not block.
func (c *sclient) requestMeshUpdate() {
	if !c.canMesh {
		panic("unexpected requestMeshUpdate")
	}
	c.wakeWriter(pendMeshUpdate)
}

// queuePong asks the writer to send a pong carrying data. It is called
// only from the reader goroutine. If a pong is already pending, the
// client is pinging faster than we write, and the new one is dropped.
// (A pong queued in the moment between the writer taking the pending
// bit and loading pong is instead written twice, which is harmless.)
func (c *sclient) queuePong(data [8]byte) {
	if c.writerState.Load().pending()&pendPong != 0 {
		// TODO(bradfitz): add a rate limiter too.
		return
	}
	c.pong.Store(binary.BigEndian.Uint64(data[:]))
	c.wakeWriter(pendPong)
}

// isMeshPeer reports whether the client is a trusted mesh peer
// node in the DERP region.
func (s *Server) isMeshPeer(info *derp.ClientInfo) bool {
	// Compare mesh keys in constant time to prevent timing attacks.
	// Since mesh keys are a fixed length, we don’t need to be concerned
	// about timing attacks on client mesh keys that are the wrong length.
	// See https://github.com/tailscale/corp/issues/28720
	if info == nil || info.MeshKey.IsZero() {
		return false
	}

	return s.meshKey.Equal(info.MeshKey)
}

// verifyClient checks whether the client is allowed to connect to the derper,
// depending on how & whether the server's been configured to verify.
func (s *Server) verifyClient(ctx context.Context, clientKey key.NodePublic, info *derp.ClientInfo, clientIP netip.Addr) error {
	if s.isMeshPeer(info) {
		// Trusted mesh peer. No need to verify further. In fact, verifying
		// further wouldn't work: it's not part of the tailnet so tailscaled and
		// likely the admission control URL wouldn't know about it.
		return nil
	}

	if info != nil && s.disallowedAppNames.Contains(info.AppName) {
		return fmt.Errorf("disallowed app name %q", info.AppName)
	}

	// tailscaled-based verification:
	if s.verifyClientsLocalTailscaled {
		_, err := s.localClient.WhoIsNodeKey(ctx, clientKey)
		if err == local.ErrPeerNotFound {
			return fmt.Errorf("peer %v not authorized (not found in local tailscaled)", clientKey)
		}
		if err != nil {
			if strings.Contains(err.Error(), "invalid 'addr' parameter") {
				// Issue 12617
				return errors.New("tailscaled version is too old (out of sync with derper binary)")
			}
			return fmt.Errorf("failed to query local tailscaled status for %v: %w", clientKey, err)
		}
	}

	// admission controller-based verification:
	if s.verifyClientsURL != "" {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		jreq, err := json.Marshal(&tailcfg.DERPAdmitClientRequest{
			NodePublic: clientKey,
			Source:     clientIP,
		})
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, "POST", s.verifyClientsURL, bytes.NewReader(jreq))
		if err != nil {
			return err
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			if s.verifyClientsURLFailOpen {
				s.logf("admission controller unreachable; allowing client %v", clientKey)
				return nil
			}
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return fmt.Errorf("admission controller: %v", res.Status)
		}
		var jres tailcfg.DERPAdmitClientResponse
		if err := json.NewDecoder(io.LimitReader(res.Body, 4<<10)).Decode(&jres); err != nil {
			return err
		}
		if !jres.Allow {
			return fmt.Errorf("admission controller: %v/%v not allowed", clientKey, clientIP)
		}
		// TODO(bradfitz): add policy for configurable bandwidth rate per client?
	}
	return nil
}

func (s *Server) sendServerKey(lw *lazyBufioWriter) error {
	buf := make([]byte, 0, len(derp.Magic)+key.NodePublicRawLen)
	buf = append(buf, derp.Magic...)
	buf = s.publicKey.AppendTo(buf)
	err := derp.WriteFrame(lw.bw(), derp.FrameServerKey, buf)
	lw.Flush() // redundant (no-op) flush to release bufio.Writer
	return err
}

func (s *Server) noteClientActivity(c *sclient) {
	if !c.isDup.Load() {
		// Fast path for clients that aren't in a dup set.
		return
	}
	if c.isDisabled.Load() {
		// If they're already disabled, no point checking more.
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cs, ok := s.clients.Load(c.key)
	if !ok {
		return
	}
	dup := cs.dup
	if dup == nil {
		// It became unduped in between the isDup fast path check above
		// and the mutex check. Nothing to do.
		return
	}

	if s.dupPolicy == lastWriterIsActive {
		dup.last = c
		cs.activeClient.Store(c)
	} else if dup.last == nil {
		// If we didn't have a primary, let the current
		// speaker be the primary.
		dup.last = c
		cs.activeClient.Store(c)
	}

	if slicesx.LastEqual(dup.sendHistory, c) {
		// The client c was the last client to make activity
		// in this set and it was already recorded. Nothing to
		// do.
		return
	}

	// If we saw this connection send previously, then consider
	// the group fighting and disable them all.
	if s.dupPolicy == disableFighters {
		if slices.Contains(dup.sendHistory, c) {
			cs.ForeachClient(func(c *sclient) {
				c.isDisabled.Store(true)
				if cs.activeClient.Load() == c {
					cs.activeClient.Store(nil)
				}
			})
		}
	}

	// Record c as the most recent sender. If c is already in
	// sendHistory, remove the earlier occurrence first so that each
	// member appears at most once and the slice stays bounded by the
	// number of connections in the set. The LastEqual check above
	// already handled the case where c is the current tail.
	if i := slices.Index(dup.sendHistory, c); i >= 0 {
		dup.sendHistory = slices.Delete(dup.sendHistory, i, i+1)
	}
	dup.sendHistory = append(dup.sendHistory, c)
}

type ServerInfo = derp.ServerInfo

func (s *Server) sendServerInfo(bw *lazyBufioWriter, clientKey key.NodePublic) error {
	msg, err := json.Marshal(ServerInfo{Version: derp.ProtocolVersion})
	if err != nil {
		return err
	}

	msgbox := s.privateKey.SealTo(clientKey, msg)
	if err := derp.WriteFrameHeader(bw.bw(), derp.FrameServerInfo, uint32(len(msgbox))); err != nil {
		return err
	}
	if _, err := bw.Write(msgbox); err != nil {
		return err
	}
	return bw.Flush()
}

// recvClientKey reads the FrameClientInfo frame from the client (its
// proof of identity) upon its initial connection. It should be
// considered especially untrusted at this point.
func (s *Server) recvClientKey(br *bufio.Reader) (clientKey key.NodePublic, info *derp.ClientInfo, err error) {
	fl, err := derp.ReadFrameTypeHeader(br, derp.FrameClientInfo)
	if err != nil {
		return zpub, nil, err
	}
	const minLen = derp.KeyLen + derp.NonceLen
	if fl < minLen {
		return zpub, nil, errors.New("short client info")
	}
	// We don't trust the client at all yet, so limit its input size to limit
	// things like JSON resource exhausting (http://github.com/golang/go/issues/31789).
	if fl > 256<<10 {
		return zpub, nil, errors.New("long client info")
	}
	if err := clientKey.ReadRawWithoutAllocating(br); err != nil {
		return zpub, nil, err
	}
	msgLen := int(fl - derp.KeyLen)
	msgbox := make([]byte, msgLen)
	if _, err := io.ReadFull(br, msgbox); err != nil {
		return zpub, nil, fmt.Errorf("msgbox: %v", err)
	}
	msg, ok := s.privateKey.OpenFrom(clientKey, msgbox)
	if !ok {
		return zpub, nil, fmt.Errorf("msgbox: cannot open len=%d with client key %s", msgLen, clientKey)
	}
	info = new(derp.ClientInfo)
	if err := json.Unmarshal(msg, info); err != nil {
		return zpub, nil, fmt.Errorf("msg: %v", err)
	}
	if !derp.ValidAppName(info.AppName) {
		return zpub, nil, fmt.Errorf("invalid AppName %.40q", info.AppName)
	}
	return clientKey, info, nil
}

// recvPacket reads the body of a send packet frame of length frameLen
// from br. The returned buffer holds the packet payload and must be
// released with putPacketBuf once the packet has been written,
// forwarded, or dropped.
func (s *Server) recvPacket(br *bufio.Reader, frameLen uint32) (dstKey key.NodePublic, buf *[]byte, err error) {
	if frameLen < derp.KeyLen {
		return zpub, nil, errors.New("short send packet frame")
	}
	if err := dstKey.ReadRawWithoutAllocating(br); err != nil {
		return zpub, nil, err
	}
	packetLen := frameLen - derp.KeyLen
	if packetLen > derp.MaxPacketSize {
		return zpub, nil, fmt.Errorf("data packet longer (%d) than max of %v", packetLen, derp.MaxPacketSize)
	}
	buf = s.getPacketBuf(int(packetLen))
	contents := *buf
	if _, err := io.ReadFull(br, contents); err != nil {
		s.putPacketBuf(buf)
		return zpub, nil, err
	}
	s.packetsRecv.Add(1)
	s.bytesRecv.Add(int64(len(contents)))
	if disco.LooksLikeDiscoWrapper(contents) {
		s.packetsRecvDisco.Add(1)
	} else {
		s.packetsRecvOther.Add(1)
	}
	return dstKey, buf, nil
}

// zpub is the key.NodePublic zero value.
var zpub key.NodePublic

// recvForwardPacket reads the body of a forward packet frame of length
// frameLen from br. The returned buffer holds the packet payload and
// must be released with putPacketBuf once the packet has been written
// or dropped.
func (s *Server) recvForwardPacket(br *bufio.Reader, frameLen uint32) (srcKey, dstKey key.NodePublic, buf *[]byte, err error) {
	if frameLen < derp.KeyLen*2 {
		return zpub, zpub, nil, errors.New("short send packet frame")
	}
	if err := srcKey.ReadRawWithoutAllocating(br); err != nil {
		return zpub, zpub, nil, err
	}
	if err := dstKey.ReadRawWithoutAllocating(br); err != nil {
		return zpub, zpub, nil, err
	}
	packetLen := frameLen - derp.KeyLen*2
	if packetLen > derp.MaxPacketSize {
		return zpub, zpub, nil, fmt.Errorf("data packet longer (%d) than max of %v", packetLen, derp.MaxPacketSize)
	}
	buf = s.getPacketBuf(int(packetLen))
	if _, err := io.ReadFull(br, *buf); err != nil {
		s.putPacketBuf(buf)
		return zpub, zpub, nil, err
	}
	// TODO: was s.packetsRecv.Add(1)
	// TODO: was s.bytesRecv.Add(int64(len(contents)))
	return srcKey, dstKey, buf, nil
}

// sclient is a client connection to the server.
//
// A node (a wireguard public key) can be connected multiple times to a DERP server
// and thus have multiple sclient instances. An sclient represents
// only one of these possibly multiple connections. See clientSet for the
// type that represents the set of all connections for a given key.
//
// (The "s" prefix is to more explicitly distinguish it from Client in derp_client.go)
type sclient struct {
	// Static after construction.
	connNum        int64 // process-wide unique counter, incremented each Accept
	s              *Server
	nc             derp.Conn
	key            key.NodePublic
	info           derp.ClientInfo
	logf           logger.Logf
	ctx            context.Context // closed when connection closes
	remoteIPPort   netip.AddrPort  // zero if remoteAddr is not ip:port.
	sendQueue      pktQueue        // packets queued to this client
	discoSendQueue pktQueue        // important packets queued to this client
	canMesh        bool            // clientInfo had correct mesh token for inter-region routing
	isNotIdealConn bool            // client indicated it is not its ideal node in the region
	isDup          atomic.Bool     // whether more than 1 sclient for key is connected
	isDisabled     atomic.Bool     // whether sends to this peer are disabled due to active/active dups
	debug          bool            // turn on for verbose logging

	// runWriterFunc is the method value [sclient.runWriter] bound to
	// this client. It is allocated once here so that the go statement
	// in [sclient.wakeWriter] doesn't allocate a new one per wake.
	runWriterFunc func()

	// keepAliveTimer fires [sclient.onKeepAliveTimer]. It is set by
	// [sclient.run] and stopped by [sclient.stopWriter].
	keepAliveTimer tstime.TimerController

	// writerState coordinates the writer goroutine, which exists only
	// while the client has something to write, with the goroutines
	// that give it work. See [sclient.wakeWriter].
	writerState atomicWriterState

	// writerExited is closed by the writer goroutine as it exits after
	// [sclient.stopWriter] moved writerState to [writerClosing].
	// stopWriter creates it before that transition and the writer reads
	// it only after observing the transition, so the plain field is
	// race-free.
	writerExited chan struct{}

	// Pending work for the writer. Producers publish their work here
	// and then call [sclient.wakeWriter] with its [writerPending] bit;
	// the writer consumes it in [sclient.writePending]. peerGoneMu
	// guards peerGonePending. pong is the latest pong reply to write,
	// as a big-endian uint64 so the reader can replace it without a
	// lock.
	peerGoneMu      sync.Mutex
	peerGonePending []peerGoneMsg // "peer gone" frames to write (not used by mesh peers)
	pong            atomic.Uint64

	// Owned by run, not thread-safe.
	br          *bufio.Reader
	connectedAt time.Time
	preferred   bool

	// Owned by the writer goroutine, not thread-safe. Only one writer
	// runs at a time, and [sclient.stopWriter] touches these only after
	// the last one has exited.
	sawSrc   map[key.NodePublic]set.Handle
	bw       *lazyBufioWriter
	writeErr error // the write error that stopped the writer, if any; logged by stopWriter

	// senderCardinality estimates the number of unique peers that have
	// sent packets to this client. It is nil unless
	// [Server.trackSenderCardinality] is set, and then until the first
	// packet. Written by the writer goroutine ([sclient.sendPacket]),
	// guarded by senderCardinalityMu for [sclient.EstimatedUniqueSenders].
	senderCardinalityMu sync.Mutex
	senderCardinality   *hyperloglog.Sketch

	// Guarded by s.mu
	//
	// peerStateChange is used by mesh peers (a set of regional
	// DERP servers) and contains records that need to be sent to
	// the client for them to update their map of who's connected
	// to this node.
	peerStateChange []peerConnState

	// peerGoneLimiter limits how often the server will inform a
	// client that it's trying to establish a direct connection
	// through us with a peer we have no record of.
	peerGoneLim *rate.Limiter

	// recvLim is the receive rate limiter. When rate limiting is enabled for a
	// non-mesh client, it points to a [xrate.Limiter]. When rate limiting
	// is disabled or the client is a mesh peer, it is nil and [sclient.rateLimit]
	// is a no-op. Updated atomically by [sclient.setRateLimit] so that
	// [sclient.rateLimit] can load it without holding [Server.mu].
	//
	// TODO: consider porting the required APIs from [xrate.Limiter] to [rate.Limiter],
	// which is already optimized to use [mono.Time].
	recvLim atomic.Pointer[xrate.Limiter]
}

func (c *sclient) presentFlags() derp.PeerPresentFlags {
	var f derp.PeerPresentFlags
	if c.info.IsProber {
		f |= derp.PeerPresentIsProber
	}
	if c.canMesh {
		f |= derp.PeerPresentIsMeshPeer
	}
	if c.isNotIdealConn {
		f |= derp.PeerPresentNotIdeal
	}
	if f == 0 {
		return derp.PeerPresentIsRegular
	}
	return f
}

// peerConnState represents whether a peer is connected to the server
// or not.
type peerConnState struct {
	ipPort  netip.AddrPort // if present, the peer's IP:port
	peer    key.NodePublic
	flags   derp.PeerPresentFlags
	appName string // if present, the peer's self-reported app name
	present bool
}

// pkt is a request to write a data frame to an sclient.
type pkt struct {
	// enqueuedAt is when a packet was put onto a queue before it was sent,
	// and is used for reporting metrics on the duration of packets in the queue.
	enqueuedAt time.Time

	// bs is the data packet bytes. When buf is non-nil, bs aliases
	// *buf and is only valid until the packet is released with
	// Server.putPacketBuf; otherwise the memory is owned by pkt.
	bs []byte

	// buf is the pooled buffer backing bs, or nil if bs did not come
	// from Server.getPacketBuf. Whoever consumes bs, by writing or
	// dropping the packet, releases it with Server.putPacketBuf.
	buf *[]byte

	// src is the who's the sender of the packet.
	src key.NodePublic
}

// pktQueue is a bounded FIFO of packets waiting to be written to a
// client. Each sclient has two, one for regular packets and one for
// disco packets.
//
// It replaces what was once a buffered channel per queue so that an
// idle client doesn't pin a channel buffer of perClientSendQueueDepth
// pkts for the lifetime of its connection: the ring is taken from
// Server.sendQueueRingPool on first enqueue and returned whenever the
// queue drains empty. Enqueuers wake the client's writer through
// [sclient.wakeWriter].
type pktQueue struct {
	mu     sync.Mutex
	ring   *[]pkt // nil iff n == 0; length Server.perClientSendQueueDepth otherwise
	head   int    // ring index of the oldest queued packet; meaningful only when n > 0
	n      int    // number of queued packets
	closed bool   // set by close; enqueues fail once set
}

// enqueue adds p to the back of the queue, dropping the packet at the
// head to make room if the queue is full. It reports whether p was
// enqueued; it is not when the queue is closed (the client is gone) or
// when s.perClientSendQueueDepth is zero, which New never configures
// but a zero-value Server has. When a head drop made room, the dropped
// packet is returned with a non-nil bs for the caller to record.
// wasEmpty reports whether the queue was empty before p was added,
// meaning the caller needs to wake the writer; see [sclient.sendPkt].
func (q *pktQueue) enqueue(s *Server, p pkt) (dropped pkt, wasEmpty, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || s.perClientSendQueueDepth == 0 {
		return pkt{}, false, false
	}
	if q.ring == nil {
		q.ring = s.getSendQueueRing()
	}
	ring := *q.ring
	wasEmpty = q.n == 0
	if q.n == len(ring) {
		dropped = ring[q.head]
		q.head = (q.head + 1) % len(ring)
		q.n--
	}
	ring[(q.head+q.n)%len(ring)] = p
	q.n++
	return dropped, wasEmpty, true
}

// dequeue removes and returns the packet at the head of the queue,
// reporting whether one was queued and whether more remain after it,
// so a drain needs no extra call to learn it is done. When the queue
// drains empty its ring is returned to the pool.
func (q *pktQueue) dequeue(s *Server) (p pkt, more, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.n == 0 {
		return pkt{}, false, false
	}
	p = q.popLocked(s)
	return p, q.n > 0, true
}

// popLocked removes and returns the packet at the head of the queue,
// which must be non-empty. When the queue drains empty its ring is
// returned to the pool. q.mu must be held.
func (q *pktQueue) popLocked(s *Server) pkt {
	ring := *q.ring
	p := ring[q.head]
	ring[q.head] = pkt{} // don't retain p.bs past delivery
	q.head = (q.head + 1) % len(ring)
	q.n--
	if q.n == 0 {
		s.sendQueueRingPool.Put(q.ring)
		q.ring = nil
	}
	return p
}

// close marks the queue closed so that no further packets can be
// enqueued, and calls drop for each packet still queued, which
// releases the ring. Closing keeps stragglers in sendPkt from
// enqueueing onto a gone client, which matters because the rings are
// pooled: a packet enqueued after the drain here would otherwise
// surface in some other client's queue when the ring is reused.
func (q *pktQueue) close(s *Server, drop func(pkt)) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	for q.n > 0 {
		drop(q.popLocked(s))
	}
}

// peerGoneMsg is a request to write a peerGone frame to an sclient
type peerGoneMsg struct {
	peer   key.NodePublic
	reason derp.PeerGoneReasonType
}

func (c *sclient) setPreferred(v bool) {
	if c.preferred == v {
		return
	}
	c.preferred = v
	var homeMove *expvar.Int
	if v {
		c.s.curHomeClients.Add(1)
		homeMove = &c.s.homeMovesIn
	} else {
		c.s.curHomeClients.Add(-1)
		homeMove = &c.s.homeMovesOut
	}

	// Keep track of varz for home serve moves in/out.  But ignore
	// the initial packet set when a client connects, which we
	// assume happens within 5 seconds. In any case, just for
	// graphs, so not important to miss a move. But it shouldn't:
	// the netcheck/re-STUNs in magicsock only happen about every
	// 30 seconds.
	if c.s.clock.Since(c.connectedAt) > 5*time.Second {
		homeMove.Add(1)
	}
}

// expMovingAverage returns the new moving average given the previous average,
// a new value, and an alpha decay factor.
// https://en.wikipedia.org/wiki/Moving_average#Exponential_moving_average
func expMovingAverage(prev, newValue, alpha float64) float64 {
	return alpha*newValue + (1-alpha)*prev
}

// recordQueueTime updates the average queue duration metric after a packet has been sent.
func (c *sclient) recordQueueTime(enqueuedAt time.Time) {
	elapsed := float64(c.s.clock.Since(enqueuedAt).Milliseconds())
	for {
		old := atomic.LoadUint64(c.s.avgQueueDuration)
		newAvg := expMovingAverage(math.Float64frombits(old), elapsed, 0.1)
		if atomic.CompareAndSwapUint64(c.s.avgQueueDuration, old, math.Float64bits(newAvg)) {
			break
		}
	}
}

// writerPhase is where the client's writer goroutine is in its
// lifecycle. It is packed with a [writerPending] into a [writerState].
// See [sclient.wakeWriter] for how the phases fit together.
type writerPhase uint8

const (
	// writerParked means no writer goroutine exists. The next
	// [sclient.wakeWriter] starts one. Nothing is pending in this phase.
	writerParked writerPhase = iota

	// writerRunning means a writer goroutine is draining the client's
	// pending work. Work published meanwhile is recorded in the
	// [writerPending] set, which the writer must take before it may park.
	writerRunning

	// writerClosing means [sclient.stopWriter] is waiting on
	// [sclient.writerExited] for the running writer to exit.
	writerClosing

	// writerStopped is terminal: the writer has exited for good, either
	// because a write failed or because [sclient.stopWriter] tore the
	// client down, and no writer goroutine will run again.
	writerStopped
)

// writerPending is a set of kinds of work pending for the client's
// writer goroutine, one pend* bit per kind. It is packed with a
// [writerPhase] into a [writerState]. A producer publishes its work (a
// [pktQueue.enqueue], a store to [sclient.pong], an append to
// [sclient.peerGonePending]) and then passes its bit to
// [sclient.wakeWriter]; the writer takes the whole set at once and
// looks only at the sources whose bits are set ([sclient.writePending]).
type writerPending uint32

const (
	pendPeerGone   writerPending = 1 << iota // peerGonePending has entries
	pendMeshUpdate                           // peerStateChange has entries to write (mesh peers only)
	pendPong                                 // pong holds a pong reply to write
	pendKeepAlive                            // the keepalive timer fired
	pendSendQueue                            // sendQueue went from empty to non-empty
	pendDiscoQueue                           // discoSendQueue went from empty to non-empty
)

// writerState is the value of [sclient.writerState]: a [writerPhase]
// and a [writerPending] packed into one word, so that a producer can
// record its work and start a parked writer in a single
// compare-and-swap, and the writer can take all pending work and decide
// whether to park likewise. The phase is in the low [writerPhaseBits]
// bits and the pending set above them; [packWriterState] builds one
// and [writerState.phase] and [writerState.pending] take it apart.
type writerState uint32

const writerPhaseBits = 2

// packWriterState returns the [writerState] with phase ph and pending
// set pend.
func packWriterState(ph writerPhase, pend writerPending) writerState {
	return writerState(ph) | writerState(pend)<<writerPhaseBits
}

// phase returns w's [writerPhase].
func (w writerState) phase() writerPhase { return writerPhase(w & (1<<writerPhaseBits - 1)) }

// pending returns w's [writerPending] set.
func (w writerState) pending() writerPending { return writerPending(w >> writerPhaseBits) }

// withPending returns w with pend added to its pending set.
func (w writerState) withPending(pend writerPending) writerState {
	return w | writerState(pend)<<writerPhaseBits
}

// atomicWriterState is an atomically accessed [writerState].
type atomicWriterState struct{ v atomic.Uint32 }

func (a *atomicWriterState) Load() writerState   { return writerState(a.v.Load()) }
func (a *atomicWriterState) Store(w writerState) { a.v.Store(uint32(w)) }
func (a *atomicWriterState) CompareAndSwap(old, new writerState) bool {
	return a.v.CompareAndSwap(uint32(old), uint32(new))
}

// wakeWriter makes sure the work the caller just published, of the
// kinds in pend, gets written. It adds pend to the writer's
// [writerPending] set and starts a writer goroutine ([sclient.runWriter])
// if none is running. It is a no-op once the writer has stopped for
// good.
//
// The writer goroutine comes and goes as needed. It runs only
// while there is something to write and exits ("parks") once the
// pending work drains, so an idle client pins one goroutine, the
// reader in [sclient.run], rather than two. This follows the shape of
// the parking serve goroutine in Go's net/http HTTP/2 server, golang/go
// commits 5c51011e82 and dcf521c570.
//
// Every producer publishes its work before calling wakeWriter, and
// the writer takes the pending set ([sclient.takePending]) before
// looking at the work, so work published while the writer is deciding
// whether to park ([sclient.tryParkWriter]) is never lost: the producer
// either finds the writer parked and starts a new one with the work
// already pending, or finds it running and adds to its pending set,
// which makes its park attempt fail.
func (c *sclient) wakeWriter(pend writerPending) {
	if c.claimWriter(pend) {
		go c.runWriterFunc()
	}
}

// claimWriter is [sclient.wakeWriter]'s state transition: it adds
// pend, the kinds of work the caller just published, to the writer's
// [writerPending] set and, if the writer had parked, moves it to
// [writerRunning] on the caller's behalf. It reports whether the caller
// must now run the writer ([sclient.runWriter]), having claimed it that
// way. Otherwise a running writer will see pend before it parks, or the
// writer has stopped for good and the work is moot.
func (c *sclient) claimWriter(pend writerPending) bool {
	for {
		old := c.writerState.Load()
		switch old.phase() {
		case writerParked:
			if c.writerState.CompareAndSwap(old, packWriterState(writerRunning, pend)) {
				return true
			}
		case writerRunning:
			if new := old.withPending(pend); new == old || c.writerState.CompareAndSwap(old, new) {
				return false
			}
		default: // closing or stopped
			return false
		}
	}
}

// runWriter is the body of the writer goroutine started by
// [sclient.wakeWriter]. It writes the client's pending work until there
// is none, flushing each time it catches up, and then parks. If a
// write fails it stops for good and closes the connection, which makes
// the reader tear the client down ([sclient.stopWriter]).
func (c *sclient) runWriter() {
	inBatch := 0 // frames (or groups of related frames) written since the last flush, for bufferedWriteFrames

	// carry is the queue work a writePending pass ran out of budget
	// for. Its pending bits were already taken, and enqueuers only wake
	// the writer when a queue goes from empty to non-empty, so it must
	// be fed back into the next pass rather than dropped.
	var carry writerPending
	for {
		pend, exit := c.takePending()
		if exit {
			return
		}
		pend |= carry
		if pend != 0 {
			var n int
			var err error
			n, carry, err = c.writePending(pend)
			inBatch += n
			if err != nil {
				c.stopWriterOnError(err)
				return
			}
			continue
		}
		// Caught up. Flush, then try to park; if work arrived
		// meanwhile, the park attempt fails and the loop goes around.
		if err := c.bw.Flush(); err != nil {
			c.stopWriterOnError(err)
			return
		}
		// Nothing to observe when nothing was written, as after a
		// wake whose work an earlier pass already drained.
		if inBatch != 0 {
			c.s.bufferedWriteFrames.Observe(float64(inBatch))
			inBatch = 0
		}
		if c.tryParkWriter() {
			return
		}
	}
}

// takePending returns and clears the writer's [writerPending] set. It
// reports exit when the writer must instead exit because
// [sclient.stopWriter] is closing the client, having done that handoff.
func (c *sclient) takePending() (pend writerPending, exit bool) {
	for {
		old := c.writerState.Load()
		switch old.phase() {
		case writerRunning:
			pend = old.pending()
			if pend == 0 || c.writerState.CompareAndSwap(old, packWriterState(writerRunning, 0)) {
				return pend, false
			}
		case writerClosing:
			c.exitWriterForStop()
			return 0, true
		default:
			panic(fmt.Sprintf("unexpected writer state %#x", old))
		}
	}
}

// tryParkWriter is the writer's attempt to exit after it caught up. It
// reports whether the writer must exit, which it must both when it
// parks and when [sclient.stopWriter] is closing the client. It reports
// false when more work was published meanwhile, so the writer must go
// on.
func (c *sclient) tryParkWriter() (exit bool) {
	for {
		old := c.writerState.Load()
		switch old.phase() {
		case writerRunning:
			if old.pending() != 0 {
				return false
			}
			if c.writerState.CompareAndSwap(old, packWriterState(writerParked, 0)) {
				return true
			}
		case writerClosing:
			c.exitWriterForStop()
			return true
		default:
			panic(fmt.Sprintf("unexpected writer state %#x", old))
		}
	}
}

// exitWriterForStop is the writer's side of the handoff to a
// [sclient.stopWriter] waiting in [writerClosing] for it to exit.
func (c *sclient) exitWriterForStop() {
	c.writerState.Store(packWriterState(writerStopped, 0))
	close(c.writerExited)
}

// stopWriterOnError ends the writer for good after a write failed with
// err. Closing the connection makes the reader's next read fail, and
// the reader's teardown ([sclient.stopWriter]) logs err.
func (c *sclient) stopWriterOnError(err error) {
	c.writeErr = err
	c.nc.Close()
	for {
		old := c.writerState.Load()
		switch old.phase() {
		case writerRunning:
			if c.writerState.CompareAndSwap(old, packWriterState(writerStopped, 0)) {
				return
			}
		case writerClosing:
			c.exitWriterForStop()
			return
		default:
			panic(fmt.Sprintf("unexpected writer state %#x", old))
		}
	}
}

// stopWriter is [sclient.run]'s teardown. It closes the connection,
// waits for a running writer goroutine to exit, and then, as the sole
// remaining owner of the client's write-side state, releases it: the
// keepalive timer, the peer gone watches, and the send queues.
//
// It must only be called from the reader goroutine, after run's read
// loop has exited.
func (c *sclient) stopWriter() {
	// Fail any write in progress so the writer exits promptly.
	c.nc.Close()

	for stopped := false; !stopped; {
		old := c.writerState.Load()
		switch old.phase() {
		case writerParked:
			stopped = c.writerState.CompareAndSwap(old, packWriterState(writerStopped, 0))
		case writerRunning:
			if c.writerExited == nil {
				c.writerExited = make(chan struct{})
			}
			if c.writerState.CompareAndSwap(old, packWriterState(writerClosing, 0)) {
				<-c.writerExited
				stopped = true
			}
		case writerStopped:
			stopped = true
		default:
			// Only stopWriter moves to writerClosing, and it runs once.
			panic(fmt.Sprintf("unexpected writer state %#x", old))
		}
	}

	if err := c.writeErr; err != nil && !c.s.isClosed() {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			c.s.sclientWriteTimeouts.Add(1)
		}
		c.logf("sender failed: %v", err)
	}

	if c.keepAliveTimer != nil {
		c.keepAliveTimer.Stop()
	}

	// Clean up watches.
	for peer, h := range c.sawSrc {
		c.s.removePeerGoneFromRegionWatcher(peer, h)
	}

	// Close the send queues so nothing more can be enqueued for this
	// client, and drain them to count dropped packets.
	drop := func(p pkt) {
		c.s.recordDrop(p.bs, p.src, c.key, dropReasonGoneDisconnected)
		c.s.putPacketBuf(p.buf)
	}
	c.sendQueue.close(c.s, drop)
	c.discoSendQueue.close(c.s, drop)
}

// keepAliveInterval returns how long to wait before sending the
// client its next keepalive frame, jittered so a server's clients
// don't all tick together.
func keepAliveInterval() time.Duration {
	return derp.KeepAlive + rand.N(5*time.Second)
}

// onKeepAliveTimer runs on the keepalive timer's goroutine when it is
// time to send the client a keepalive. Because it already has a
// goroutine of its own, it runs a parked writer inline
// ([sclient.runWriter]) rather than starting another goroutine for it.
func (c *sclient) onKeepAliveTimer() {
	if c.claimWriter(pendKeepAlive) {
		c.runWriter()
	}
}

// writePending writes the pending work of the kinds in pend, without
// flushing, and returns how many frames (or groups of related frames)
// it wrote. Control frames (peer gone, mesh updates, pong, keepalive)
// go before packets, and between the two [pktQueue]s the order is
// random, as select's was when they were channels, so neither disco
// nor regular packets can starve the other.
//
// A pass writes at most a queue's depth worth of packets. A sender
// that keeps a queue topped up as fast as it drains would otherwise
// hold the writer in here forever, with the control frames published
// meanwhile never written. The queue bits it didn't finish are
// returned as carry for the caller to add to its next pass, after
// picking up any newly pending work. It returns the first write error.
func (c *sclient) writePending(pend writerPending) (frames int, carry writerPending, err error) {
	if pend&pendPeerGone != 0 {
		for _, m := range c.takePeerGonePending() {
			if err := c.sendPeerGone(m.peer, m.reason); err != nil {
				return frames, 0, err
			}
			frames++
		}
	}
	if pend&pendMeshUpdate != 0 {
		if err := c.sendMeshUpdates(); err != nil {
			return frames, 0, err
		}
		frames++
	}
	if pend&pendPong != 0 {
		var data [8]byte
		binary.BigEndian.PutUint64(data[:], c.pong.Load())
		if err := c.sendPong(data); err != nil {
			return frames, 0, err
		}
		frames++
	}
	if pend&pendKeepAlive != 0 {
		if err := c.sendKeepAlive(); err != nil {
			return frames, 0, err
		}
		c.keepAliveTimer.Reset(keepAliveInterval())
		frames++
	}
	const queues = pendSendQueue | pendDiscoQueue
	for budget := max(c.s.perClientSendQueueDepth, 1); pend&queues != 0 && budget > 0; budget-- {
		q, bit := &c.sendQueue, pendSendQueue
		if pend&pendDiscoQueue != 0 && (pend&pendSendQueue == 0 || rand.IntN(2) == 0) {
			q, bit = &c.discoSendQueue, pendDiscoQueue
		}
		msg, more, ok := q.dequeue(c.s)
		if !more {
			pend &^= bit
		}
		if !ok {
			continue
		}
		err := c.sendPacket(msg.src, msg.bs)
		c.s.putPacketBuf(msg.buf)
		if err != nil {
			return frames, 0, err
		}
		c.recordQueueTime(msg.enqueuedAt)
		frames++
	}
	return frames, pend & queues, nil
}

func (c *sclient) setWriteDeadline() {
	d := c.s.tcpWriteTimeout
	if c.canMesh {
		// Trusted peers get more tolerance.
		//
		// The "canMesh" is a bit of a misnomer; mesh peers typically run over a
		// different interface for a per-region private VPC and are not
		// throttled. But monitoring software elsewhere over the internet also
		// use the private mesh key to subscribe to connect/disconnect events
		// and might hit throttling and need more time to get the initial dump
		// of connected peers.
		d = privilegedWriteTimeout
	}
	if d == 0 {
		// A zero value should disable the write deadline per
		// --tcp-write-timeout docs. The flag should only be applicable for
		// non-mesh connections, again per its docs. If mesh happened to use a
		// zero value constant above it would be a bug, so we don't bother
		// with a condition on c.canMesh.
		return
	}
	// Ignore the error from setting the write deadline. In practice,
	// setting the deadline will only fail if the connection is closed
	// or closing, so the subsequent Write() will fail anyway.
	_ = c.nc.SetWriteDeadline(time.Now().Add(d))
}

// sendKeepAlive sends a keep-alive frame, without flushing.
func (c *sclient) sendKeepAlive() error {
	c.setWriteDeadline()
	return derp.WriteFrameHeader(c.bw.bw(), derp.FrameKeepAlive, 0)
}

// sendPong sends a pong reply, without flushing.
func (c *sclient) sendPong(data [8]byte) error {
	c.s.sentPong.Add(1)
	c.setWriteDeadline()
	if err := derp.WriteFrameHeader(c.bw.bw(), derp.FramePong, uint32(len(data))); err != nil {
		return err
	}
	_, err := c.bw.Write(data[:])
	return err
}

const (
	peerGoneFrameLen = derp.KeyLen + 1

	// peerPresentBaseLen is the size of a peerPresent frame before its
	// variable-length app name suffix: 16 byte IP + 2 byte port + 1 byte
	// flags + 1 byte app name length.
	peerPresentBaseLen = derp.KeyLen + 16 + 2 + 1 + 1
)

// sendPeerGone sends a peerGone frame, without flushing.
func (c *sclient) sendPeerGone(peer key.NodePublic, reason derp.PeerGoneReasonType) error {
	switch reason {
	case derp.PeerGoneReasonDisconnected:
		c.s.peerGoneDisconnectedFrames.Add(1)
	case derp.PeerGoneReasonNotHere:
		c.s.peerGoneNotHereFrames.Add(1)
	}
	c.setWriteDeadline()
	data := make([]byte, 0, peerGoneFrameLen)
	data = peer.AppendTo(data)
	data = append(data, byte(reason))
	if err := derp.WriteFrameHeader(c.bw.bw(), derp.FramePeerGone, uint32(len(data))); err != nil {
		return err
	}

	_, err := c.bw.Write(data)
	return err
}

// sendPeerPresent sends a peerPresent frame, without flushing.
func (c *sclient) sendPeerPresent(peer key.NodePublic, ipPort netip.AddrPort, flags derp.PeerPresentFlags, appName string) error {
	c.setWriteDeadline()
	frameLen := peerPresentBaseLen + len(appName)
	if err := derp.WriteFrameHeader(c.bw.bw(), derp.FramePeerPresent, uint32(frameLen)); err != nil {
		return err
	}
	payload := make([]byte, frameLen)
	_ = peer.AppendTo(payload[:0])
	a16 := ipPort.Addr().As16()
	copy(payload[derp.KeyLen:], a16[:])
	binary.BigEndian.PutUint16(payload[derp.KeyLen+16:], ipPort.Port())
	payload[derp.KeyLen+18] = byte(flags)
	payload[derp.KeyLen+19] = byte(len(appName))
	copy(payload[derp.KeyLen+20:], appName)
	_, err := c.bw.Write(payload)
	return err
}

// sendMeshUpdates drains all mesh peerStateChange entries into the write buffer
// without flushing.
func (c *sclient) sendMeshUpdates() error {
	var lastBatch []peerConnState // memory to best effort reuse

	// takeAll returns c.peerStateChange and empties it.
	takeAll := func() []peerConnState {
		c.s.mu.Lock()
		defer c.s.mu.Unlock()
		if len(c.peerStateChange) == 0 {
			return nil
		}
		batch := c.peerStateChange
		if cap(lastBatch) > 16 {
			lastBatch = nil
		}
		c.peerStateChange = lastBatch[:0]
		return batch
	}

	for loops := 0; ; loops++ {
		batch := takeAll()
		if len(batch) == 0 {
			c.s.meshUpdateLoopCount.Observe(float64(loops))
			return nil
		}
		c.s.meshUpdateBatchSize.Observe(float64(len(batch)))

		for _, pcs := range batch {
			var err error
			if pcs.present {
				err = c.sendPeerPresent(pcs.peer, pcs.ipPort, pcs.flags, pcs.appName)
			} else {
				err = c.sendPeerGone(pcs.peer, derp.PeerGoneReasonDisconnected)
			}
			if err != nil {
				return err
			}
		}
		lastBatch = batch
	}
}

// sendPacket writes contents to the client in a RecvPacket frame. If
// srcKey.IsZero, uses the old DERPv1 framing format, otherwise uses
// DERPv2. The bytes of contents are only valid until this function
// returns, do not retain slices.
// It does not flush its bufio.Writer.
func (c *sclient) sendPacket(srcKey key.NodePublic, contents []byte) (err error) {
	defer func() {
		// Stats update.
		if err != nil {
			c.s.recordDrop(contents, srcKey, c.key, dropReasonWriteError)
		} else {
			c.s.packetsSent.Add(1)
			c.s.bytesSent.Add(int64(len(contents)))
		}
		if c.debug {
			c.debugLogf("sendPacket from %s: %v", srcKey.ShortString(), err)
		}
	}()

	c.setWriteDeadline()

	withKey := !srcKey.IsZero()
	pktLen := len(contents)
	if withKey {
		pktLen += key.NodePublicRawLen
		c.noteSendFromSrc(srcKey)
		if c.s.trackSenderCardinality {
			c.senderCardinalityMu.Lock()
			if c.senderCardinality == nil {
				c.senderCardinality = hyperloglog.New()
			}
			var raw [key.NodePublicRawLen]byte
			c.senderCardinality.Insert(srcKey.AppendTo(raw[:0]))
			c.senderCardinalityMu.Unlock()
		}
	}
	if err = derp.WriteFrameHeader(c.bw.bw(), derp.FrameRecvPacket, uint32(pktLen)); err != nil {
		return err
	}
	if withKey {
		if err := srcKey.WriteRawWithoutAllocating(c.bw.bw()); err != nil {
			return err
		}
	}
	_, err = c.bw.Write(contents)
	return err
}

// EstimatedUniqueSenders returns an estimate of the number of unique peers
// that have sent packets to this client. It returns 0 if sender
// cardinality tracking is disabled (the default; see
// [Server.trackSenderCardinality]).
func (c *sclient) EstimatedUniqueSenders() uint64 {
	c.senderCardinalityMu.Lock()
	defer c.senderCardinalityMu.Unlock()
	if c.senderCardinality == nil {
		return 0
	}
	return c.senderCardinality.Estimate()
}

// noteSendFromSrc notes that we are about to write a packet
// from src to sclient.
//
// It must only be called from the writer goroutine ([sclient.runWriter]).
func (c *sclient) noteSendFromSrc(src key.NodePublic) {
	if _, ok := c.sawSrc[src]; ok {
		return
	}
	h := c.s.addPeerGoneFromRegionWatcher(src, c.onPeerGoneFromRegion)
	mak.Set(&c.sawSrc, src, h)
}

// AddPacketForwarder registers fwd as a packet forwarder for dst.
// fwd must be comparable.
func (s *Server) AddPacketForwarder(dst key.NodePublic, fwd PacketForwarder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.clientsMesh[dst]; ok {
		if prev == fwd {
			// Duplicate registration of same forwarder. Ignore.
			return
		}
		if m, ok := prev.(*multiForwarder); ok {
			if _, ok := m.all[fwd]; ok {
				// Duplicate registration of same forwarder in set; ignore.
				return
			}
			m.add(fwd)
			return
		}
		if prev != nil {
			// Otherwise, the existing value is not a set,
			// not a dup, and not local-only (nil) so make
			// it a set. `prev` existed first, so will have higher
			// priority.
			fwd = newMultiForwarder(prev, fwd)
			s.multiForwarderCreated.Add(1)
		}
	}
	s.clientsMesh[dst] = fwd
}

// RemovePacketForwarder removes fwd as a packet forwarder for dst.
// fwd must be comparable.
func (s *Server) RemovePacketForwarder(dst key.NodePublic, fwd PacketForwarder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.clientsMesh[dst]
	if !ok {
		return
	}
	if m, ok := v.(*multiForwarder); ok {
		if len(m.all) < 2 {
			panic("unexpected")
		}
		if remain, isLast := m.deleteLocked(fwd); isLast {
			// If fwd was in m and we no longer need to be a
			// multiForwarder, replace the entry with the
			// remaining PacketForwarder.
			s.clientsMesh[dst] = remain
			s.multiForwarderDeleted.Add(1)
		}
		return
	}
	if v != fwd {
		s.removePktForwardOther.Add(1)
		// Delete of an entry that wasn't in the
		// map. Harmless, so ignore.
		// (This might happen if a user is moving around
		// between nodes and/or the server sent duplicate
		// connection change broadcasts.)
		return
	}

	if _, isLocal := s.clients.Load(dst); isLocal {
		s.clientsMesh[dst] = nil
	} else {
		delete(s.clientsMesh, dst)
		s.notePeerGoneFromRegionLocked(dst)
	}
}

// multiForwarder is a PacketForwarder that represents a set of
// forwarding options. It's used in the rare cases that a client is
// connected to multiple DERP nodes in a region. That shouldn't really
// happen except for perhaps during brief moments while the client is
// reconfiguring, in which case we don't want to forget where the
// client is. The map value is unique connection number; the lowest
// one has been seen the longest. It's used to make sure we forward
// packets consistently to the same node and don't pick randomly.
type multiForwarder struct {
	fwd syncs.AtomicValue[PacketForwarder] // preferred forwarder.
	all map[PacketForwarder]uint8          // all forwarders, protected by s.mu.
}

// newMultiForwarder creates a new multiForwarder.
// The first PacketForwarder passed to this function will be the preferred one.
func newMultiForwarder(fwds ...PacketForwarder) *multiForwarder {
	f := &multiForwarder{all: make(map[PacketForwarder]uint8)}
	f.fwd.Store(fwds[0])
	for idx, fwd := range fwds {
		f.all[fwd] = uint8(idx)
	}
	return f
}

// add adds a new forwarder to the map with a connection number that
// is higher than the existing ones.
func (f *multiForwarder) add(fwd PacketForwarder) {
	var max uint8
	for _, v := range f.all {
		if v > max {
			max = v
		}
	}
	f.all[fwd] = max + 1
}

// deleteLocked removes a packet forwarder from the map. It expects Server.mu to be held.
// If only one forwarder remains after the removal, it will be returned alongside a `true` boolean value.
func (f *multiForwarder) deleteLocked(fwd PacketForwarder) (_ PacketForwarder, isLast bool) {
	delete(f.all, fwd)

	if fwd == f.fwd.Load() {
		// The preferred forwarder has been removed, choose a new one
		// based on the lowest index.
		var lowestfwd PacketForwarder
		var lowest uint8
		for k, v := range f.all {
			if lowestfwd == nil || v < lowest {
				lowestfwd = k
				lowest = v
			}
		}
		if lowestfwd != nil {
			f.fwd.Store(lowestfwd)
		}
	}

	if len(f.all) == 1 {
		for k := range f.all {
			return k, true
		}
	}
	return nil, false
}

func (f *multiForwarder) ForwardPacket(src, dst key.NodePublic, payload derp.LoanedBytes) error {
	return f.fwd.Load().ForwardPacket(src, dst, payload)
}

func (f *multiForwarder) String() string {
	return fmt.Sprintf("<MultiForwarder fwd=%s total=%d>", f.fwd.Load(), len(f.all))
}

func (s *Server) expVarFunc(f func() any) expvar.Func {
	return expvar.Func(func() any {
		s.mu.Lock()
		defer s.mu.Unlock()
		return f()
	})
}

// ExpVar returns an expvar variable suitable for registering with expvar.Publish.
func (s *Server) ExpVar(rateLimitEnabled bool) expvar.Var {
	m := new(metrics.Set)
	m.Set("gauge_memstats_sys0", expvar.Func(func() any { return int64(s.memSys0) }))
	m.Set("gauge_watchers", s.expVarFunc(func() any { return len(s.watchers) }))
	m.Set("gauge_current_file_descriptors", expvar.Func(func() any { return metrics.CurrentFDs() }))
	m.Set("gauge_current_connections", &s.curClients)
	m.Set("gauge_current_home_connections", &s.curHomeClients)
	m.Set("gauge_current_notideal_connections", &s.curClientsNotIdeal)
	m.Set("gauge_clients_total", s.expVarFunc(func() any { return len(s.clientsMesh) }))
	m.Set("gauge_clients_local", s.expVarFunc(func() any { return s.numLocalClientKeys }))
	m.Set("gauge_clients_remote", s.expVarFunc(func() any { return len(s.clientsMesh) - s.numLocalClientKeys }))
	m.Set("gauge_current_dup_client_keys", &s.dupClientKeys)
	m.Set("gauge_current_dup_client_conns", &s.dupClientConns)
	m.Set("counter_total_dup_client_conns", &s.dupClientConnTotal)
	m.Set("accepts", &s.accepts)
	m.Set("bytes_received", &s.bytesRecv)
	m.Set("bytes_sent", &s.bytesSent)
	m.Set("counter_packets_received_kind", &s.packetsRecvByKind)
	m.Set("packets_sent", &s.packetsSent)
	m.Set("packets_received", &s.packetsRecv)
	m.Set("unknown_frames", &s.unknownFrames)
	m.Set("home_moves_in", &s.homeMovesIn)
	m.Set("home_moves_out", &s.homeMovesOut)
	m.Set("got_ping", &s.gotPing)
	m.Set("sent_pong", &s.sentPong)
	m.Set("peer_gone_disconnected_frames", &s.peerGoneDisconnectedFrames)
	m.Set("peer_gone_not_here_frames", &s.peerGoneNotHereFrames)
	m.Set("packets_forwarded_out", &s.packetsForwardedOut)
	m.Set("packets_forwarded_in", &s.packetsForwardedIn)
	m.Set("multiforwarder_created", &s.multiForwarderCreated)
	m.Set("multiforwarder_deleted", &s.multiForwarderDeleted)
	m.Set("packet_forwarder_delete_other_value", &s.removePktForwardOther)
	m.Set("sclient_write_timeouts", &s.sclientWriteTimeouts)
	m.Set("average_queue_duration_ms", expvar.Func(func() any {
		return math.Float64frombits(atomic.LoadUint64(s.avgQueueDuration))
	}))
	m.Set("counter_tcp_rtt", &s.tcpRtt)
	m.Set("counter_mesh_update_batch_size", s.meshUpdateBatchSize)
	m.Set("counter_mesh_update_loop_count", s.meshUpdateLoopCount)
	m.Set("counter_buffered_write_frames", s.bufferedWriteFrames)
	var expvarVersion expvar.String
	expvarVersion.Set(version.Long())
	m.Set("version", &expvarVersion)
	if rateLimitEnabled {
		// Rate limiting is currently experimental, its APIs are unstable, and it must
		// be opted-in via --rate-config. Therefore, we only publish related metrics
		// on demand, to avoid polluting uninterested metrics consumers.
		m.Set("rate_limit_per_client_bytes_per_second", s.expVarFunc(func() any {
			return s.rateConfig.PerClientRateLimitBytesPerSec
		}))
		m.Set("rate_limit_per_client_burst_bytes", s.expVarFunc(func() any {
			return s.rateConfig.PerClientRateBurstBytes
		}))
		m.Set("rate_limit_per_client_waited", &s.rateLimitPerClientWaited)
	}
	return m
}

func (s *Server) ConsistencyCheck() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []string

	var nilMeshNotInClient int
	for k, f := range s.clientsMesh {
		if f == nil {
			if _, ok := s.clients.Load(k); !ok {
				nilMeshNotInClient++
			}
		}
	}
	if nilMeshNotInClient != 0 {
		errs = append(errs, fmt.Sprintf("%d s.clientsMesh keys not in s.clients", nilMeshNotInClient))
	}

	var clientNotInMesh int
	for k := range s.clients.All() {
		if _, ok := s.clientsMesh[k]; !ok {
			clientNotInMesh++
		}
	}
	if clientNotInMesh != 0 {
		errs = append(errs, fmt.Sprintf("%d s.clients keys not in s.clientsMesh", clientNotInMesh))
	}

	if s.curClients.Value() != int64(s.numLocalClientKeys) {
		errs = append(errs, fmt.Sprintf("expvar connections = %d != clients map says of %d",
			s.curClients.Value(),
			s.numLocalClientKeys))
	}

	if s.verifyClientsLocalTailscaled {
		if err := s.checkVerifyClientsLocalTailscaled(); err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, ", "))
}

// checkVerifyClientsLocalTailscaled checks that a verifyClients call can be made successfully for the derper hosts own node key.
func (s *Server) checkVerifyClientsLocalTailscaled() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	status, err := s.localClient.StatusWithoutPeers(ctx)
	if err != nil {
		return fmt.Errorf("localClient.Status: %w", err)
	}
	info := &derp.ClientInfo{
		IsProber: true,
	}
	clientIP := netip.IPv6Loopback()
	if err := s.verifyClient(ctx, status.Self.PublicKey, info, clientIP); err != nil {
		return fmt.Errorf("verifyClient for self nodekey: %w", err)
	}
	return nil
}

const minTimeBetweenLogs = 2 * time.Second

// BytesSentRecv records the number of bytes that have been sent since the last traffic check
// for a given process, as well as the public key of the process sending those bytes.
type BytesSentRecv struct {
	Sent uint64
	Recv uint64
	// Key is the public key of the client which sent/received these bytes.
	Key           key.NodePublic
	UniqueSenders uint64 `json:",omitzero"`
}

// parseSSOutput parses the output from the specific call to ss in ServeDebugTraffic.
// Separated out for ease of testing.
func parseSSOutput(raw string) map[netip.AddrPort]BytesSentRecv {
	newState := map[netip.AddrPort]BytesSentRecv{}
	// parse every 2 lines and get src and dst ips, and kv pairs
	lines := strings.Split(raw, "\n")
	for i := 0; i < len(lines); i += 2 {
		ipInfo := strings.Fields(strings.TrimSpace(lines[i]))
		if len(ipInfo) < 5 {
			continue
		}
		src, err := netip.ParseAddrPort(ipInfo[4])
		if err != nil {
			continue
		}
		stats := strings.Fields(strings.TrimSpace(lines[i+1]))
		stat := BytesSentRecv{}
		for _, s := range stats {
			if strings.Contains(s, "bytes_sent") {
				sent, err := strconv.Atoi(s[strings.Index(s, ":")+1:])
				if err == nil {
					stat.Sent = uint64(sent)
				}
			} else if strings.Contains(s, "bytes_received") {
				recv, err := strconv.Atoi(s[strings.Index(s, ":")+1:])
				if err == nil {
					stat.Recv = uint64(recv)
				}
			}
		}
		newState[src] = stat
	}
	return newState
}

// debugTrafficFlushSize is the buffered JSON size at which
// [Server.ServeDebugTraffic] releases the server mutex and writes
// what it has so far to the network.
const debugTrafficFlushSize = 32 << 10

func (s *Server) ServeDebugTraffic(w http.ResponseWriter, r *http.Request) {
	prevState := map[netip.AddrPort]BytesSentRecv{}

	// Records are JSON-encoded into buf while holding s.mu, but
	// are only written to the network with s.mu released, so a
	// slow client can't stall the server. Rather than toggling
	// the lock around every record, we let buf grow to
	// debugTrafficFlushSize before flushing.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for r.Context().Err() == nil {
		output, err := exec.Command("ss", "-i", "-H", "-t").Output()
		if err != nil {
			fmt.Fprintf(w, "ss failed: %v", err)
			return
		}
		newState := parseSSOutput(string(output))
		s.mu.Lock()
		for k, next := range newState {
			prev := prevState[k]
			if prev.Sent < next.Sent || prev.Recv < next.Recv {
				if pkey, ok := s.keyOfAddr[k]; ok {
					next.Key = pkey
					if cs, ok := s.clients.Load(pkey); ok {
						if c := cs.activeClient.Load(); c != nil {
							next.UniqueSenders = c.EstimatedUniqueSenders()
						}
					}
					if err := enc.Encode(next); err != nil {
						s.mu.Unlock()
						return
					}
					if buf.Len() >= debugTrafficFlushSize {
						s.mu.Unlock()
						_, err := w.Write(buf.Bytes())
						buf.Reset()
						if err != nil {
							return
						}
						s.mu.Lock()
					}
				}
			}
		}
		s.mu.Unlock()
		prevState = newState
		buf.WriteByte('\n')
		if _, err := w.Write(buf.Bytes()); err != nil {
			return
		}
		buf.Reset()
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(minTimeBetweenLogs)
	}
}

var bufioWriterPool = &sync.Pool{
	New: func() any {
		return bufio.NewWriterSize(io.Discard, 2<<10)
	},
}

// lazyBufioWriter is a bufio.Writer-like wrapping writer that lazily
// allocates its actual bufio.Writer from a sync.Pool, releasing it to
// the pool upon flush.
//
// We do this to reduce memory overhead; most DERP connections are
// idle and the idle bufio.Writers were 30% of overall memory usage.
type lazyBufioWriter struct {
	w   io.Writer     // underlying
	lbw *bufio.Writer // lazy; nil means it needs an associated buffer
}

func (w *lazyBufioWriter) bw() *bufio.Writer {
	if w.lbw == nil {
		w.lbw = bufioWriterPool.Get().(*bufio.Writer)
		w.lbw.Reset(w.w)
	}
	return w.lbw
}

func (w *lazyBufioWriter) Available() int { return w.bw().Available() }

func (w *lazyBufioWriter) Write(p []byte) (int, error) { return w.bw().Write(p) }

func (w *lazyBufioWriter) Flush() error {
	if w.lbw == nil {
		return nil
	}
	err := w.lbw.Flush()

	w.lbw.Reset(io.Discard)
	bufioWriterPool.Put(w.lbw)
	w.lbw = nil

	return err
}
