package chaos

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"tailscale.com/syncs"
	"tailscale.com/types/netmap"
)

var errCount = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "chaos_errors_total",
	Help: "Number of errors",
}, []string{"type"})

const TimeFileNameFormat = "20060102T150405Z"

func setVerboseOptionsFromFlag(opts *NodeOpts, verbose int) {
	switch verbose {
	case 0:
		opts.userLogf = func(format string, args ...any) {}
	case 1:
		opts.userLogf = log.Printf
	case 2:
		opts.userLogf = log.Printf
		opts.logf = log.Printf
	}
}

func nodeFuncFromFlag(flag string) NewNodeFunc {
	switch flag {
	case "direct":
		return NewNodeDirectAsync
	case "tsnet":
		return NewNodeTSNetAsync
	default:
		log.Fatalf("Unknown node type: %s", joinNNodesArgs.NodeType)
		return nil
	}
}

func tagsToDst(tags []string, port string) []string {
	dsts := make([]string, len(tags))
	for i, tag := range tags {
		dsts[i] = fmt.Sprintf("%s:%s", tag, port)
	}
	return dsts
}

func tagsToTagOwners(owners []string, tags []string) map[string][]string {
	m := make(map[string][]string)
	for _, tag := range tags {
		m[tag] = owners
	}

	return m
}

// tagsMetricLabel returns a string representation of the tags for use in
// metric labels. If noSuffix is true, it will remove any numeric suffixes
// from the tags.
func tagsMetricLabel(tags []string, fullLabels bool) string {
	if len(tags) == 0 {
		return ""
	}
	trim := func(tag string) string {
		if !fullLabels {
			tag = removeNumericSuffix(tag)
		}
		return strings.TrimPrefix(tag, "tag:")
	}
	var b strings.Builder
	b.WriteString(trim(tags[0]))
	for _, tag := range tags[1:] {
		b.WriteString(",")
		b.WriteString(trim(tag))
	}
	return b.String()
}

// removeNumericSuffix removes the numeric suffix from the input string.
func removeNumericSuffix(input string) string {
	// Find the position where the numeric suffix starts
	for i := len(input) - 1; i >= 0; i-- {
		if !unicode.IsDigit(rune(input[i])) {
			return input[:i+1]
		}
	}
	// If the whole string is numeric, return an empty string
	return input
}

// netmapLatencyTracker measures latency between the time a new node
// joins the network and the time it first appears in any of the other nodes'
// netmaps. It relies on chaos nodes having a hostname of the form "chaos-<UUID>".
type netmapLatencyTracker struct {
	countNeverSeen    prometheus.Counter
	countNotFullySeen prometheus.Counter

	firstSeenLatencies *prometheus.HistogramVec
	allSeenLatencies   *prometheus.HistogramVec
	numUnseenFirst     *prometheus.GaugeVec
	numUnseenAll       *prometheus.GaugeVec

	// visibilityUpdates is our queue of updates to unseedFirst/unseenAll which
	// can block. This is a syncs.Map just to ensure it has an independent
	// synchronisation mechanism which is not mu.
	visibilityUpdates syncs.Map[uuid.UUID, visibilityUpdate]
	// visibilityUpdateReadyCh is updated when more work is available on
	// visibilityUpdates.
	visibilityUpdateReadyCh chan struct{}

	mu sync.Mutex

	// visibility is each node's list of peers' IDs.
	// A node does not appear in visibility until we receive its first netmap.
	visibility map[uuid.UUID]map[uuid.UUID]time.Time // node => peers => first seen

	// unseenFirst is a map of node IDs that have joined the network but
	// have not yet appeared in a netmap of any other node.
	unseenFirst map[uuid.UUID]nodeStart
	// unseenAll is a map of node IDs that have joined the network but
	// have not yet appeared in the netmaps of all other nodes.
	unseenAll map[uuid.UUID]nodeStart
}

type visibilityUpdate struct {
	t       time.Time
	self    uuid.UUID
	peers   map[uuid.UUID]bool
	deleted bool
}

type nodeStart struct {
	start     time.Time
	tagsLabel string
}

var latencyTracker *netmapLatencyTracker
var latencyTrackerOnce sync.Once

// newLatencyTracker returns a new netmapLatencyTracker singleton.
func newLatencyTracker() *netmapLatencyTracker {
	latencyTrackerOnce.Do(func() {
		latencyTracker = &netmapLatencyTracker{
			countNeverSeen: promauto.NewCounter(prometheus.CounterOpts{
				Name: "chaos_netmap_tracker_never_seen_nodes",
				Help: "Number of nodes that disappeared before they were seen in any other netmaps",
			}),
			countNotFullySeen: promauto.NewCounter(prometheus.CounterOpts{
				Name: "chaos_netmap_tracker_not_fully_seen_nodes",
				Help: "Number of nodes that disappeared before they were seen in all other nodes' netmaps",
			}),

			firstSeenLatencies: promauto.NewHistogramVec(prometheus.HistogramOpts{
				Name:    "chaos_netmap_distribution_latency_seconds",
				Help:    "Time it took for a new node to be visible in a single netmap",
				Buckets: prometheus.ExponentialBucketsRange(0.01, 30, 20),
			}, []string{"tags"}),
			allSeenLatencies: promauto.NewHistogramVec(prometheus.HistogramOpts{
				Name:    "chaos_netmap_distribution_all_latency_seconds",
				Help:    "Time it took for a new node to be visible in all netmaps",
				Buckets: prometheus.ExponentialBucketsRange(0.01, 30, 20),
			}, []string{"tags"}),
			numUnseenFirst: promauto.NewGaugeVec(prometheus.GaugeOpts{
				Name: "chaos_netmap_tracker_pending_nodes",
				Help: "Number of nodes yet to appear in any other node's netmap",
			}, []string{"tags"}),
			numUnseenAll: promauto.NewGaugeVec(prometheus.GaugeOpts{
				Name: "chaos_netmap_tracker_pending_all_nodes",
				Help: "Number of nodes yet to be appear in all other nodes' netmaps",
			}, []string{"tags"}),

			visibilityUpdateReadyCh: make(chan struct{}),
			visibility:              make(map[uuid.UUID]map[uuid.UUID]time.Time),

			unseenFirst: make(map[uuid.UUID]nodeStart),
			unseenAll:   make(map[uuid.UUID]nodeStart),
		}
		go latencyTracker.backgroundNetmapUpdater()
	})
	return latencyTracker
}

func (t *netmapLatencyTracker) processUpdate(u visibilityUpdate) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if u.deleted {
		id := u.self
		a, neverSeen := t.unseenFirst[id]
		b, notAllSeen := t.unseenAll[id]
		delete(t.unseenAll, id)
		delete(t.unseenFirst, id)

		if neverSeen {
			t.numUnseenFirst.WithLabelValues(a.tagsLabel).Dec()
			t.countNeverSeen.Inc()
		}
		if notAllSeen {
			t.numUnseenAll.WithLabelValues(b.tagsLabel).Dec()
			t.countNotFullySeen.Inc()
		}

		seen, ok := t.visibility[id]
		if ok {
			delete(t.visibility, id)
			for p := range seen {
				t.checkAllVisible(p)
			}
		}
		return
	}

	// Patch the visibility match.
	if t.visibility[u.self] == nil {
		t.visibility[u.self] = make(map[uuid.UUID]time.Time)
	}

	for p := range u.peers {
		vt, ok := t.visibility[u.self][p]
		if ok && u.t.Before(vt) {
			delete(u.peers, p)
			continue
		}
		t.visibility[u.self][p] = u.t
	}

	// u.peers now only newly-visible nodes.
	for p := range u.peers {
		if node, ok := t.unseenFirst[p]; ok {
			t.numUnseenFirst.WithLabelValues(node.tagsLabel).Dec()
			t.firstSeenLatencies.WithLabelValues(node.tagsLabel).Observe(u.t.Sub(node.start).Seconds())
			delete(t.unseenFirst, p)
		}
		t.checkAllVisible(p)
	}
	t.checkAllVisible(u.self)
}

func (t *netmapLatencyTracker) sendUpdate(u visibilityUpdate) {
	t.visibilityUpdates.Store(u.self, u)
	select {
	case t.visibilityUpdateReadyCh <- struct{}{}:
	default:
	}
}

func (t *netmapLatencyTracker) backgroundNetmapUpdater() {
	for {
		<-t.visibilityUpdateReadyCh
		for {
			_, upd, found := takeItem(&t.visibilityUpdates)
			if !found {
				break
			}
			t.processUpdate(upd)
		}
	}
}

// takeItem deletes and returns the first key and it's value visited when
// ranging over the underlying map.
func takeItem[K comparable, V any](m *syncs.Map[K, V]) (key K, val V, ok bool) {
	m.WithLock(func(m map[K]V) {
		for k, v := range m {
			key, val, ok = k, v, true
			delete(m, k)
			return
		}
	})
	return
}

func (t *netmapLatencyTracker) checkAllVisible(p uuid.UUID) {
	node, ok := t.unseenAll[p]
	if !ok {
		return
	}
	if t.visibility[p] == nil {
		return
	}
	var latest time.Time
	for q := range t.visibility[p] {
		t, ok := t.visibility[q][p]
		if !ok {
			// if p can see q, but q does not have a netmap, then assume that
			// p is an older node than q. We mostly only care about p being seen
			// by nodes older than it.
			continue
		}
		if t.After(latest) {
			latest = t
		}
	}

	t.numUnseenAll.WithLabelValues(node.tagsLabel).Dec()
	t.allSeenLatencies.WithLabelValues(node.tagsLabel).Observe(latest.Sub(node.start).Seconds())
	delete(t.unseenAll, p)
}

// Start records node join time, it should be called after a new node
// has joined the network, with that node's UUID.
func (t *netmapLatencyTracker) Start(id uuid.UUID, tagsLabel string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	start := nodeStart{start: time.Now(), tagsLabel: tagsLabel}
	t.unseenFirst[id] = start
	t.numUnseenFirst.WithLabelValues(tagsLabel).Inc()
	t.unseenAll[id] = start
	t.numUnseenAll.WithLabelValues(tagsLabel).Inc()
}

func (t *netmapLatencyTracker) Done(id uuid.UUID) {
	t.sendUpdate(visibilityUpdate{
		t:       time.Now(),
		self:    id,
		deleted: true,
	})
}

// ProcessNetmap should be called every time a new netmap is received.
func (t *netmapLatencyTracker) ProcessNetmap(self uuid.UUID, nm *netmap.NetworkMap) {
	seen := make(map[uuid.UUID]bool)
	for _, p := range nm.Peers {
		id, err := hostnameToUUID(p.Hostinfo().Hostname())
		if err != nil {
			log.Printf("Failed to parse UUID from hostname %q: %v", p.Hostinfo().Hostname(), err)
			errCount.WithLabelValues("tracker-parse-uuid").Inc()
			continue
		}
		seen[id] = true
	}
	t.sendUpdate(visibilityUpdate{
		t:     time.Now(),
		self:  self,
		peers: seen,
	})
}

// uuidToHostname converts a UUID to a hostname.
func uuidToHostname(id uuid.UUID) string {
	return "chaos-" + id.String()
}

// hostnameToUUID converts a hostname to a UUID. It expects the hostname
// to have the format "chaos-<UUID>".
func hostnameToUUID(hostname string) (uuid.UUID, error) {
	hid, ok := strings.CutPrefix(hostname, "chaos-")
	if !ok {
		return uuid.Nil, errors.New("hostname does not have the expected prefix")
	}
	return uuid.Parse(hid)
}

// jticker is a jittered ticker that sends a message to the channel
// at a given interval with +/- 10% jitter.
type jticker <-chan struct{}

// newJitteredTicker creates a new jittered ticker.
func newJitteredTicker(ctx context.Context, after, every time.Duration) jticker {
	ch := make(chan struct{})
	go func() {
		if after > every {
			select {
			case <-time.After(after - every):
			case <-ctx.Done():
				return
			}
		}
		for {
			delay := time.Duration(float64(time.Second) * every.Seconds() * (0.9 + 0.2*rand.Float64()))
			select {
			case <-time.After(delay):
				ch <- struct{}{}
			case <-ctx.Done():
				close(ch)
				return
			}
		}
	}()
	return ch
}
