// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derpserver

import (
	"cmp"
	"container/heap"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"tailscale.com/types/key"
)

const (
	debugClientsDefaultLimit = 100
	debugClientsMaxLimit     = 1000
)

// debugClient is a snapshot of one connected client, rendered by
// [Server.ServeDebugClients] as an HTML row or a JSON object.
type debugClient struct {
	ConnNum     int64          `json:"connNum"`
	Key         key.NodePublic `json:"key"`
	Remote      netip.AddrPort `json:"remote"`
	ConnectedAt time.Time      `json:"connectedAt"`
	Connected   time.Duration  `json:"connected"` // how long the connection has been up, in nanoseconds in JSON
	Active      bool           `json:"active"`    // the connection currently receiving packets for Key
	Dup         bool           `json:"dup"`       // Key has more than one connection
	Disabled    bool           `json:"disabled"`  // sends to this connection are disabled due to dups
	Home        bool           `json:"home"`      // client reported this as its preferred (home) DERP
	MeshPeer    bool           `json:"meshPeer"`
	NotIdeal    bool           `json:"notIdeal"`
	Prober      bool           `json:"prober"`
	Version     int            `json:"version"`
	AppName     string         `json:"appName"`
	RxPkts      uint64         `json:"rxPkts"` // data packets received from the client
	RxBytes     uint64         `json:"rxBytes"`
	TxPkts      uint64         `json:"txPkts"` // data packets sent to the client
	TxBytes     uint64         `json:"txBytes"`
	Senders     uint64         `json:"senders"` // estimated number of unique peers that have sent to it
}

// debugClientsSort is the order in which [Server.ServeDebugClients]
// walks the connections. Ties are broken by connection number so
// the order is total and a cursor can resume exactly where the
// previous page stopped.
type debugClientsSort int

const (
	sortClientsByKey       debugClientsSort = iota // node key
	sortClientsByIP                                // remote address and port
	sortClientsByConn                              // connection number (accept order)
	sortClientsByConnected                         // connection time; ascending is longest connected first

	// The traffic counter sorts. They must stay after the sorts
	// above; see [debugClientsSort.isCounter].
	sortClientsByRxBytes
	sortClientsByTxBytes
	sortClientsByRxPkts
	sortClientsByTxPkts
)

// debugClientsSortNames maps each sort to its name in the sort URL
// parameter.
var debugClientsSortNames = map[debugClientsSort]string{
	sortClientsByKey:       "key",
	sortClientsByIP:        "ip",
	sortClientsByConn:      "conn",
	sortClientsByConnected: "connected",
	sortClientsByRxBytes:   "rx",
	sortClientsByTxBytes:   "tx",
	sortClientsByRxPkts:    "rxpkts",
	sortClientsByTxPkts:    "txpkts",
}

func (s debugClientsSort) String() string {
	if name, ok := debugClientsSortNames[s]; ok {
		return name
	}
	return "unknown"
}

// isCounter reports whether s sorts by a traffic counter. Counters
// change while the walk runs, so their value is loaded once per
// connection as it's considered and that value is used for both the
// cursor test and the heap order.
func (s debugClientsSort) isCounter() bool { return s >= sortClientsByRxBytes }

// debugClientsQuery is a parsed /debug/clients/ request: a filter,
// a walk order, a page size, an output format, and optionally a
// cursor after which the page starts.
type debugClientsQuery struct {
	// Primary filter. Exactly one of the fields is set.
	all  bool
	ip   netip.Addr
	cidr netip.Prefix
	key  key.NodePublic

	// hasApps is whether app name filters were given, in which case a
	// connection must also have one of the apps names (an empty
	// string matches connections that sent no app name).
	hasApps bool
	apps    []string

	sort  debugClientsSort
	desc  bool // walk in descending order
	limit int  // maximum connections per page
	json  bool // respond with JSON rather than HTML

	// hasAfter is whether a cursor was given. The page then starts
	// strictly after the cursor in the walk order. Which of the
	// after fields is meaningful depends on sort. For all but the
	// conn sort, afterConn is the connection number tiebreak and is
	// only set if hasAfterConn; a cursor without it, as a person
	// might type by hand, excludes every connection at that value.
	hasAfter     bool
	afterKey     key.NodePublic
	afterAddr    netip.AddrPort
	afterTime    time.Time
	afterN       uint64 // for the counter sorts
	afterConn    int64
	hasAfterConn bool
}

// parseDebugClientsQuery parses r's query parameters. now is used to
// turn a duration cursor for the connected sort into a time.
// It returns ok=false with no error when r has no filter parameters
// at all, in which case the caller should serve the index page.
func parseDebugClientsQuery(r *http.Request, now time.Time) (q *debugClientsQuery, ok bool, err error) {
	v := r.URL.Query()
	q = &debugClientsQuery{limit: debugClientsDefaultLimit}
	q.json = v.Get("format") == "json"
	if f := v.Get("format"); f != "" && f != "json" && f != "html" {
		return nil, false, fmt.Errorf("bad format %q; want json or html", f)
	}

	n := 0
	if v.Has("all") {
		n++
		q.all = true
	}
	if s := v.Get("ip"); s != "" {
		n++
		q.ip, err = netip.ParseAddr(s)
		if err != nil {
			return nil, false, fmt.Errorf("bad ip %q: %w", s, err)
		}
		q.ip = q.ip.Unmap()
	}
	if s := v.Get("cidr"); s != "" {
		n++
		q.cidr, err = netip.ParsePrefix(s)
		if err != nil {
			return nil, false, fmt.Errorf("bad cidr %q: %w", s, err)
		}
		q.cidr = q.cidr.Masked()
	}
	if s := v.Get("key"); s != "" {
		n++
		if err := q.key.UnmarshalText([]byte(s)); err != nil {
			return nil, false, fmt.Errorf("bad key %q: %w", s, err)
		}
	}
	if v.Has("app") {
		q.hasApps = true
		q.apps = v["app"]
	}
	switch n {
	case 0:
		if !q.hasApps {
			return nil, false, nil
		}
		q.all = true // an app filter alone applies to all connections
	case 1:
	default:
		return nil, false, fmt.Errorf("only one of all, ip, cidr, or key may be given")
	}

	if s := v.Get("sort"); s != "" {
		name, desc := strings.CutPrefix(s, "-")
		q.desc = desc
		found := false
		for so, soName := range debugClientsSortNames {
			if soName == name {
				q.sort, found = so, true
				break
			}
		}
		if !found {
			return nil, false, fmt.Errorf("bad sort %q; want key, ip, conn, connected, rx, tx, rxpkts, or txpkts, optionally with a leading -", s)
		}
	}
	if s := v.Get("limit"); s != "" {
		q.limit, err = strconv.Atoi(s)
		if err != nil || q.limit < 1 {
			return nil, false, fmt.Errorf("bad limit %q", s)
		}
		q.limit = min(q.limit, debugClientsMaxLimit)
	}
	if s := v.Get("after"); s != "" {
		q.hasAfter = true
		switch q.sort {
		case sortClientsByKey:
			if err := q.afterKey.UnmarshalText([]byte(s)); err != nil {
				return nil, false, fmt.Errorf("bad after %q for sort by key: %w", s, err)
			}
		case sortClientsByIP:
			q.afterAddr, err = netip.ParseAddrPort(s)
			if err != nil {
				// Also accept a bare address, meaning the
				// page starts after all of its ports in the
				// walk direction.
				addr, err2 := netip.ParseAddr(s)
				if err2 != nil {
					return nil, false, fmt.Errorf("bad after %q for sort by ip: %w", s, err)
				}
				port := uint16(65535)
				if q.desc {
					port = 0
				}
				q.afterAddr = netip.AddrPortFrom(addr, port)
			}
		case sortClientsByConn:
			q.afterConn, err = strconv.ParseInt(s, 10, 64)
			if err != nil {
				return nil, false, fmt.Errorf("bad after %q for sort by conn: %w", s, err)
			}
		case sortClientsByConnected:
			// The next-page links use the connection time in
			// Unix nanoseconds. By hand, a duration such as 30m
			// means connections that have been up that long.
			if ns, err := strconv.ParseInt(s, 10, 64); err == nil {
				q.afterTime = time.Unix(0, ns)
			} else if d, err := time.ParseDuration(s); err == nil {
				q.afterTime = now.Add(-d)
			} else {
				return nil, false, fmt.Errorf("bad after %q for sort by connected; want Unix nanoseconds or a duration", s)
			}
		default:
			q.afterN, err = strconv.ParseUint(s, 10, 64)
			if err != nil {
				return nil, false, fmt.Errorf("bad after %q for sort by %v: %w", s, q.sort, err)
			}
		}
	}
	if s := v.Get("afterconn"); s != "" && q.hasAfter && q.sort != sortClientsByConn {
		q.afterConn, err = strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, false, fmt.Errorf("bad afterconn %q: %w", s, err)
		}
		q.hasAfterConn = true
	}
	return q, true, nil
}

// matches reports whether c passes the query's filters. The key
// filter always matches, as the caller looks that key up directly
// rather than scanning.
func (q *debugClientsQuery) matches(c *sclient) bool {
	switch {
	case q.ip.IsValid():
		if c.remoteIPPort.Addr().Unmap() != q.ip {
			return false
		}
	case q.cidr.IsValid():
		if !q.cidr.Contains(c.remoteIPPort.Addr().Unmap()) {
			return false
		}
	}
	return !q.hasApps || slices.Contains(q.apps, c.info.AppName)
}

// counter returns c's current value of the traffic counter the query
// sorts by, or 0 for the other sorts.
func (q *debugClientsQuery) counter(c *sclient) uint64 {
	switch q.sort {
	case sortClientsByRxBytes:
		return c.bytesRecv.Load()
	case sortClientsByTxBytes:
		return c.bytesSent.Load()
	case sortClientsByRxPkts:
		return c.packetsRecv.Load()
	case sortClientsByTxPkts:
		return c.packetsSent.Load()
	}
	return 0
}

// pageEntry is a connection being considered for the page while
// walking under [Server.mu]. It's snapshotted into a [debugClient]
// after the lock is released.
type pageEntry struct {
	c      *sclient
	active bool
	n      uint64 // the sort counter's value when considered, for the counter sorts
}

// compare orders a and b in the query's walk order.
func (q *debugClientsQuery) compare(a, b pageEntry) int {
	var d int
	switch q.sort {
	case sortClientsByKey:
		d = a.c.key.Compare(b.c.key)
	case sortClientsByIP:
		d = a.c.remoteIPPort.Compare(b.c.remoteIPPort)
	case sortClientsByConn:
	case sortClientsByConnected:
		d = a.c.connectedAt.Compare(b.c.connectedAt)
	default:
		d = cmp.Compare(a.n, b.n)
	}
	d = cmp.Or(d, cmp.Compare(a.c.connNum, b.c.connNum))
	if q.desc {
		d = -d
	}
	return d
}

// pastCursor reports whether e comes after the query's cursor in the
// walk order, and so belongs on this page or a later one.
func (q *debugClientsQuery) pastCursor(e pageEntry) bool {
	if !q.hasAfter {
		return true
	}
	var d int
	switch q.sort {
	case sortClientsByKey:
		d = e.c.key.Compare(q.afterKey)
	case sortClientsByIP:
		d = e.c.remoteIPPort.Compare(q.afterAddr)
	case sortClientsByConn:
		d = cmp.Compare(e.c.connNum, q.afterConn)
	case sortClientsByConnected:
		d = e.c.connectedAt.Compare(q.afterTime)
	default:
		d = cmp.Compare(e.n, q.afterN)
	}
	if d == 0 && q.sort != sortClientsByConn {
		if !q.hasAfterConn {
			return false
		}
		d = cmp.Compare(e.c.connNum, q.afterConn)
	}
	if q.desc {
		d = -d
	}
	return d > 0
}

// sortParam returns the query's sort as it appears in the URL.
func (q *debugClientsQuery) sortParam() string {
	if q.desc {
		return "-" + q.sort.String()
	}
	return q.sort.String()
}

// String returns a short description of the filter for the results page.
func (q *debugClientsQuery) String() string {
	var s string
	switch {
	case q.all:
		s = "all clients"
	case q.ip.IsValid():
		s = "clients from " + q.ip.String()
	case q.cidr.IsValid():
		s = "clients from " + q.cidr.String()
	default:
		s = "connections for " + q.key.String()
	}
	if q.hasApps {
		names := make([]string, len(q.apps))
		for i, a := range q.apps {
			names[i] = cmp.Or(a, "(none)")
		}
		s += " with app " + strings.Join(names, " or ")
	}
	return s
}

// link returns a relative URL for the same filters, page size, and
// format with the given sort and cursor. Empty after means no cursor.
func (q *debugClientsQuery) link(sort, after, afterConn string) string {
	v := url.Values{}
	switch {
	case q.all:
		v.Set("all", "1")
	case q.ip.IsValid():
		v.Set("ip", q.ip.String())
	case q.cidr.IsValid():
		v.Set("cidr", q.cidr.String())
	default:
		v.Set("key", q.key.String())
	}
	if q.hasApps {
		v["app"] = q.apps
	}
	v.Set("sort", sort)
	if after != "" {
		v.Set("after", after)
	}
	if afterConn != "" {
		v.Set("afterconn", afterConn)
	}
	if q.limit != debugClientsDefaultLimit {
		v.Set("limit", strconv.Itoa(q.limit))
	}
	if q.json {
		v.Set("format", "json")
	}
	return "?" + v.Encode()
}

// pageHeap is a max-heap of at most limit entries in the walk order,
// so its top is the selected connection furthest along the walk and
// the one to evict when a nearer connection turns up.
type pageHeap struct {
	q   *debugClientsQuery
	ent []pageEntry
}

func (h *pageHeap) Len() int           { return len(h.ent) }
func (h *pageHeap) Less(i, j int) bool { return h.q.compare(h.ent[i], h.ent[j]) > 0 }
func (h *pageHeap) Swap(i, j int)      { h.ent[i], h.ent[j] = h.ent[j], h.ent[i] }
func (h *pageHeap) Push(x any)         { h.ent = append(h.ent, x.(pageEntry)) }
func (h *pageHeap) Pop() any {
	n := len(h.ent)
	e := h.ent[n-1]
	h.ent = h.ent[:n-1]
	return e
}

// offer adds e to the page if it's among the nearest limit
// connections seen so far, evicting the furthest one if needed.
func (h *pageHeap) offer(e pageEntry) {
	if len(h.ent) < h.q.limit {
		heap.Push(h, e)
		return
	}
	if h.q.compare(e, h.ent[0]) < 0 {
		h.ent[0] = e
		heap.Fix(h, 0)
	}
}

// debugClientsPage is one page of results.
type debugClientsPage struct {
	Clients   []debugClient
	Conns     int // connections matching the filter, ignoring the cursor
	Keys      int // node keys with at least one matching connection
	Remaining int // matching connections after this page in the walk order

	// lastN is the sort counter's value, as used for ordering, of
	// the last entry on the page. It's the next page's cursor for
	// the counter sorts.
	lastN uint64
}

// debugClientsWalk accumulates a [debugClientsPage] while walking
// the connections under [Server.mu]. Per connection it does only a
// filter match, a cursor comparison, and at most a heap operation,
// so the lock hold stays short even with many connections.
type debugClientsWalk struct {
	q    *debugClientsQuery
	h    pageHeap
	page debugClientsPage
	past int // matching connections past the cursor
}

func (w *debugClientsWalk) visit(cs *clientSet) {
	active := cs.activeClient.Load()
	matched := false
	if cs.dup != nil {
		for c := range cs.dup.set {
			if w.consider(c, c == active) {
				matched = true
			}
		}
	} else if active != nil {
		matched = w.consider(active, true)
	}
	if matched {
		w.page.Keys++
	}
}

// consider offers c to the page and reports whether it matched the filter.
func (w *debugClientsWalk) consider(c *sclient, active bool) bool {
	if !w.q.matches(c) {
		return false
	}
	w.page.Conns++
	e := pageEntry{c: c, active: active}
	if w.q.sort.isCounter() {
		e.n = w.q.counter(c)
	}
	if w.q.pastCursor(e) {
		w.past++
		w.h.offer(e)
	}
	return true
}

// debugClientsPage returns the page of connected clients selected by q.
func (s *Server) debugClientsPage(q *debugClientsQuery) debugClientsPage {
	w := &debugClientsWalk{q: q}
	w.h.q = q
	// [parseDebugClientsQuery] already caps limit, but bound the
	// allocation here too so a request's page size demonstrably can't
	// drive a large allocation.
	capHint := q.limit
	if capHint > debugClientsMaxLimit {
		capHint = debugClientsMaxLimit
	}
	w.h.ent = make([]pageEntry, 0, capHint)
	s.mu.Lock()
	if !q.key.IsZero() {
		if cs, ok := s.clients.Load(q.key); ok {
			w.visit(cs)
		}
	} else {
		for _, cs := range s.clients.All() {
			w.visit(cs)
		}
	}
	s.mu.Unlock()

	// The selected clients may have disconnected by now, but
	// [sclient.debugSnapshot] reads only fields that stay valid.
	slices.SortFunc(w.h.ent, q.compare)
	now := s.clock.Now()
	w.page.Clients = make([]debugClient, 0, len(w.h.ent))
	for _, e := range w.h.ent {
		w.page.Clients = append(w.page.Clients, e.c.debugSnapshot(now, e.active))
	}
	if n := len(w.h.ent); n > 0 {
		w.page.lastN = w.h.ent[n-1].n
	}
	w.page.Remaining = w.past - len(w.page.Clients)
	return w.page
}

// debugSnapshot returns a snapshot of c for the debug clients page.
// It only reads fields that are static after construction or are
// read via atomics or their own locks, so it's safe to call from any
// goroutine.
func (c *sclient) debugSnapshot(now time.Time, active bool) debugClient {
	return debugClient{
		ConnNum:     c.connNum,
		Key:         c.key,
		Remote:      c.remoteIPPort,
		ConnectedAt: c.connectedAt,
		Connected:   now.Sub(c.connectedAt).Round(time.Second),
		Active:      active,
		Dup:         c.isDup.Load(),
		Disabled:    c.isDisabled.Load(),
		Home:        c.preferred.Load(),
		MeshPeer:    c.canMesh,
		NotIdeal:    c.isNotIdealConn,
		Prober:      c.info.IsProber,
		Version:     c.info.Version,
		AppName:     c.info.AppName,
		RxPkts:      c.packetsRecv.Load(),
		RxBytes:     c.bytesRecv.Load(),
		TxPkts:      c.packetsSent.Load(),
		TxBytes:     c.bytesSent.Load(),
		Senders:     c.EstimatedUniqueSenders(),
	}
}

// debugClientsView is the data for the results page template.
type debugClientsView struct {
	Query     string
	Sort      debugClientsSort
	Desc      bool
	Page      debugClientsPage
	SortLinks map[string]string // sort name to href that sorts by it, or flips its direction
	NextURL   string            // href of the next page, or empty if this is the last
}

// debugClientsJSON is the format=json response body.
type debugClientsJSON struct {
	Query     string        `json:"query"`     // description of the filter
	Conns     int           `json:"conns"`     // connections matching the filter, ignoring the cursor
	Keys      int           `json:"keys"`      // node keys with at least one matching connection
	Remaining int           `json:"remaining"` // matching connections after this page
	Next      string        `json:"next,omitzero"`
	Clients   []debugClient `json:"clients"`
}

// ServeDebugClients serves the /debug/clients/ page listing connected
// clients.
//
// With no query parameters it serves an index page with a form to
// pick one of the filters below. Otherwise it lists the clients
// matching exactly one of:
//
//	?all             every connected client
//	?ip=1.2.3.4      clients connected from that IP address
//	?cidr=1.2.0.0/16 clients connected from that prefix
//	?key=nodekey:... the connection(s) for that node key
//
// Any of those can be narrowed with app=NAME, repeatable to match any
// of several app names; app alone implies all. An empty app matches
// connections that sent no app name.
//
// Results are paginated. sort=key (the default), ip, conn, connected,
// rx, tx, rxpkts, or txpkts picks the walk order, with a leading - for
// descending; connected ascending is longest connected first. limit=N
// sets the page size. after=X, where X is a value of the sort field,
// starts the page after that value; the next-page links also add
// afterconn=N to resume precisely among connections that share the
// value. For the connected sort, X is a connection time in Unix
// nanoseconds, or a duration such as 30m meaning connections up that
// long. Cursors are applied while walking, so skipped connections are
// never snapshotted.
//
// format=json returns the page as a [debugClientsJSON] object instead
// of HTML, with the next page's relative URL in "next".
//
// The traffic counters keep changing between pages, so walking by
// one of them can show a connection twice or skip it if its counter
// crossed the cursor in between.
func (s *Server) ServeDebugClients(w http.ResponseWriter, r *http.Request) {
	q, ok, err := parseDebugClientsQuery(r, s.clock.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !ok {
		s.mu.Lock()
		keys := s.numLocalClientKeys
		s.mu.Unlock()
		conns := s.curClients.Value()
		if r.URL.Query().Get("format") == "json" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"conns": conns, "keys": keys})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		debugClientsIndexTmpl.Execute(w, map[string]any{
			"Conns": conns,
			"Keys":  keys,
		})
		return
	}
	page := s.debugClientsPage(q)

	var nextURL string
	if page.Remaining > 0 {
		last := page.Clients[len(page.Clients)-1]
		conn := strconv.FormatInt(last.ConnNum, 10)
		switch q.sort {
		case sortClientsByKey:
			nextURL = q.link(q.sortParam(), last.Key.String(), conn)
		case sortClientsByIP:
			nextURL = q.link(q.sortParam(), last.Remote.String(), conn)
		case sortClientsByConn:
			nextURL = q.link(q.sortParam(), conn, "")
		case sortClientsByConnected:
			nextURL = q.link(q.sortParam(), strconv.FormatInt(last.ConnectedAt.UnixNano(), 10), conn)
		default:
			nextURL = q.link(q.sortParam(), strconv.FormatUint(page.lastN, 10), conn)
		}
	}

	if q.json {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "\t")
		enc.Encode(debugClientsJSON{
			Query:     q.String(),
			Conns:     page.Conns,
			Keys:      page.Keys,
			Remaining: page.Remaining,
			Next:      nextURL,
			Clients:   page.Clients,
		})
		return
	}

	v := debugClientsView{
		Query:     q.String(),
		Sort:      q.sort,
		Desc:      q.desc,
		Page:      page,
		SortLinks: map[string]string{},
		NextURL:   nextURL,
	}
	for so, name := range debugClientsSortNames {
		param := name
		if so == q.sort && !q.desc {
			param = "-" + name
		} else if so != q.sort && so.isCounter() {
			// Most traffic first is the useful order for the counters.
			param = "-" + name
		}
		v.SortLinks[name] = q.link(param, "", "")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	debugClientsListTmpl.Execute(w, v)
}

var debugClientsIndexTmpl = template.Must(template.New("").Parse(`<!DOCTYPE html>
<html><head><title>DERP clients</title></head>
<body>
<h1>DERP clients</h1>
<p>{{.Conns}} connections for {{.Keys}} node keys.</p>
<ul>
<li><form method="GET"><button name="all" value="1">List all clients</button></form></li>
<li><form method="GET">By IP address: <input name="ip" size="40" placeholder="1.2.3.4"> <button>Go</button></form></li>
<li><form method="GET">By CIDR: <input name="cidr" size="40" placeholder="1.2.0.0/16"> <button>Go</button></form></li>
<li><form method="GET">By node key: <input name="key" size="80" placeholder="nodekey:8cde7aa8ef94232c9d274ba5422936c639dd6d24688576d919af59277841b430"> <button>Go</button></form></li>
<li><form method="GET">By app name: <input name="app" size="40" placeholder="tailcat-server"> <button>Go</button></form></li>
</ul>
<p>Results are paginated. Click a column header to sort by it or flip its direction.
Optional parameters: app=NAME (repeatable, narrows any filter), sort=key|ip|conn|connected|rx|tx|rxpkts|txpkts (leading - for descending),
limit=N, after=X (a value of the sort column to start after; for connected, Unix nanoseconds or a duration like 30m), format=json.</p>
</body></html>
`))

var debugClientsListTmpl = template.Must(template.New("").Funcs(template.FuncMap{
	"arrow": func(v debugClientsView, name string) string {
		if v.Sort.String() != name {
			return ""
		}
		if v.Desc {
			return " ▼"
		}
		return " ▲"
	},
}).Parse(`<!DOCTYPE html>
<html><head><title>DERP clients: {{.Query}}</title>
<style>
table { border-collapse: collapse; font-family: monospace; }
th, td { border: 1px solid #ccc; padding: 2px 6px; text-align: left; }
td.n { text-align: right; }
</style>
</head>
<body>
<h1>DERP clients: {{.Query}}</h1>
<p><a href="./">index</a></p>
<p>Showing {{len .Page.Clients}} of {{.Page.Conns}} matching connections ({{.Page.Keys}} node keys).
{{if .NextURL}}<a href="{{.NextURL}}">Next page</a> ({{.Page.Remaining}} more){{end}}</p>
<table>
<tr>
<th><a href="{{index .SortLinks "conn"}}">conn#</a>{{arrow . "conn"}}</th>
<th><a href="{{index .SortLinks "key"}}">node key</a>{{arrow . "key"}}</th>
<th><a href="{{index .SortLinks "ip"}}">remote</a>{{arrow . "ip"}}</th>
<th><a href="{{index .SortLinks "connected"}}">connected</a>{{arrow . "connected"}}</th>
<th>flags</th><th>ver</th><th>app</th>
<th><a href="{{index .SortLinks "rxpkts"}}">rx pkts</a>{{arrow . "rxpkts"}}</th>
<th><a href="{{index .SortLinks "rx"}}">rx bytes</a>{{arrow . "rx"}}</th>
<th><a href="{{index .SortLinks "txpkts"}}">tx pkts</a>{{arrow . "txpkts"}}</th>
<th><a href="{{index .SortLinks "tx"}}">tx bytes</a>{{arrow . "tx"}}</th>
<th>senders</th></tr>
{{range .Page.Clients}}<tr>
<td>{{.ConnNum}}</td>
<td><a href="?key={{.Key}}">{{.Key}}</a></td>
<td><a href="?ip={{.Remote.Addr}}">{{.Remote}}</a></td>
<td>{{.Connected}}</td>
<td>{{if .Home}}home {{end}}{{if .MeshPeer}}mesh {{end}}{{if .Prober}}prober {{end}}{{if .NotIdeal}}notideal {{end}}{{if .Dup}}dup{{if .Active}}-active{{end}}{{if .Disabled}}-disabled{{end}}{{end}}</td>
<td>{{.Version}}</td>
<td>{{if .AppName}}<a href="?app={{.AppName}}">{{.AppName}}</a>{{end}}</td>
<td class="n">{{.RxPkts}}</td>
<td class="n">{{.RxBytes}}</td>
<td class="n">{{.TxPkts}}</td>
<td class="n">{{.TxBytes}}</td>
<td class="n">{{.Senders}}</td>
</tr>
{{end}}</table>
{{if .NextURL}}<p><a href="{{.NextURL}}">Next page</a> ({{.Page.Remaining}} more)</p>{{end}}
</body></html>
`))
