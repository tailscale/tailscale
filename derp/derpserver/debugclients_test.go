// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// addDebugTestClient registers a fake connected client with s.
func addDebugTestClient(s *Server, k key.NodePublic, remote string, info derp.ClientInfo) *sclient {
	c := &sclient{
		s:            s,
		key:          k,
		logf:         logger.Discard,
		remoteIPPort: netip.MustParseAddrPort(remote),
		connectedAt:  s.clock.Now(),
		info:         info,
	}
	s.accepts.Add(1)
	c.connNum = s.accepts.Value()
	s.registerClient(c)
	return c
}

func getDebugClients(t *testing.T, s *Server, query string) (code int, body string) {
	t.Helper()
	req := httptest.NewRequest("GET", "/debug/clients/"+query, nil)
	rec := httptest.NewRecorder()
	s.ServeDebugClients(rec, req)
	return rec.Code, rec.Body.String()
}

func TestServeDebugClients(t *testing.T) {
	s := New(key.NewNode(), t.Logf)
	defer s.Close()

	// Register three keys: one single connection, one duplicated
	// across two IPs, and one on IPv6.
	k1 := key.NewNode().Public()
	k2 := key.NewNode().Public()
	k3 := key.NewNode().Public()
	addDebugTestClient(s, k1, "10.1.2.3:1111", derp.ClientInfo{Version: 2, AppName: "one"})
	addDebugTestClient(s, k2, "10.1.9.9:2222", derp.ClientInfo{IsProber: true})
	c2b := addDebugTestClient(s, k2, "192.0.2.5:3333", derp.ClientInfo{})
	addDebugTestClient(s, k3, "[2001:db8::1]:4444", derp.ClientInfo{AppName: "tailcat-server"})
	c2b.setPreferred(true)
	c2b.packetsRecv.Store(12)
	c2b.bytesRecv.Store(3456)
	c2b.packetsSent.Store(78)
	c2b.bytesSent.Store(90123)

	tests := []struct {
		name    string
		query   string
		code    int
		want    []string // substrings the body must contain
		wantNot []string // substrings the body must not contain
	}{
		{
			name:  "index",
			query: "",
			code:  200,
			want:  []string{`<form`, `name="ip"`, `name="cidr"`, `name="key"`, `name="all"`, "4 connections for 3 node keys"},
		},
		{
			name:    "all",
			query:   "?all=1",
			code:    200,
			want:    []string{"Showing 4 of 4 matching connections (3 node keys)", k1.String(), k2.String(), k3.String(), "10.1.2.3:1111", "192.0.2.5:3333", "[2001:db8::1]:4444", "one", "prober", "dup-active", "home"},
			wantNot: []string{"Next page"},
		},
		{
			name:    "ip",
			query:   "?ip=10.1.9.9",
			code:    200,
			want:    []string{"Showing 1 of 1 matching connections (1 node keys)", k2.String(), "10.1.9.9:2222", "prober", "dup"},
			wantNot: []string{k1.String(), k3.String(), "192.0.2.5", "dup-active"},
		},
		{
			name:    "ip-v6",
			query:   "?ip=2001:db8::1",
			code:    200,
			want:    []string{"Showing 1 of 1 matching connections (1 node keys)", k3.String()},
			wantNot: []string{k1.String(), k2.String()},
		},
		{
			name:    "cidr",
			query:   "?cidr=10.1.0.0/16",
			code:    200,
			want:    []string{"Showing 2 of 2 matching connections (2 node keys)", k1.String(), k2.String(), "10.1.2.3:1111", "10.1.9.9:2222"},
			wantNot: []string{k3.String(), "192.0.2.5"},
		},
		{
			name:    "cidr-no-match",
			query:   "?cidr=172.16.0.0/12",
			code:    200,
			want:    []string{"Showing 0 of 0 matching connections (0 node keys)"},
			wantNot: []string{k1.String(), k2.String(), k3.String()},
		},
		{
			name:    "key",
			query:   "?key=" + k2.String(),
			code:    200,
			want:    []string{"Showing 2 of 2 matching connections (1 node keys)", "10.1.9.9:2222", "192.0.2.5:3333", "dup-active", "home", `<td class="n">12</td>`, `<td class="n">3456</td>`, `<td class="n">78</td>`, `<td class="n">90123</td>`},
			wantNot: []string{k1.String(), k3.String()},
		},
		{
			name:    "app",
			query:   "?app=one",
			code:    200,
			want:    []string{"all clients with app one", "Showing 1 of 1 matching connections (1 node keys)", k1.String()},
			wantNot: []string{k2.String(), k3.String()},
		},
		{
			name:    "app-either",
			query:   "?app=one&app=tailcat-server&app=nonesuch",
			code:    200,
			want:    []string{"with app one or tailcat-server or nonesuch", "Showing 2 of 2 matching connections (2 node keys)", k1.String(), k3.String(), `href="?app=tailcat-server"`},
			wantNot: []string{k2.String()},
		},
		{
			name:    "app-empty-matches-no-app-name",
			query:   "?app=",
			code:    200,
			want:    []string{"Showing 2 of 2 matching connections (1 node keys)", k2.String()},
			wantNot: []string{k1.String(), k3.String()},
		},
		{
			name:    "app-narrows-cidr",
			query:   "?cidr=10.0.0.0/8&app=one",
			code:    200,
			want:    []string{"clients from 10.0.0.0/8 with app one", "Showing 1 of 1 matching connections (1 node keys)", k1.String()},
			wantNot: []string{k2.String()},
		},
		{
			name:  "app-preserved-in-links",
			query: "?all&app=one&app=tailcat-server&limit=1&sort=conn",
			code:  200,
			want:  []string{"Showing 1 of 2 matching", `href="?after=1&amp;all=1&amp;app=one&amp;app=tailcat-server&amp;limit=1&amp;sort=conn"`},
		},
		{
			name:  "bad-format",
			query: "?all&format=xml",
			code:  400,
			want:  []string{"bad format"},
		},
		{
			name:  "sort-by-tx-desc-next-cursor",
			query: "?all&sort=-tx&limit=1",
			code:  200,
			want:  []string{"192.0.2.5:3333", `href="?after=90123&amp;afterconn=3&amp;all=1&amp;limit=1&amp;sort=-tx"`},
		},
		{
			name:    "key-not-connected",
			query:   "?key=" + key.NewNode().Public().String(),
			code:    200,
			want:    []string{"Showing 0 of 0 matching connections (0 node keys)"},
			wantNot: []string{k1.String()},
		},
		{
			name:  "limit-shows-next-page",
			query: "?all&limit=1&sort=conn",
			code:  200,
			want:  []string{"Showing 1 of 4 matching connections (3 node keys)", "Next page", "(3 more)", "10.1.2.3:1111", `href="?after=1&amp;all=1&amp;limit=1&amp;sort=conn"`},
		},
		{
			name:  "bad-ip",
			query: "?ip=bogus",
			code:  400,
			want:  []string{"bad ip"},
		},
		{
			name:  "bad-cidr",
			query: "?cidr=10.0.0.0",
			code:  400,
			want:  []string{"bad cidr"},
		},
		{
			name:  "bad-key",
			query: "?key=8cde7aa8",
			code:  400,
			want:  []string{"bad key"},
		},
		{
			name:  "bad-sort",
			query: "?all&sort=age",
			code:  400,
			want:  []string{"bad sort"},
		},
		{
			name:  "bad-limit",
			query: "?all&limit=0",
			code:  400,
			want:  []string{"bad limit"},
		},
		{
			name:  "bad-after-for-sort",
			query: "?all&sort=conn&after=nodekey:00",
			code:  400,
			want:  []string{"bad after"},
		},
		{
			name:  "bad-after-for-counter-sort",
			query: "?all&sort=rx&after=-1",
			code:  400,
			want:  []string{"bad after"},
		},
		{
			name:  "multiple-filters",
			query: "?all=1&ip=10.1.2.3",
			code:  400,
			want:  []string{"only one of"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, body := getDebugClients(t, s, tt.query)
			if code != tt.code {
				t.Fatalf("status = %d; want %d; body:\n%s", code, tt.code, body)
			}
			for _, w := range tt.want {
				if !strings.Contains(body, w) {
					t.Errorf("body missing %q:\n%s", w, body)
				}
			}
			for _, w := range tt.wantNot {
				if strings.Contains(body, w) {
					t.Errorf("body unexpectedly contains %q:\n%s", w, body)
				}
			}
		})
	}

	// Output must be HTML with the right content type on success.
	req := httptest.NewRequest("GET", "/debug/clients/?all", nil)
	rec := httptest.NewRecorder()
	s.ServeDebugClients(rec, req)
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("bare ?all status = %d", rec.Code)
	}

	t.Run("json", func(t *testing.T) {
		rec := httptest.NewRecorder()
		s.ServeDebugClients(rec, httptest.NewRequest("GET", "/debug/clients/?key="+k2.String()+"&format=json", nil))
		if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("status %d, Content-Type %q:\n%s", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
		}
		var got debugClientsJSON
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decoding JSON: %v:\n%s", err, rec.Body.String())
		}
		if got.Conns != 2 || got.Keys != 1 || got.Remaining != 0 || got.Next != "" || len(got.Clients) != 2 {
			t.Errorf("summary = %+v", got)
		}
		if got.Query != "connections for "+k2.String() {
			t.Errorf("query = %q", got.Query)
		}
		// Rows sort by key then conn#, so c2b (conn 3) is second.
		c := got.Clients[1]
		if c.ConnNum != 3 || c.Key != k2 || c.Remote != netip.MustParseAddrPort("192.0.2.5:3333") || !c.Home || !c.Dup || !c.Active || c.RxPkts != 12 || c.TxBytes != 90123 || c.ConnectedAt.IsZero() {
			t.Errorf("client = %+v", c)
		}
		// Node keys and addresses must round-trip as their text forms.
		if !strings.Contains(rec.Body.String(), `"key": "`+k2.String()+`"`) || !strings.Contains(rec.Body.String(), `"remote": "192.0.2.5:3333"`) {
			t.Errorf("unexpected encoding:\n%s", rec.Body.String())
		}
	})

	t.Run("json-index", func(t *testing.T) {
		rec := httptest.NewRecorder()
		s.ServeDebugClients(rec, httptest.NewRequest("GET", "/debug/clients/?format=json", nil))
		var got map[string]int
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got["conns"] != 4 || got["keys"] != 3 {
			t.Errorf("index JSON = %v (err %v):\n%s", got, err, rec.Body.String())
		}
	})
}

var (
	debugConnNumRx = regexp.MustCompile(`(?m)^<tr>\n<td>(\d+)</td>$`) // conn# is the first cell of each row
	debugNextRx    = regexp.MustCompile(`<a href="([^"]+)">Next page</a>`)
)

// walkDebugClients follows next-page links from the first page of
// query and returns the connection numbers in the order seen, along
// with the number of pages.
func walkDebugClients(t *testing.T, s *Server, query string) (conns []int64, pages int) {
	t.Helper()
	for query != "" {
		pages++
		if pages > 100 {
			t.Fatal("too many pages; next links don't terminate")
		}
		code, body := getDebugClients(t, s, query)
		if code != 200 {
			t.Fatalf("%s: status %d:\n%s", query, code, body)
		}
		for _, m := range debugConnNumRx.FindAllStringSubmatch(body, -1) {
			var n int64
			fmt.Sscan(m[1], &n)
			conns = append(conns, n)
		}
		query = ""
		if m := debugNextRx.FindStringSubmatch(body); m != nil {
			query = strings.ReplaceAll(m[1], "&amp;", "&")
		}
	}
	return conns, pages
}

// walkDebugClientsJSON is like walkDebugClients but follows the JSON
// form's next links.
func walkDebugClientsJSON(t *testing.T, s *Server, query string) (conns []int64, pages int) {
	t.Helper()
	for query != "" {
		pages++
		if pages > 100 {
			t.Fatal("too many pages; next links don't terminate")
		}
		code, body := getDebugClients(t, s, query)
		if code != 200 {
			t.Fatalf("%s: status %d:\n%s", query, code, body)
		}
		var page debugClientsJSON
		if err := json.Unmarshal([]byte(body), &page); err != nil {
			t.Fatalf("%s: decoding JSON: %v:\n%s", query, err, body)
		}
		for _, c := range page.Clients {
			conns = append(conns, c.ConnNum)
		}
		query = page.Next
	}
	return conns, pages
}

func TestServeDebugClientsPagination(t *testing.T) {
	s := New(key.NewNode(), t.Logf)
	defer s.Close()

	// Seven connections over five keys. One key has three
	// connections from different IPs so that page boundaries fall
	// inside a key (for sort=key) and inside an IP (for sort=ip).
	var clients []*sclient
	dupKey := key.NewNode().Public()
	for i, remote := range []string{"10.0.0.1:1", "10.0.0.2:2", "10.0.0.2:3"} {
		clients = append(clients, addDebugTestClient(s, dupKey, remote, derp.ClientInfo{Version: i}))
	}
	for _, remote := range []string{"10.0.0.3:4", "10.0.0.1:5", "10.0.0.9:6", "10.0.0.5:7"} {
		clients = append(clients, addDebugTestClient(s, key.NewNode().Public(), remote, derp.ClientInfo{}))
	}
	if len(clients) != 7 {
		t.Fatalf("got %d clients", len(clients))
	}
	// Give the traffic counters a mix of distinct and tied values so
	// page boundaries also fall among tied counters, and stagger the
	// connection times so client i has been up (i+1)*10 minutes.
	now := s.clock.Now()
	for i, c := range clients {
		c.bytesRecv.Store(uint64(i * 7 % 5))
		c.bytesSent.Store(uint64(1000 - i*100))
		c.packetsRecv.Store(uint64(i / 2))
		c.packetsSent.Store(uint64(i % 3))
		c.connectedAt = now.Add(-time.Duration(i+1) * 10 * time.Minute)
	}

	// wantOrder returns the connection numbers in the order the
	// given query sorts them.
	wantOrder := func(q *debugClientsQuery) []int64 {
		var ents []pageEntry
		for _, c := range clients {
			ents = append(ents, pageEntry{c: c, n: q.counter(c)})
		}
		slices.SortFunc(ents, q.compare)
		var out []int64
		for _, e := range ents {
			out = append(out, e.c.connNum)
		}
		return out
	}

	for _, sort := range []string{"key", "-key", "ip", "-ip", "conn", "-conn", "connected", "-connected", "rx", "-rx", "tx", "-tx", "rxpkts", "-rxpkts", "txpkts", "-txpkts"} {
		for _, limit := range []int{1, 2, 3, 7, 100} {
			t.Run(fmt.Sprintf("sort=%s/limit=%d", sort, limit), func(t *testing.T) {
				query := fmt.Sprintf("?all&sort=%s&limit=%d", sort, limit)
				req := httptest.NewRequest("GET", "/debug/clients/"+query, nil)
				q, ok, err := parseDebugClientsQuery(req, now)
				if err != nil || !ok {
					t.Fatalf("parse: ok=%v err=%v", ok, err)
				}
				want := wantOrder(q)
				got, pages := walkDebugClients(t, s, query)
				if !slices.Equal(got, want) {
					t.Errorf("walk = %v; want %v", got, want)
				}
				wantPages := (len(clients) + limit - 1) / limit
				if pages != wantPages {
					t.Errorf("pages = %d; want %d", pages, wantPages)
				}

				// The JSON form must walk identically via its next links.
				gotJSON, jsonPages := walkDebugClientsJSON(t, s, query+"&format=json")
				if !slices.Equal(gotJSON, want) {
					t.Errorf("JSON walk = %v; want %v", gotJSON, want)
				}
				if jsonPages != wantPages {
					t.Errorf("JSON pages = %d; want %d", jsonPages, wantPages)
				}
			})
		}
	}

	// sort=connected ascending is longest connected first, and a
	// duration cursor means connections up at most that long.
	t.Run("connected", func(t *testing.T) {
		got, _ := walkDebugClients(t, s, "?all&sort=connected&limit=3")
		if want := []int64{7, 6, 5, 4, 3, 2, 1}; !slices.Equal(got, want) {
			t.Errorf("longest connected first = %v; want %v", got, want)
		}
		// 35m falls between clients so the handler's slightly later
		// clock reading can't move a client across the cursor.
		got, _ = walkDebugClients(t, s, "?all&sort=connected&after=35m")
		if want := []int64{3, 2, 1}; !slices.Equal(got, want) { // up 30m, 20m, 10m
			t.Errorf("after=35m = %v; want %v", got, want)
		}
		got, _ = walkDebugClients(t, s, "?all&sort=-connected&after=35m")
		if want := []int64{4, 5, 6, 7}; !slices.Equal(got, want) { // up 40m..70m, newest first
			t.Errorf("-connected after=35m = %v; want %v", got, want)
		}
		code, body := getDebugClients(t, s, "?all&sort=connected&after=soon")
		if code != 400 || !strings.Contains(body, "bad after") {
			t.Errorf("bad duration cursor: status %d:\n%s", code, body)
		}
	})

	// A hand-typed cursor without afterconn skips every connection
	// at that value.
	t.Run("bare-cursor", func(t *testing.T) {
		code, body := getDebugClients(t, s, "?all&sort=key&after="+dupKey.String())
		if code != 200 {
			t.Fatalf("status %d", code)
		}
		if strings.Contains(body, dupKey.String()) {
			t.Errorf("page after %v still lists it:\n%s", dupKey, body)
		}
		wantAfter := 0 // connections whose (random) key sorts after dupKey
		for _, c := range clients {
			if c.key.Compare(dupKey) > 0 {
				wantAfter++
			}
		}
		if want := fmt.Sprintf("Showing %d of 7 matching connections (5 node keys)", wantAfter); !strings.Contains(body, want) {
			t.Errorf("summary missing %q:\n%s", want, body)
		}

		for _, tt := range []struct {
			query    string
			wantRows []int64
		}{
			{"?all&sort=ip&after=10.0.0.2", []int64{4, 7, 6}},      // 10.0.0.3:4, 10.0.0.5:7, 10.0.0.9:6
			{"?all&sort=-ip&after=10.0.0.2", []int64{5, 1}},        // 10.0.0.1:5, 10.0.0.1:1
			{"?all&sort=ip&after=10.0.0.2:2", []int64{3, 4, 7, 6}}, // an exact addr:port is a precise cursor
		} {
			got, _ := walkDebugClients(t, s, tt.query)
			if !slices.Equal(got, tt.wantRows) {
				t.Errorf("%s: rows = %v; want %v", tt.query, got, tt.wantRows)
			}
		}
	})

	// The cursor applies to the filtered set and counts are for
	// the filter, not the page.
	t.Run("cursor-with-filter", func(t *testing.T) {
		got, pages := walkDebugClients(t, s, "?cidr=10.0.0.0/30&sort=-conn&limit=2")
		if want := []int64{5, 4, 3, 2, 1}; !slices.Equal(got, want) {
			t.Errorf("walk = %v; want %v", got, want)
		}
		if pages != 3 {
			t.Errorf("pages = %d; want 3", pages)
		}
	})
}

// BenchmarkDebugClientsPage measures the cost of one page request
// against many connected clients, which is mostly the walk done
// under Server.mu.
func BenchmarkDebugClientsPage(b *testing.B) {
	s := New(key.NewNode(), logger.Discard)
	defer s.Close()
	const numClients = 100_000
	for i := range numClients {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		c := &sclient{
			s:            s,
			key:          key.NewNode().Public(),
			logf:         logger.Discard,
			remoteIPPort: netip.AddrPortFrom(ip, 4000),
			connectedAt:  s.clock.Now(),
			connNum:      int64(i),
		}
		s.registerClient(c)
	}
	for _, sort := range []string{"key", "ip", "-conn", "-tx"} {
		b.Run("sort="+sort, func(b *testing.B) {
			req := httptest.NewRequest("GET", "/debug/clients/?all&sort="+sort, nil)
			q, _, err := parseDebugClientsQuery(req, time.Now())
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for range b.N {
				page := s.debugClientsPage(q)
				if len(page.Clients) != debugClientsDefaultLimit || page.Conns != numClients {
					b.Fatalf("got %d clients of %d", len(page.Clients), page.Conns)
				}
			}
		})
	}
}
