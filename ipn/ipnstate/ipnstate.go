// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ipnstate captures the entire state of the Tailscale network.
//
// It's a leaf package so ipn, wgengine, and magicsock can all depend on it.
package ipnstate

import (
	"bytes"
	"fmt"
	"html"
	"io"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// Status represents the entire state of the IPN network.
type Status struct {
	BackendState string
	Peer         map[key.Public]*PeerStatus
	User         map[tailcfg.UserID]tailcfg.UserProfile
}

func (s *Status) Peers() []key.Public {
	kk := make([]key.Public, 0, len(s.Peer))
	for k := range s.Peer {
		kk = append(kk, k)
	}
	sort.Slice(kk, func(i, j int) bool { return bytes.Compare(kk[i][:], kk[j][:]) < 0 })
	return kk
}

type PeerStatus struct {
	PublicKey key.Public
	HostName  string // HostInfo's Hostname (not a DNS name or necessarily unique)
	OS        string // HostInfo.OS
	UserID    tailcfg.UserID

	TailAddr string // Tailscale IP

	// Endpoints:
	Addrs   []string
	CurAddr string // one of Addrs, or unique if roaming

	RxBytes       int64
	TxBytes       int64
	Created       time.Time // time registered with tailcontrol
	LastSeen      time.Time // last seen to tailcontrol
	LastHandshake time.Time // with local wireguard
	KeepAlive     bool

	// InNetworkMap means that this peer was seen in our latest network map.
	// In theory, all of InNetworkMap and InMagicSock and InEngine should all be true.
	InNetworkMap bool

	// InMagicSock means that this peer is being tracked by magicsock.
	// In theory, all of InNetworkMap and InMagicSock and InEngine should all be true.
	InMagicSock bool

	// InEngine means that this peer is tracked by the wireguard engine.
	// In theory, all of InNetworkMap and InMagicSock and InEngine should all be true.
	InEngine bool
}

// SimpleHostName returns a potentially simplified version of ps.HostName for display purposes.
func (ps *PeerStatus) SimpleHostName() string {
	n := ps.HostName
	n = strings.TrimSuffix(n, ".local")
	n = strings.TrimSuffix(n, ".localdomain")
	return n
}

type StatusBuilder struct {
	mu     sync.Mutex
	locked bool
	st     Status
}

func (sb *StatusBuilder) Status() *Status {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.locked = true
	return &sb.st
}

// AddUser adds a user profile to the status.
func (sb *StatusBuilder) AddUser(id tailcfg.UserID, up tailcfg.UserProfile) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.locked {
		log.Printf("[unexpected] ipnstate: AddUser after Locked")
		return
	}

	if sb.st.User == nil {
		sb.st.User = make(map[tailcfg.UserID]tailcfg.UserProfile)
	}

	sb.st.User[id] = up
}

// AddPeer adds a peer node to the status.
//
// Its PeerStatus is mixed with any previous status already added.
func (sb *StatusBuilder) AddPeer(peer key.Public, st *PeerStatus) {
	if st == nil {
		panic("nil PeerStatus")
	}

	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.locked {
		log.Printf("[unexpected] ipnstate: AddPeer after Locked")
		return
	}

	if sb.st.Peer == nil {
		sb.st.Peer = make(map[key.Public]*PeerStatus)
	}
	e, ok := sb.st.Peer[peer]
	if !ok {
		sb.st.Peer[peer] = st
		st.PublicKey = peer
		return
	}

	if v := st.HostName; v != "" {
		e.HostName = v
	}
	if v := st.UserID; v != 0 {
		e.UserID = v
	}
	if v := st.TailAddr; v != "" {
		e.TailAddr = v
	}
	if v := st.OS; v != "" {
		e.OS = st.OS
	}
	if v := st.Addrs; v != nil {
		e.Addrs = v
	}
	if v := st.CurAddr; v != "" {
		e.CurAddr = v
	}
	if v := st.RxBytes; v != 0 {
		e.RxBytes = v
	}
	if v := st.TxBytes; v != 0 {
		e.TxBytes = v
	}
	if v := st.LastHandshake; !v.IsZero() {
		e.LastHandshake = v
	}
	if v := st.Created; !v.IsZero() {
		e.Created = v
	}
	if v := st.LastSeen; !v.IsZero() {
		e.LastSeen = v
	}
	if st.InNetworkMap {
		e.InNetworkMap = true
	}
	if st.InMagicSock {
		e.InMagicSock = true
	}
	if st.InEngine {
		e.InEngine = true
	}
	if st.KeepAlive {
		e.KeepAlive = true
	}
}

type StatusUpdater interface {
	UpdateStatus(*StatusBuilder)
}

func (st *Status) WriteHTML(w io.Writer) {
	f := func(format string, args ...interface{}) { fmt.Fprintf(w, format, args...) }

	f(`<html><head><style>
.owner { font-size: 80%%; color: #444; }
.tailaddr { font-size: 80%%; font-family: monospace: }
</style></head>`)
	f("<body><h1>Tailscale State</h1>")
	//f("<p><b>logid:</b> %s</p>\n", logid)
	//f("<p><b>opts:</b> <code>%s</code></p>\n", html.EscapeString(fmt.Sprintf("%+v", opts)))

	f("<table border=1 cellpadding=5><tr><th>Peer</th><th>Node</th><th>Rx</th><th>Tx</th><th>Handshake</th><th>Endpoints</th></tr>")

	now := time.Now()

	// The tailcontrol server rounds LastSeen to 10 minutes. So we
	// declare that a longAgo seen time of 15 minutes means
	// they're not connected.
	longAgo := now.Add(-15 * time.Minute)

	for _, peer := range st.Peers() {
		ps := st.Peer[peer]
		var hsAgo string
		if !ps.LastHandshake.IsZero() {
			hsAgo = now.Sub(ps.LastHandshake).Round(time.Second).String() + " ago"
		} else {
			if ps.LastSeen.Before(longAgo) {
				hsAgo = "<i>offline</i>"
			} else if !ps.KeepAlive {
				hsAgo = "on demand"
			} else {
				hsAgo = "<b>pending</b>"
			}
		}
		var owner string
		if up, ok := st.User[ps.UserID]; ok {
			owner = up.LoginName
			if i := strings.Index(owner, "@"); i != -1 {
				owner = owner[:i]
			}
		}
		f("<tr><td>%s</td><td>%s<div class=owner>%s</div><div class=tailaddr>%s</div></td><td>%v</td><td>%v</td><td>%v</td>",
			peer.ShortString(),
			osEmoji(ps.OS)+" "+html.EscapeString(ps.SimpleHostName()),
			html.EscapeString(owner),
			ps.TailAddr,
			ps.RxBytes,
			ps.TxBytes,
			hsAgo,
		)
		f("<td>")
		match := false
		for _, addr := range ps.Addrs {
			if addr == ps.CurAddr {
				match = true
				f("<b>%s</b> 🔗<br>\n", addr)
			} else {
				f("%s<br>\n", addr)
			}
		}
		if ps.CurAddr != "" && !match {
			f("<b>%s</b> \xf0\x9f\xa7\xb3<br>\n", ps.CurAddr)
		}
		f("</tr>") // end Addrs

		f("</tr>\n")
	}
	f("</table>")
}

func osEmoji(os string) string {
	switch os {
	case "linux":
		return "🐧"
	case "macOS":
		return "🍎"
	case "windows":
		return "🖥️"
	case "iOS":
		return "📱"
	case "android":
		return "🤖"
	case "freebsd":
		return "👿"
	case "openbsd":
		return "🐡"
	}
	return "👽"
}
