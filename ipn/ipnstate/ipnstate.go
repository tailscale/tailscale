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

	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/dnsname"
)

// Status represents the entire state of the IPN network.
type Status struct {
	BackendState string
	TailscaleIPs []netaddr.IP // Tailscale IP(s) assigned to this node
	Self         *PeerStatus

	// MagicDNSSuffix is the network's MagicDNS suffix for nodes
	// in the network such as "userfoo.tailscale.net".
	// There are no surrounding dots.
	// MagicDNSSuffix should be populated regardless of whether a domain
	// has MagicDNS enabled.
	MagicDNSSuffix string

	Peer map[key.Public]*PeerStatus
	User map[tailcfg.UserID]tailcfg.UserProfile
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
	DNSName   string
	OS        string // HostInfo.OS
	UserID    tailcfg.UserID

	TailAddr string // Tailscale IP

	// Endpoints:
	Addrs   []string
	CurAddr string // one of Addrs, or unique if roaming
	Relay   string // DERP region

	RxBytes       int64
	TxBytes       int64
	Created       time.Time // time registered with tailcontrol
	LastWrite     time.Time // time last packet sent
	LastSeen      time.Time // last seen to tailcontrol
	LastHandshake time.Time // with local wireguard
	KeepAlive     bool

	// ShareeNode indicates this node exists in the netmap because
	// it's owned by a shared-to user and that node might connect
	// to us. These nodes should be hidden by "tailscale status"
	// etc by default.
	ShareeNode bool `json:",omitempty"`

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

func (sb *StatusBuilder) SetBackendState(v string) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.st.BackendState = v
}

func (sb *StatusBuilder) SetMagicDNSSuffix(v string) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.st.MagicDNSSuffix = v
}

func (sb *StatusBuilder) Status() *Status {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.locked = true
	return &sb.st
}

// SetSelfStatus sets the status of the local machine.
func (sb *StatusBuilder) SetSelfStatus(ss *PeerStatus) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.st.Self = ss
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

// AddIP adds a Tailscale IP address to the status.
func (sb *StatusBuilder) AddTailscaleIP(ip netaddr.IP) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.locked {
		log.Printf("[unexpected] ipnstate: AddIP after Locked")
		return
	}

	sb.st.TailscaleIPs = append(sb.st.TailscaleIPs, ip)
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
	if v := st.DNSName; v != "" {
		e.DNSName = v
	}
	if v := st.Relay; v != "" {
		e.Relay = v
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
	if v := st.LastWrite; !v.IsZero() {
		e.LastWrite = v
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
	if st.ShareeNode {
		e.ShareeNode = true
	}
}

type StatusUpdater interface {
	UpdateStatus(*StatusBuilder)
}

func (st *Status) WriteHTML(w io.Writer) {
	f := func(format string, args ...interface{}) { fmt.Fprintf(w, format, args...) }

	f(`<!DOCTYPE html>
<html lang="en">
<head>
<title>Tailscale State</title>
<style>
body { font-family: monospace; }
.owner { text-decoration: underline; }
.tailaddr { font-style: italic; }
.acenter { text-align: center; }
.aright { text-align: right; }
table, th, td { border: 1px solid black; border-spacing : 0; border-collapse : collapse; }
thead { background-color: #FFA500; }
th, td { padding: 5px; }
td { vertical-align: top; }
table tbody tr:nth-child(even) td { background-color: #f5f5f5; }
</style>
</head>
<body>
<h1>Tailscale State</h1>
`)

	//f("<p><b>logid:</b> %s</p>\n", logid)
	//f("<p><b>opts:</b> <code>%s</code></p>\n", html.EscapeString(fmt.Sprintf("%+v", opts)))

	ips := make([]string, 0, len(st.TailscaleIPs))
	for _, ip := range st.TailscaleIPs {
		ips = append(ips, ip.String())
	}
	f("<p>Tailscale IP: %s", strings.Join(ips, ", "))

	f("<table>\n<thead>\n")
	f("<tr><th>Peer</th><th>OS</th><th>Node</th><th>Owner</th><th>Rx</th><th>Tx</th><th>Activity</th><th>Connection</th></tr>\n")
	f("</thead>\n<tbody>\n")

	now := time.Now()

	var peers []*PeerStatus
	for _, peer := range st.Peers() {
		ps := st.Peer[peer]
		if ps.ShareeNode {
			continue
		}
		peers = append(peers, ps)
	}
	SortPeers(peers)

	for _, ps := range peers {
		var actAgo string
		if !ps.LastWrite.IsZero() {
			ago := now.Sub(ps.LastWrite)
			actAgo = ago.Round(time.Second).String() + " ago"
			if ago < 5*time.Minute {
				actAgo = "<b>" + actAgo + "</b>"
			}
		}
		var owner string
		if up, ok := st.User[ps.UserID]; ok {
			owner = up.LoginName
			if i := strings.Index(owner, "@"); i != -1 {
				owner = owner[:i]
			}
		}

		hostName := ps.SimpleHostName()
		dnsName := strings.TrimRight(ps.DNSName, ".")
		if i := strings.Index(dnsName, "."); i != -1 && dnsname.HasSuffix(dnsName, st.MagicDNSSuffix) {
			dnsName = dnsName[:i]
		}
		if strings.EqualFold(dnsName, hostName) || ps.UserID != st.Self.UserID {
			hostName = ""
		}
		var hostNameHTML string
		if hostName != "" {
			hostNameHTML = "<br>" + html.EscapeString(hostName)
		}

		f("<tr><td>%s</td><td class=acenter>%s</td>"+
			"<td><b>%s</b>%s<div class=\"tailaddr\">%s</div></td><td class=\"acenter owner\">%s</td><td class=\"aright\">%v</td><td class=\"aright\">%v</td><td class=\"aright\">%v</td>",
			ps.PublicKey.ShortString(),
			osEmoji(ps.OS),
			html.EscapeString(dnsName),
			hostNameHTML,
			ps.TailAddr,
			html.EscapeString(owner),
			ps.RxBytes,
			ps.TxBytes,
			actAgo,
		)
		f("<td>")

		// TODO: let server report this active bool instead
		active := !ps.LastWrite.IsZero() && time.Since(ps.LastWrite) < 2*time.Minute
		if active {
			if ps.Relay != "" && ps.CurAddr == "" {
				f("relay <b>%s</b>", html.EscapeString(ps.Relay))
			} else if ps.CurAddr != "" {
				f("direct <b>%s</b>", html.EscapeString(ps.CurAddr))
			}
		}

		f("</td>") // end Addrs

		f("</tr>\n")
	}
	f("</tbody>\n</table>\n")
	f("</body>\n</html>\n")
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

// PingResult contains response information for the "tailscale ping" subcommand,
// saying how Tailscale can reach a Tailscale IP or subnet-routed IP.
type PingResult struct {
	IP       string // ping destination
	NodeIP   string // Tailscale IP of node handling IP (different for subnet routers)
	NodeName string // DNS name base or (possibly not unique) hostname

	Err            string
	LatencySeconds float64

	Endpoint string // ip:port if direct UDP was used

	DERPRegionID   int    // non-zero if DERP was used
	DERPRegionCode string // three-letter airport/region code if DERP was used

	// TODO(bradfitz): details like whether port mapping was used on either side? (Once supported)
}

func SortPeers(peers []*PeerStatus) {
	sort.Slice(peers, func(i, j int) bool { return sortKey(peers[i]) < sortKey(peers[j]) })
}

func sortKey(ps *PeerStatus) string {
	if ps.DNSName != "" {
		return ps.DNSName
	}
	if ps.HostName != "" {
		return ps.HostName
	}
	return ps.TailAddr
}
