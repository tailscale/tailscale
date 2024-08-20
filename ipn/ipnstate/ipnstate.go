// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ipnstate captures the entire state of the Tailscale network.
//
// It's a leaf package so ipn, wgengine, and magicsock can all depend on it.
package ipnstate

import (
	"fmt"
	"html"
	"io"
	"log"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
	"tailscale.com/util/dnsname"
	"tailscale.com/version"
)

//go:generate go run tailscale.com/cmd/cloner  -clonefunc=false -type=TKAPeer

// Status represents the entire state of the IPN network.
type Status struct {
	// Version is the daemon's long version (see version.Long).
	Version string

	// TUN is whether /dev/net/tun (or equivalent kernel interface) is being
	// used. If false, it's running in userspace mode.
	TUN bool

	// BackendState is an ipn.State string value:
	//  "NoState", "NeedsLogin", "NeedsMachineAuth", "Stopped",
	//  "Starting", "Running".
	BackendState string

	// HaveNodeKey is whether the current profile has a node key configured.
	HaveNodeKey bool `json:",omitempty"`

	AuthURL      string       // current URL provided by control to authorize client
	TailscaleIPs []netip.Addr // Tailscale IP(s) assigned to this node
	Self         *PeerStatus

	// ExitNodeStatus describes the current exit node.
	// If nil, an exit node is not in use.
	ExitNodeStatus *ExitNodeStatus `json:"ExitNodeStatus,omitempty"`

	// Health contains health check problems.
	// Empty means everything is good. (or at least that no known
	// problems are detected)
	Health []string

	// This field is the legacy name of CurrentTailnet.MagicDNSSuffix.
	//
	// Deprecated: use CurrentTailnet.MagicDNSSuffix instead.
	MagicDNSSuffix string

	// CurrentTailnet is information about the tailnet that the node
	// is currently connected to. When not connected, this field is nil.
	CurrentTailnet *TailnetStatus

	// CertDomains are the set of DNS names for which the control
	// plane server will assist with provisioning TLS
	// certificates. See SetDNSRequest for dns-01 ACME challenges
	// for e.g. LetsEncrypt. These names are FQDNs without
	// trailing periods, and without any "_acme-challenge." prefix.
	CertDomains []string

	// Peer is the state of each peer, keyed by each peer's current public key.
	Peer map[key.NodePublic]*PeerStatus

	// User contains profile information about UserIDs referenced by
	// PeerStatus.UserID, PeerStatus.AltSharerUserID, etc.
	User map[tailcfg.UserID]tailcfg.UserProfile

	// ClientVersion, when non-nil, contains information about the latest
	// version of the Tailscale client that's available. Depending on
	// the platform and client settings, it may not be available.
	ClientVersion *tailcfg.ClientVersion
}

// TKAKey describes a key trusted by network lock.
type TKAKey struct {
	Key      key.NLPublic
	Metadata map[string]string
	Votes    uint
}

// TKAPeer describes a peer and its network lock details.
type TKAPeer struct {
	Name             string // DNS
	ID               tailcfg.NodeID
	StableID         tailcfg.StableNodeID
	TailscaleIPs     []netip.Addr // Tailscale IP(s) assigned to this node
	NodeKey          key.NodePublic
	NodeKeySignature tka.NodeKeySignature
}

// NetworkLockStatus represents whether network-lock is enabled,
// along with details about the locally-known state of the tailnet
// key authority.
type NetworkLockStatus struct {
	// Enabled is true if network lock is enabled.
	Enabled bool

	// Head describes the AUM hash of the leaf AUM. Head is nil
	// if network lock is not enabled.
	Head *[32]byte

	// PublicKey describes the node's network-lock public key.
	// It may be zero if the node has not logged in.
	PublicKey key.NLPublic

	// NodeKey describes the node's current node-key. This field is not
	// populated if the node is not operating (i.e. waiting for a login).
	NodeKey *key.NodePublic

	// NodeKeySigned is true if our node is authorized by network-lock.
	NodeKeySigned bool

	// NodeKeySignature is the current signature of this node's key.
	NodeKeySignature *tka.NodeKeySignature

	// TrustedKeys describes the keys currently trusted to make changes
	// to network-lock.
	TrustedKeys []TKAKey

	// VisiblePeers describes peers which are visible in the netmap that
	// have valid Tailnet Lock signatures signatures.
	VisiblePeers []*TKAPeer

	// FilteredPeers describes peers which were removed from the netmap
	// (i.e. no connectivity) because they failed tailnet lock
	// checks.
	FilteredPeers []*TKAPeer

	// StateID is a nonce associated with the network lock authority,
	// generated upon enablement. This field is not populated if the
	// network lock is disabled.
	StateID uint64
}

// NetworkLockUpdate describes a change to network-lock state.
type NetworkLockUpdate struct {
	Hash   [32]byte
	Change string // values of tka.AUMKind.String()

	// Raw contains the serialized AUM. The AUM is sent in serialized
	// form to avoid transitive dependences bloating this package.
	Raw []byte
}

// TailnetStatus is information about a Tailscale network ("tailnet").
type TailnetStatus struct {
	// Name is the name of the network that's currently in use.
	Name string

	// MagicDNSSuffix is the network's MagicDNS suffix for nodes
	// in the network such as "userfoo.tailscale.net".
	// There are no surrounding dots.
	// MagicDNSSuffix should be populated regardless of whether a domain
	// has MagicDNS enabled.
	MagicDNSSuffix string

	// MagicDNSEnabled is whether or not the network has MagicDNS enabled.
	// Note that the current device may still not support MagicDNS if
	// `--accept-dns=false` was used.
	MagicDNSEnabled bool
}

// ExitNodeStatus describes the current exit node.
type ExitNodeStatus struct {
	// ID is the exit node's ID.
	ID tailcfg.StableNodeID

	// Online is whether the exit node is alive.
	Online bool

	// TailscaleIPs are the exit node's IP addresses assigned to the node.
	TailscaleIPs []netip.Prefix
}

func (s *Status) Peers() []key.NodePublic {
	kk := make([]key.NodePublic, 0, len(s.Peer))
	for k := range s.Peer {
		kk = append(kk, k)
	}
	sort.Slice(kk, func(i, j int) bool { return kk[i].Less(kk[j]) })
	return kk
}

type PeerStatusLite struct {
	// NodeKey is this peer's public node key.
	NodeKey key.NodePublic

	// TxBytes/RxBytes are the total number of bytes transmitted to/received
	// from this peer.
	TxBytes, RxBytes int64

	// LastHandshake is the last time a handshake succeeded with this peer. (Or
	// we got key confirmation via the first data message, which is
	// approximately the same thing.)
	//
	// The time.Time zero value means that no handshake has succeeded, at least
	// since this peer was last known to WireGuard. (Tailscale removes peers
	// from the wireguard peer that are idle.)
	LastHandshake time.Time
}

// PeerStatus describes a peer node and its current state.
type PeerStatus struct {
	ID        tailcfg.StableNodeID
	PublicKey key.NodePublic
	HostName  string // HostInfo's Hostname (not a DNS name or necessarily unique)

	// DNSName is the Peer's FQDN. It ends with a dot.
	// It has the form "host.<MagicDNSSuffix>."
	DNSName string
	OS      string // HostInfo.OS
	UserID  tailcfg.UserID

	// AltSharerUserID is the user who shared this node
	// if it's different than UserID. Otherwise it's zero.
	AltSharerUserID tailcfg.UserID `json:",omitempty"`

	// TailscaleIPs are the IP addresses assigned to the node.
	TailscaleIPs []netip.Addr
	// AllowedIPs are IP addresses allowed to route to this node.
	AllowedIPs *views.Slice[netip.Prefix] `json:",omitempty"`

	// Tags are the list of ACL tags applied to this node.
	// See tailscale.com/tailcfg#Node.Tags for more information.
	Tags *views.Slice[string] `json:",omitempty"`

	// PrimaryRoutes are the routes this node is currently the primary
	// subnet router for, as determined by the control plane. It does
	// not include the IPs in TailscaleIPs.
	PrimaryRoutes *views.Slice[netip.Prefix] `json:",omitempty"`

	// Endpoints:
	Addrs   []string
	CurAddr string // one of Addrs, or unique if roaming
	Relay   string // DERP region

	RxBytes        int64
	TxBytes        int64
	Created        time.Time // time registered with tailcontrol
	LastWrite      time.Time // time last packet sent
	LastSeen       time.Time // last seen to tailcontrol; only present if offline
	LastHandshake  time.Time // with local wireguard
	Online         bool      // whether node is connected to the control plane
	ExitNode       bool      // true if this is the currently selected exit node.
	ExitNodeOption bool      // true if this node can be an exit node (offered && approved)

	// Active is whether the node was recently active. The
	// definition is somewhat undefined but has historically and
	// currently means that there was some packet sent to this
	// peer in the past two minutes. That definition is subject to
	// change.
	Active bool

	// PeerAPIURL are the URLs of the node's PeerAPI servers.
	PeerAPIURL []string

	// Capabilities are capabilities that the node has.
	// They're free-form strings, but should be in the form of URLs/URIs
	// such as:
	//    "https://tailscale.com/cap/is-admin"
	//    "https://tailscale.com/cap/file-sharing"
	//    "funnel"
	//
	// Deprecated: use CapMap instead. See https://github.com/tailscale/tailscale/issues/11508
	// Every value is Capabilities is also a key in CapMap, even if it
	// has no values in that map.
	Capabilities []tailcfg.NodeCapability `json:",omitempty"`

	// CapMap is a map of capabilities to their values.
	CapMap tailcfg.NodeCapMap `json:",omitempty"`

	// SSH_HostKeys are the node's SSH host keys, if known.
	SSH_HostKeys []string `json:"sshHostKeys,omitempty"`

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

	// Expired means that this peer's node key has expired, based on either
	// information from control or optimisically set on the client if the
	// expiration time has passed.
	Expired bool `json:",omitempty"`

	// KeyExpiry, if present, is the time at which the node key expired or
	// will expire.
	KeyExpiry *time.Time `json:",omitempty"`

	Location *tailcfg.Location `json:",omitempty"`
}

// HasCap reports whether ps has the given capability.
func (ps *PeerStatus) HasCap(cap tailcfg.NodeCapability) bool {
	return ps.CapMap.Contains(cap)
}

// IsTagged reports whether ps is tagged.
func (ps *PeerStatus) IsTagged() bool {
	return ps.Tags != nil && ps.Tags.Len() > 0
}

// StatusBuilder is a request to construct a Status. A new StatusBuilder is
// passed to various subsystems which then call methods on it to populate state.
// Call its Status method to return the final constructed Status.
type StatusBuilder struct {
	WantPeers bool // whether caller wants peers

	locked bool
	st     Status
}

// MutateStatus calls f with the status to mutate.
//
// It may not assume other fields of status are already populated, and
// may not retain or write to the Status after f returns.
func (sb *StatusBuilder) MutateStatus(f func(*Status)) {
	f(&sb.st)
}

// Status returns the status that has been built up so far from previous
// calls to MutateStatus, MutateSelfStatus, AddPeer, etc.
func (sb *StatusBuilder) Status() *Status {
	sb.locked = true
	return &sb.st
}

// MutateSelfStatus calls f with the PeerStatus of our own node to mutate.
//
// It may not assume other fields of status are already populated, and
// may not retain or write to the Status after f returns.
//
// MutateStatus acquires a lock so f must not call back into sb.
func (sb *StatusBuilder) MutateSelfStatus(f func(*PeerStatus)) {
	if sb.st.Self == nil {
		sb.st.Self = new(PeerStatus)
	}
	f(sb.st.Self)
}

// AddUser adds a user profile to the status.
func (sb *StatusBuilder) AddUser(id tailcfg.UserID, up tailcfg.UserProfile) {
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
func (sb *StatusBuilder) AddTailscaleIP(ip netip.Addr) {
	if sb.locked {
		log.Printf("[unexpected] ipnstate: AddIP after Locked")
		return
	}

	sb.st.TailscaleIPs = append(sb.st.TailscaleIPs, ip)
}

// AddPeer adds a peer node to the status.
//
// Its PeerStatus is mixed with any previous status already added.
func (sb *StatusBuilder) AddPeer(peer key.NodePublic, st *PeerStatus) {
	if st == nil {
		panic("nil PeerStatus")
	}

	if sb.locked {
		log.Printf("[unexpected] ipnstate: AddPeer after Locked")
		return
	}

	if sb.st.Peer == nil {
		sb.st.Peer = make(map[key.NodePublic]*PeerStatus)
	}
	e, ok := sb.st.Peer[peer]
	if !ok {
		sb.st.Peer[peer] = st
		st.PublicKey = peer
		return
	}

	if v := st.ID; v != "" {
		e.ID = v
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
	if v := st.AltSharerUserID; v != 0 {
		e.AltSharerUserID = v
	}
	if v := st.TailscaleIPs; v != nil {
		e.TailscaleIPs = v
	}
	if v := st.PrimaryRoutes; v != nil && !v.IsNil() {
		e.PrimaryRoutes = v
	}
	if v := st.AllowedIPs; v != nil && !v.IsNil() {
		e.AllowedIPs = v
	}
	if v := st.Tags; v != nil && !v.IsNil() {
		e.Tags = v
	}
	if v := st.OS; v != "" {
		e.OS = st.OS
	}
	if v := st.SSH_HostKeys; v != nil {
		e.SSH_HostKeys = v
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
	if st.Online {
		e.Online = true
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
	if st.ExitNode {
		e.ExitNode = true
	}
	if st.ExitNodeOption {
		e.ExitNodeOption = true
	}
	if st.ShareeNode {
		e.ShareeNode = true
	}
	if st.Active {
		e.Active = true
	}
	if st.PeerAPIURL != nil {
		e.PeerAPIURL = st.PeerAPIURL
	}
	if st.Expired {
		e.Expired = true
	}
	if t := st.KeyExpiry; t != nil {
		e.KeyExpiry = ptr.To(*t)
	}
	if v := st.CapMap; v != nil {
		e.CapMap = v
	}
	if v := st.Capabilities; v != nil {
		e.Capabilities = v
	}
	e.Location = st.Location
}

type StatusUpdater interface {
	UpdateStatus(*StatusBuilder)
}

func (st *Status) WriteHTML(w io.Writer) {
	f := func(format string, args ...any) { fmt.Fprintf(w, format, args...) }

	f(`<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
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

		hostName := dnsname.SanitizeHostname(ps.HostName)
		dnsName := dnsname.TrimSuffix(ps.DNSName, st.MagicDNSSuffix)
		if strings.EqualFold(dnsName, hostName) || ps.UserID != st.Self.UserID {
			hostName = ""
		}
		var hostNameHTML string
		if hostName != "" {
			hostNameHTML = "<br>" + html.EscapeString(hostName)
		}

		var tailAddr string
		if len(ps.TailscaleIPs) > 0 {
			tailAddr = ps.TailscaleIPs[0].String()
		}
		f("<tr><td>%s</td><td class=acenter>%s</td>"+
			"<td><b>%s</b>%s<div class=\"tailaddr\">%s</div></td><td class=\"acenter owner\">%s</td><td class=\"aright\">%v</td><td class=\"aright\">%v</td><td class=\"aright\">%v</td>",
			ps.PublicKey.ShortString(),
			osEmoji(ps.OS),
			html.EscapeString(dnsName),
			hostNameHTML,
			tailAddr,
			html.EscapeString(owner),
			ps.RxBytes,
			ps.TxBytes,
			actAgo,
		)
		f("<td>")

		if ps.Active {
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
	case "tvOS":
		return "🍎📺"
	case "android":
		return "🤖"
	case "freebsd":
		return "👿"
	case "openbsd":
		return "🐡"
	case "illumos":
		return "☀️"
	}
	return "👽"
}

// PingResult contains response information for the "tailscale ping" subcommand,
// saying how Tailscale can reach a Tailscale IP or subnet-routed IP.
// See tailcfg.PingResponse for a related response that is sent back to control
// for remote diagnostic pings.
type PingResult struct {
	IP       string // ping destination
	NodeIP   string // Tailscale IP of node handling IP (different for subnet routers)
	NodeName string // DNS name base or (possibly not unique) hostname

	Err            string
	LatencySeconds float64

	// Endpoint is the ip:port if direct UDP was used.
	// It is not currently set for TSMP pings.
	Endpoint string

	// DERPRegionID is non-zero DERP region ID if DERP was used.
	// It is not currently set for TSMP pings.
	DERPRegionID int

	// DERPRegionCode is the three-letter region code
	// corresponding to DERPRegionID.
	// It is not currently set for TSMP pings.
	DERPRegionCode string

	// PeerAPIPort is set by TSMP ping responses for peers that
	// are running a peerapi server. This is the port they're
	// running the server on.
	PeerAPIPort uint16 `json:",omitempty"`

	// PeerAPIURL is the URL that was hit for pings of type "peerapi" (tailcfg.PingPeerAPI).
	// It's of the form "http://ip:port" (or [ip]:port for IPv6).
	PeerAPIURL string `json:",omitempty"`

	// IsLocalIP is whether the ping request error is due to it being
	// a ping to the local node.
	IsLocalIP bool `json:",omitempty"`

	// TODO(bradfitz): details like whether port mapping was used on either side? (Once supported)
}

func (pr *PingResult) ToPingResponse(pingType tailcfg.PingType) *tailcfg.PingResponse {
	return &tailcfg.PingResponse{
		Type:           pingType,
		IP:             pr.IP,
		NodeIP:         pr.NodeIP,
		NodeName:       pr.NodeName,
		Err:            pr.Err,
		LatencySeconds: pr.LatencySeconds,
		Endpoint:       pr.Endpoint,
		DERPRegionID:   pr.DERPRegionID,
		DERPRegionCode: pr.DERPRegionCode,
		PeerAPIPort:    pr.PeerAPIPort,
		IsLocalIP:      pr.IsLocalIP,
	}
}

// SortPeers sorts peers by either their DNS name, hostname, Tailscale IP,
// or ultimately their current public key.
func SortPeers(peers []*PeerStatus) {
	slices.SortStableFunc(peers, (*PeerStatus).compare)
}

func (a *PeerStatus) compare(b *PeerStatus) int {
	if a.DNSName != "" || b.DNSName != "" {
		if v := strings.Compare(a.DNSName, b.DNSName); v != 0 {
			return v
		}
	}
	if a.HostName != "" || b.HostName != "" {
		if v := strings.Compare(a.HostName, b.HostName); v != 0 {
			return v
		}
	}
	if len(a.TailscaleIPs) > 0 && len(b.TailscaleIPs) > 0 {
		if v := a.TailscaleIPs[0].Compare(b.TailscaleIPs[0]); v != 0 {
			return v
		}
	}
	return a.PublicKey.Compare(b.PublicKey)
}

// DebugDERPRegionReport is the result of a "tailscale debug derp" command,
// to let people debug a custom DERP setup.
type DebugDERPRegionReport struct {
	Info     []string
	Warnings []string
	Errors   []string
}

type SelfUpdateStatus string

const (
	UpdateFinished   SelfUpdateStatus = "UpdateFinished"
	UpdateInProgress SelfUpdateStatus = "UpdateInProgress"
	UpdateFailed     SelfUpdateStatus = "UpdateFailed"
)

type UpdateProgress struct {
	Status  SelfUpdateStatus `json:"status,omitempty"`
	Message string           `json:"message,omitempty"`
	Version string           `json:"version,omitempty"`
}

func NewUpdateProgress(ps SelfUpdateStatus, msg string) UpdateProgress {
	return UpdateProgress{
		Status:  ps,
		Message: msg,
		Version: version.Short(),
	}
}
