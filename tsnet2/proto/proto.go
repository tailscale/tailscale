// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package proto defines the wire protocol between the tsnet2 client shim
// and the tsnet2d daemon over a Unix socket.
//
// The protocol is intentionally dumb: every conn opens with a single byte
// indicating the "channel kind", followed by channel-specific framing.
//
//	0x01  control  — long-lived; framed JSON RPC for lifecycle, listener
//	                 registration, fallback handler registration.
//	0x02  localapi — short-lived; the rest of the connection is plain HTTP/1.1
//	                 speaking to localapi.NewHandler() on the daemon side.
//	0x03  datapath — short-lived; the connection carries a one-line JSON
//	                 metadata header (terminated by '\n') describing the
//	                 flow, then raw cleartext bytes in both directions.
//	0x04  accept   — short-lived; the client parks one of these per
//	                 pre-allocated accept-worker slot. The daemon writes a
//	                 single line of JSON metadata + a 0x0a delimiter, then
//	                 starts streaming a datapath flow on the same conn.
//
// Control RPCs are line-delimited JSON envelopes:
//
//	{"id":1,"method":"start","params":{...}}
//	{"id":1,"result":{...}}
//	{"id":1,"error":"..."}
//
// Notifications (no id, server-initiated) are not used in v1.
package proto

import "net/netip"

// ChannelKind is the single-byte handshake sent by the client after
// connecting, identifying which channel it wants to open.
type ChannelKind byte

const (
	ChannelControl  ChannelKind = 0x01
	ChannelLocalAPI ChannelKind = 0x02
	ChannelDatapath ChannelKind = 0x03
	ChannelAccept   ChannelKind = 0x04
)

// Methods recognised by the control channel.
const (
	MethodStart                 = "start"
	MethodUp                    = "up"
	MethodClose                 = "close"
	MethodTailscaleIPs          = "tailscale_ips"
	MethodCertDomains           = "cert_domains"
	MethodRegisterListener      = "register_listener"
	MethodUnregisterListener    = "unregister_listener"
	MethodRegisterFallbackTCP   = "register_fallback_tcp"
	MethodUnregisterFallbackTCP = "unregister_fallback_tcp"
)

// Frame is the envelope for line-delimited JSON RPC on the control
// channel. Exactly one of Method/Result/Error will be set on the wire.
type Frame struct {
	ID     uint64 `json:"id,omitempty"`
	Method string `json:"method,omitempty"`
	// Params carries method-specific arguments. The receiver re-decodes
	// the raw JSON into the concrete type for the method.
	Params []byte `json:"params,omitempty"`
	Result []byte `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

// StartParams carries the Server configuration the daemon needs to bring
// up its LocalBackend.
type StartParams struct {
	Hostname      string   `json:"hostname"`
	ControlURL    string   `json:"control_url"`
	AuthKey       string   `json:"auth_key"`
	Ephemeral     bool     `json:"ephemeral"`
	AdvertiseTags []string `json:"advertise_tags"`
}

// UpResult is the response from the "up" control RPC.
type UpResult struct {
	TailscaleIPs []netip.Addr `json:"tailscale_ips"`
	NodeName     string       `json:"node_name"`
	CertDomains  []string     `json:"cert_domains"`
}

// RegisterListenerParams asks the daemon to register a tailnet listener
// on (Network, Addr). The daemon returns an opaque ID the client can use
// to unregister and to identify accepted conns on the accept channel.
type RegisterListenerParams struct {
	Network string `json:"network"`
	Addr    string `json:"addr"`
}

// RegisterListenerResult is the daemon's response to RegisterListener.
type RegisterListenerResult struct {
	ListenerID string `json:"listener_id"`
	// Addr is the resolved network address the daemon is actually
	// listening on (with any port 0 allocation resolved).
	Addr string `json:"addr"`
}

// UnregisterListenerParams asks the daemon to remove a previously
// registered listener.
type UnregisterListenerParams struct {
	ListenerID string `json:"listener_id"`
}

// TailscaleIPsResult is the response from the "tailscale_ips" RPC.
type TailscaleIPsResult struct {
	V4 string `json:"v4,omitempty"`
	V6 string `json:"v6,omitempty"`
}

// CertDomainsResult is the response from the "cert_domains" RPC.
type CertDomainsResult struct {
	Domains []string `json:"domains"`
}

// DatapathHeader is the one-line JSON header the client writes on a
// datapath connection right after the channel-kind byte.
type DatapathHeader struct {
	// Op is "dial" for client-initiated outbound flows.
	Op string `json:"op"`
	// Network/Addr are the dial target for Op == "dial".
	Network string `json:"network,omitempty"`
	Addr    string `json:"addr,omitempty"`
}

// AcceptHeader is the one-line JSON header the daemon writes on an
// accept channel when it has an inbound conn ready to hand back.
type AcceptHeader struct {
	ListenerID string `json:"listener_id"`
	Local      string `json:"local"`
	Remote     string `json:"remote"`
}
