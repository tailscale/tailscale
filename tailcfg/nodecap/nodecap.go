// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package nodecap defines the types of capabilities granted to tailnet nodes.
package nodecap

// Cap represents a capability granted to the self node
// as listed in [tailscale.com/tailcfg/MapResponse.Node.Capabilities].
//
// It must be a URL like "https://tailscale.com/cap/file-sharing" or "tailscale.com/cap/webui",
// or a well-known capability name like "funnel".
// The latter is only allowed for Tailscale-defined capabilities.
//
// Unlike [tailscale.com/tailcfg/peercap.Cap],
// Cap is not in context of a peer and is granted to the node itself.
//
// These are also referred to as "Node Attributes" in the ACL policy file.
type Cap string

// Prefix is a prefix for [tailscale.com/tailcfg.NodeCapMap] keys that share a common namespace,
// where each entry represents a distinct named instance (e.g. one per service).
// The full key is formed by concatenating the prefix with the instance name.
type Prefix string

// ToAttribute returns the full [Cap] key for the given value under this prefix,
// of the form prefix+value.
func (p Prefix) ToAttribute(value string) Cap {
	return Cap(string(p) + value)
}

const (
	FileSharing        Cap = "https://tailscale.com/cap/file-sharing"
	Admin              Cap = "https://tailscale.com/cap/is-admin"
	Owner              Cap = "https://tailscale.com/cap/is-owner"
	SSH                Cap = "https://tailscale.com/cap/ssh"                   // feature enabled/available
	SSHRuleIn          Cap = "https://tailscale.com/cap/ssh-rule-in"           // some SSH rule reach this node
	DataPlaneAuditLogs Cap = "https://tailscale.com/cap/data-plane-audit-logs" // feature enabled
	Debug              Cap = "https://tailscale.com/cap/debug"                 // exposes debug endpoints over the PeerAPI
	HTTPS              Cap = "https"

	// MacUIV2 makes the macOS GUI enable its v2 mode.
	MacUIV2 Cap = "https://tailscale.com/cap/mac-ui-v2"

	// ServicesInDesktopClients enables services list/menu/section in desktop clients.
	// If this capability is not present, desktop clients should not show services.
	ServicesInDesktopClients Cap = "https://tailscale.com/cap/services-in-desktop-clients"

	// BindToInterfaceByRoute changes how Darwin nodes create
	// sockets (in the net/netns package). See that package for more
	// details on the behaviour of this capability.
	BindToInterfaceByRoute Cap = "https://tailscale.com/cap/bind-to-interface-by-route"

	// DisableAndroidBindToActiveNetwork disables binding sockets to the
	// currently active network on Android, which is enabled by default.
	// This allows the control plane to turn off the behavior if it causes
	// problems.
	DisableAndroidBindToActiveNetwork Cap = "disable-android-bind-to-active-network"

	// DebugDisableAlternateDefaultRouteInterface changes how Darwin
	// nodes get the default interface. There is an optional hook (used by the
	// macOS and iOS clients) to override the default interface, this capability
	// disables that and uses the default behavior (of parsing the routing
	// table).
	DebugDisableAlternateDefaultRouteInterface Cap = "https://tailscale.com/cap/debug-disable-alternate-default-route-interface"

	// DebugDisableBindConnToInterface disables the automatic binding
	// of connections to the default network interface on Darwin nodes.
	DebugDisableBindConnToInterface Cap = "https://tailscale.com/cap/debug-disable-bind-conn-to-interface"

	// DebugDisableBindConnToInterface disables the automatic binding
	// of connections to the default network interface on Darwin nodes using network extensions
	DebugDisableBindConnToInterfaceAppleExt Cap = "https://tailscale.com/cap/debug-disable-bind-conn-to-interface-apple-ext"

	// TailnetLock indicates the node may initialize tailnet lock.
	TailnetLock Cap = "https://tailscale.com/cap/tailnet-lock"

	//// Funnel warning capabilities used for reporting errors to the user.

	// WarnFunnelNoInvite indicates whether Funnel is enabled for the tailnet.
	// This cap is no longer used 2023-08-09 onwards.
	WarnFunnelNoInvite Cap = "https://tailscale.com/cap/warn-funnel-no-invite"

	// WarnFunnelNoHTTPS indicates HTTPS has not been enabled for the tailnet.
	// This cap is no longer used 2023-08-09 onwards.
	WarnFunnelNoHTTPS Cap = "https://tailscale.com/cap/warn-funnel-no-https"

	//// Debug logging capabilities

	// DebugTSDNSResolution enables verbose debug logging for DNS
	// resolution for Tailscale-controlled domains (the control server, log
	// server, DERP servers, etc.)
	DebugTSDNSResolution Cap = "https://tailscale.com/cap/debug-ts-dns-resolution"

	// FunnelPorts specifies the ports that the Funnel is available on.
	// The ports are specified as a comma-separated list of port numbers or port
	// ranges (e.g. "80,443,8080-8090") in the ports query parameter.
	// e.g. https://tailscale.com/cap/funnel-ports?ports=80,443,8080-8090
	FunnelPorts Cap = "https://tailscale.com/cap/funnel-ports"

	// OnlyTCP443 specifies that the client should not attempt to generate
	// any outbound traffic that isn't TCP on port 443 (HTTPS). This is used for
	// clients in restricted environments where only HTTPS traffic is allowed
	// other types of traffic trips outbound firewall alarms. This thus implies
	// all traffic is over DERP.
	OnlyTCP443 Cap = "only-tcp-443"

	// Funnel grants the ability for a node to host ingress traffic.
	Funnel Cap = "funnel"
	// SSHAggregator grants the ability for a node to collect SSH sessions.
	SSHAggregator Cap = "ssh-aggregator"

	// DebugForceBackgroundSTUN forces a node to always do background
	// STUN queries regardless of inactivity.
	DebugForceBackgroundSTUN Cap = "debug-always-stun"

	// DebugDisableWGTrim disables the lazy WireGuard configuration,
	// always giving WireGuard the full netmap, even for idle peers.
	DebugDisableWGTrim Cap = "debug-no-wg-trim"

	// DisableSubnetsIfPAC controls whether subnet routers should be
	// disabled if WPAD is present on the network.
	DisableSubnetsIfPAC Cap = "debug-disable-subnets-if-pac"

	// DisableUPnP makes the client not perform a UPnP portmapping.
	// By default, we want to enable it to see if it works on more clients.
	//
	// If UPnP catastrophically fails for people, this should be set kill
	// new attempts at UPnP connections.
	DisableUPnP Cap = "debug-disable-upnp"

	// DisableDeltaUpdates makes the client not process updates via the
	// delta update mechanism and should instead treat all netmap changes as
	// "full" ones as tailscaled did in 1.48.x and earlier.
	DisableDeltaUpdates Cap = "disable-delta-updates"

	// RandomizeClientPort makes magicsock UDP bind to
	// :0 to get a random local port, ignoring any configured
	// fixed port.
	RandomizeClientPort Cap = "randomize-client-port"

	// SilentDisco makes the client suppress disco heartbeats to its
	// peers.
	SilentDisco Cap = "silent-disco"

	// OneCGNATEnable makes the client prefer one big CGNAT /10 route
	// rather than a /32 per peer. At most one of this or
	// [OneCGNATDisable] may be set; if neither are, it's automatic.
	OneCGNATEnable Cap = "one-cgnat?v=true"

	// OneCGNATDisable makes the client prefer a /32 route per peer
	// rather than one big /10 CGNAT route. At most one of this or
	// [OneCGNATEnable] may be set; if neither are, it's automatic.
	OneCGNATDisable Cap = "one-cgnat?v=false"

	// PeerMTUEnable makes the client do path MTU discovery to its
	// peers. If it isn't set, it defaults to the client default.
	PeerMTUEnable Cap = "peer-mtu-enable"

	// DNSForwarderDisableTCPRetries disables retrying truncated
	// DNS queries over TCP if the response is truncated.
	DNSForwarderDisableTCPRetries Cap = "dns-forwarder-disable-tcp-retries"

	// LinuxMustUseIPTables forces Linux clients to use iptables for
	// netfilter management.
	// This cannot be set simultaneously with [LinuxMustUseNfTables].
	LinuxMustUseIPTables Cap = "linux-netfilter?v=iptables"

	// LinuxMustUseNfTables forces Linux clients to use nftables for
	// netfilter management.
	// This cannot be set simultaneously with [LinuxMustUseIPTables].
	LinuxMustUseNfTables Cap = "linux-netfilter?v=nftables"

	// ProbeUDPLifetime makes the client probe UDP path lifetime at the
	// tail end of an active direct connection in magicsock.
	ProbeUDPLifetime Cap = "probe-udp-lifetime"

	// TaildriveShare enables sharing via Taildrive.
	TaildriveShare Cap = "drive:share"

	// TaildriveAccess enables accessing shares via Taildrive.
	TaildriveAccess Cap = "drive:access"

	// SuggestExitNode is applied to each exit node which the control plane has determined
	// is a recommended exit node.
	SuggestExitNode Cap = "suggest-exit-node"

	// DisableWebClient disables using the web client.
	DisableWebClient Cap = "disable-web-client"

	// LogExitFlows enables exit node destinations in network flow logs.
	LogExitFlows Cap = "log-exit-flows"

	// AutoExitNode permits the automatic exit nodes feature.
	AutoExitNode Cap = "auto-exit-node"

	// StoreAppCRoutes configures the node to store app connector routes persistently.
	StoreAppCRoutes Cap = "store-appc-routes"

	// SuggestExitNodeUI allows the currently suggested exit node to appear in the client GUI.
	SuggestExitNodeUI Cap = "suggest-exit-node-ui"

	// UserDialUseRoutes makes UserDial use either the peer dialer or the system dialer,
	// depending on the destination address and the configured routes. When present, it also makes
	// the DNS forwarder use UserDial instead of SystemDial when dialing resolvers.
	UserDialUseRoutes Cap = "user-dial-routes"

	// SSHBehaviorV1 forces SSH to use the V1 behavior (no su, run SFTP in-process)
	// Added 2024-05-29 in Tailscale version 1.68.
	SSHBehaviorV1 Cap = "ssh-behavior-v1"

	// SSHBehaviorV2 forces SSH to use the V2 behavior (use su, run SFTP in child process).
	// This overrides [SSHBehaviorV1] if set.
	// See forceV1Behavior in ssh/tailssh/incubator.go for distinction between
	// V1 and V2 behavior.
	// Added 2024-08-06 in Tailscale version 1.72.
	SSHBehaviorV2 Cap = "ssh-behavior-v2"

	// DisableSplitDNSWhenNoCustomResolvers indicates that the node's
	// DNS manager should not adopt a split DNS configuration even though the
	// Config of the resolver only contains routes that do not specify custom
	// resolver(s), hence all DNS queries can be safely sent to the upstream
	// DNS resolver and the node's DNS forwarder doesn't need to handle all
	// DNS traffic.
	// This is for now (2024-06-06) an iOS-specific battery life optimization,
	// and this node attribute allows us to disable the optimization remotely
	// if needed.
	DisableSplitDNSWhenNoCustomResolvers Cap = "disable-split-dns-when-no-custom-resolvers"

	// ScopeQuad100OnMacOS makes sandboxed macOS clients scope quad-100
	// to its match domains instead of installing it as the OS's primary
	// (catch-all) resolver, so that public names fall through to the OS
	// resolver -- e.g. a user's DoH system profile -- rather than being
	// shadowed. It has no effect on any other platform. Without this attribute,
	// sandboxed macOS keeps the older behavior of making quad-100 the default
	// resolver, as iOS still does. See tailscale/corp#45534.
	ScopeQuad100OnMacOS Cap = "scope-quad100-macos"

	// DisableLocalDNSOverrideViaNRPT indicates that the node's DNS manager should not
	// create a default (catch-all) Windows NRPT rule when "Override local DNS" is enabled.
	// Without this rule, Windows 8.1 and newer devices issue parallel DNS requests to DNS servers
	// associated with all network adapters, even when "Override local DNS" is enabled and/or
	// a Mullvad exit node is being used, resulting in DNS leaks.
	// We began creating this rule on 2024-06-14, and this node attribute
	// allows us to disable the new behavior remotely if needed.
	DisableLocalDNSOverrideViaNRPT Cap = "disable-local-dns-override-via-nrpt"

	// DisableMagicSockCryptoRouting disables the use of the
	// magicsock cryptorouting hook. See tailscale/corp#20732.
	//
	// Deprecated: [DisableMagicSockCryptoRouting] is deprecated as of
	// [tailscale.com/tailcfg.CapabilityVersion] 124,
	// CryptoRouting is now mandatory. See tailscale/corp#31083.
	DisableMagicSockCryptoRouting Cap = "disable-magicsock-crypto-routing"

	// DisableCaptivePortalDetection instructs the client to not perform captive portal detection
	// automatically when the network state changes.
	DisableCaptivePortalDetection Cap = "disable-captive-portal-detection"

	// DisableSkipStatusQueue is set when the node should disable skipping
	// of queued netmap.NetworkMap between the controlclient and LocalBackend.
	// See tailscale/tailscale#14768.
	DisableSkipStatusQueue Cap = "disable-skip-status-queue"

	// SSHEnvironmentVariables enables logic for handling environment variables sent
	// via SendEnv in the SSH server and applying them to the SSH session.
	SSHEnvironmentVariables Cap = "ssh-env-vars"

	// ServiceHost indicates the VIP Services for which the client is
	// approved to act as a service host, and which IP addresses are assigned
	// to those VIP Services. Any VIP Services that the client is not
	// advertising can be ignored.
	// Each value of this key in [NodeCapMap] is of type [ServiceIPMappings].
	// If multiple values of this key exist, they should be merged in sequence
	// (replace conflicting keys).
	ServiceHost Cap = "service-host"

	// MaxKeyDuration represents the MaxKeyDuration setting on the
	// tailnet. The value of this key in [NodeCapMap] will be only one entry of
	// type float64 representing the duration in seconds. This cap will be
	// omitted if the tailnet's MaxKeyDuration is the default.
	MaxKeyDuration Cap = "tailnet.maxKeyDuration"

	// NativeIPV4 contains the IPV4 address of the node in its
	// native tailnet. This is currently only sent to Hello, in its
	// peer node list.
	NativeIPV4 Cap = "native-ipv4"

	// DisableRelayServer prevents the node from acting as an underlay
	// UDP relay server. There are no expected values for this key; the key
	// only needs to be present in [NodeCapMap] to take effect.
	DisableRelayServer Cap = "disable-relay-server"

	// DisableRelayClient prevents the node from both allocating UDP
	// relay server endpoints itself, and from using endpoints allocated by
	// its peers. This attribute can be added to the node dynamically; if added
	// while the node is already running, the node will be unable to allocate
	// endpoints after it next updates its network map, and will be immediately
	// unable to use new paths via a UDP relay server. Setting this attribute
	// dynamically does not remove any existing paths, including paths that
	// traverse a UDP relay server. There are no expected values for this key
	// in [NodeCapMap]; the key only needs to be present in [NodeCapMap] to
	// take effect.
	DisableRelayClient Cap = "disable-relay-client"

	// MagicDNSPeerAAAA is a capability that tells the node's MagicDNS
	// server to answer AAAA queries about its peers. See tailscale/tailscale#1152.
	MagicDNSPeerAAAA Cap = "magicdns-aaaa"

	// DNSSubdomainResolve, when set on Self or a Peer node, indicates
	// that the subdomains of that node's MagicDNS name should resolve to the
	// same IP addresses as the node itself.
	// For example, if node "myserver.tailnet.ts.net" has this capability,
	// then "anything.myserver.tailnet.ts.net" will resolve to myserver's IPs.
	DNSSubdomainResolve Cap = "dns-subdomain-resolve"

	// TrafficSteering configures the node to use the traffic
	// steering subsystem for via routes. See tailscale/corp#29966.
	TrafficSteering Cap = "traffic-steering"

	// TailnetDisplayName is an optional alternate name for the tailnet
	// to be displayed to the user.
	// If empty or absent, a default is used.
	// If this value is present and set by a user this will only include letters,
	// numbers, apostrophe, spaces, and hyphens. This may not be true for the default.
	// Values can look like "foo.com" or "Foo's Test Tailnet - Staging".
	TailnetDisplayName Cap = "tailnet-display-name"

	// ClientSideReachability configures the node to determine
	// reachability itself when choosing connectors. When absent, the
	// default behavior is to trust the control plane when it claims that a
	// node is no longer online, but that is not a reliable signal.
	//
	// It is temporary and will be ignored once its behaviour becomes the default.
	ClientSideReachability Cap = "client-side-reachability"

	// ClientSideReachabilityRouteCheck configures the node to use
	// the routecheck subsystem to determine reachability when choosing
	// connectors. This relies on [ClientSideReachability] being set.
	// See tailscale/tailscale#17367.
	//
	// It is temporary and will be ignored once its behaviour becomes the default.
	ClientSideReachabilityRouteCheck Cap = "client-side-reachability-routecheck"

	// DefaultAutoUpdate advertises the default node auto-update setting
	// for this tailnet. The node is free to opt-in or out locally regardless of
	// this value. Once this has been set and stored in the client, future
	// changes from the control plane are ignored.
	//
	// The value of the key in [NodeCapMap] is a JSON boolean.
	DefaultAutoUpdate Cap = "default-auto-update"

	// DisableHostsFileUpdates indicates that the node's DNS manager should
	// not create hosts file entries when it normally would, such as when we're not
	// the primary resolver on Windows or when the host is domain-joined and its
	// primary domain takes precedence over MagicDNS. As of 2026-02-12, it is only
	// used on Windows.
	DisableHostsFileUpdates Cap = "disable-hosts-file-updates"

	// ForceRegisterMagicDNSIPv4Only forces the client to only register
	// its MagicDNS IPv4 address with systemd/etc, and not both its IPv4 and IPv6 addresses.
	// See https://github.com/tailscale/tailscale/issues/15404.
	// TODO(bradfitz): remove this a few releases after 2026-02-16.
	ForceRegisterMagicDNSIPv4Only Cap = "force-register-magicdns-ipv4-only"

	// CacheNetworkMaps instructs the node to persistently cache network
	// maps and use them to establish peer connectivity on start, if doing so is
	// supported by the client and storage is available. When this attribute is
	// absent (or removed), a node that supports netmap caching will ignore and
	// discard existing cached maps, and will not store any.
	CacheNetworkMaps Cap = "cache-network-maps"

	// DisableCacheNetworkMaps indicates that the node should not cache
	// network maps (as per [CacheNetworkMaps]) when it normally would.
	// This attribute exists to allow the policy document to override the default.
	// When set, it takes precedence over [CacheNetworkMaps].
	DisableCacheNetworkMaps Cap = "disable-cache-network-maps"

	// DisableLinuxCGNATDropRule tells Linux clients to not insert a
	// blanket firewall DROP rule for inbound traffic from the CGNAT IP range
	// that does not originate from the Tailscale network interface.
	// This enables access to off-tailnet endpoints within that IP range.
	DisableLinuxCGNATDropRule Cap = "disable-linux-cgnat-drop-rule"

	// EmitRuntimeMetrics enables emission of [runtime/metrics] as
	// [tailscale.com/util/clientmetric]'s.
	EmitRuntimeMetrics Cap = "emit-runtime-metrics"

	// DisableUDPGRO disables UDP GRO (UDP_GRO socket option on Linux)
	// on the magicsock UDP socket. It exists so control can mitigate kernel
	// regressions that cause throughput or correctness issues with UDP GRO on
	// specific OS/kernel versions, without requiring a client release. See
	// https://github.com/tailscale/tailscale/issues/19777 for example.
	// Currently only consulted on Linux; may apply to other platforms as they
	// gain UDP GRO support.
	DisableUDPGRO Cap = "disable-udp-gro"

	// DisableUDPGSO disables UDP GSO (UDP_SEGMENT socket option on
	// Linux) on the magicsock UDP socket. It exists so control can mitigate
	// kernel regressions that cause throughput or correctness issues with UDP
	// GSO on specific OS/kernel versions, without requiring a client release.
	// See https://github.com/tailscale/tailscale/issues/19777 for example.
	// Currently only consulted on Linux; may apply to other platforms as they
	// gain UDP GSO support.
	DisableUDPGSO Cap = "disable-udp-gso"

	// DisableTUNUDPGRO disables UDP GRO on the Tailscale TUN device.
	// It exists so control can mitigate kernel regressions that cause
	// throughput or correctness issues with TUN UDP GRO on specific OS/kernel
	// versions, without requiring a client release. See
	// https://github.com/tailscale/tailscale/issues/13041 for example.
	// Currently only consulted on Linux; may apply to other platforms as they
	// gain TUN UDP GRO support.
	DisableTUNUDPGRO Cap = "disable-tun-udp-gro"

	// DisableTUNTCPGRO disables TCP GRO on the Tailscale TUN device.
	// It exists so control can mitigate kernel regressions that cause
	// throughput or correctness issues with TUN TCP GRO on specific OS/kernel
	// versions, without requiring a client release. See
	// https://github.com/tailscale/tailscale/issues/13041 for example.
	// Currently only consulted on Linux; may apply to other platforms as they
	// gain TUN TCP GRO support.
	DisableTUNTCPGRO Cap = "disable-tun-tcp-gro"

	// NeverGSOEqualTail enables a sentinel-tail workaround in the
	// underlay UDP packet TX path on Linux. Applies to magicsock and peer relay
	// UDP sockets. The workaround avoids emitting UDP GSO batches whose
	// fragments are all equal in length, at a small payload and packet overhead
	// cost. It exists so control can mitigate kernel regressions that mangle
	// UDP headers or checksums for equal-length GSO batches, without requiring
	// a client release. See https://github.com/tailscale/tailscale/issues/19777.
	NeverGSOEqualTail Cap = "never-gso-equal-tail"
)

const (
	// ServicesPrefix is the prefix for per-service [NodeCapMap]
	// entries describing Services visible (accessible) to this node.
	// Each value under such a key is of type [ServiceDetails].
	// The suffix after the prefix is an opaque server-chosen identifier;
	// consumers must use [ServiceDetails.Name] as the canonical service name
	// rather than parsing it from the map key.
	ServicesPrefix Prefix = "services/"
)
