// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipv6

import (
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/internal/ip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// defaultMaxRtrSolicitations is the default number of Router
	// Solicitation messages to send when an IPv6 endpoint becomes enabled.
	//
	// Default = 3 (from RFC 4861 section 10).
	defaultMaxRtrSolicitations = 3

	// defaultRtrSolicitationInterval is the default amount of time between
	// sending Router Solicitation messages.
	//
	// Default = 4s (from 4861 section 10).
	defaultRtrSolicitationInterval = 4 * time.Second

	// defaultMaxRtrSolicitationDelay is the default maximum amount of time
	// to wait before sending the first Router Solicitation message.
	//
	// Default = 1s (from 4861 section 10).
	defaultMaxRtrSolicitationDelay = time.Second

	// defaultHandleRAs is the default configuration for whether or not to
	// handle incoming Router Advertisements as a host.
	defaultHandleRAs = HandlingRAsEnabledWhenForwardingDisabled

	// defaultDiscoverDefaultRouters is the default configuration for
	// whether or not to discover default routers from incoming Router
	// Advertisements, as a host.
	defaultDiscoverDefaultRouters = true

	// defaultDiscoverMoreSpecificRoutes is the default configuration for
	// whether or not to discover more-specific routes from incoming Router
	// Advertisements, as a host.
	defaultDiscoverMoreSpecificRoutes = true

	// defaultDiscoverOnLinkPrefixes is the default configuration for
	// whether or not to discover on-link prefixes from incoming Router
	// Advertisements' Prefix Information option, as a host.
	defaultDiscoverOnLinkPrefixes = true

	// defaultAutoGenGlobalAddresses is the default configuration for
	// whether or not to generate global IPv6 addresses in response to
	// receiving a new Prefix Information option with its Autonomous
	// Address AutoConfiguration flag set, as a host.
	//
	// Default = true.
	defaultAutoGenGlobalAddresses = true

	// minimumRtrSolicitationInterval is the minimum amount of time to wait
	// between sending Router Solicitation messages. This limit is imposed
	// to make sure that Router Solicitation messages are not sent all at
	// once, defeating the purpose of sending the initial few messages.
	minimumRtrSolicitationInterval = 500 * time.Millisecond

	// minimumMaxRtrSolicitationDelay is the minimum amount of time to wait
	// before sending the first Router Solicitation message. It is 0 because
	// we cannot have a negative delay.
	minimumMaxRtrSolicitationDelay = 0

	// MaxDiscoveredOffLinkRoutes is the maximum number of discovered off-link
	// routes. The stack should stop discovering new off-link routes after
	// this limit is reached.
	//
	// This value MUST be at minimum 2 as per RFC 4861 section 6.3.4, and
	// SHOULD be more.
	MaxDiscoveredOffLinkRoutes = 10

	// MaxDiscoveredOnLinkPrefixes is the maximum number of discovered
	// on-link prefixes. The stack should stop discovering new on-link
	// prefixes after discovering MaxDiscoveredOnLinkPrefixes on-link
	// prefixes.
	MaxDiscoveredOnLinkPrefixes = 10

	// validPrefixLenForAutoGen is the expected prefix length that an
	// address can be generated for. Must be 64 bits as the interface
	// identifier (IID) is 64 bits and an IPv6 address is 128 bits, so
	// 128 - 64 = 64.
	validPrefixLenForAutoGen = 64

	// defaultAutoGenTempGlobalAddresses is the default configuration for whether
	// or not to generate temporary SLAAC addresses.
	defaultAutoGenTempGlobalAddresses = true

	// defaultMaxTempAddrValidLifetime is the default maximum valid lifetime
	// for temporary SLAAC addresses generated as part of RFC 4941.
	//
	// Default = 7 days (from RFC 4941 section 5).
	defaultMaxTempAddrValidLifetime = 7 * 24 * time.Hour

	// defaultMaxTempAddrPreferredLifetime is the default preferred lifetime
	// for temporary SLAAC addresses generated as part of RFC 4941.
	//
	// Default = 1 day (from RFC 4941 section 5).
	defaultMaxTempAddrPreferredLifetime = 24 * time.Hour

	// defaultRegenAdvanceDuration is the default duration before the deprecation
	// of a temporary address when a new address will be generated.
	//
	// Default = 5s (from RFC 4941 section 5).
	defaultRegenAdvanceDuration = 5 * time.Second

	// minRegenAdvanceDuration is the minimum duration before the deprecation
	// of a temporary address when a new address will be generated.
	minRegenAdvanceDuration = time.Duration(0)

	// maxSLAACAddrLocalRegenAttempts is the maximum number of times to attempt
	// SLAAC address regenerations in response to an IPv6 endpoint-local conflict.
	maxSLAACAddrLocalRegenAttempts = 10

	// MinPrefixInformationValidLifetimeForUpdate is the minimum Valid
	// Lifetime to update the valid lifetime of a generated address by
	// SLAAC.
	//
	// Min = 2hrs.
	MinPrefixInformationValidLifetimeForUpdate = 2 * time.Hour

	// MaxDesyncFactor is the upper bound for the preferred lifetime's desync
	// factor for temporary SLAAC addresses.
	//
	// Must be greater than 0.
	//
	// Max = 10m (from RFC 4941 section 5).
	MaxDesyncFactor = 10 * time.Minute

	// MinMaxTempAddrPreferredLifetime is the minimum value allowed for the
	// maximum preferred lifetime for temporary SLAAC addresses.
	//
	// This value guarantees that a temporary address is preferred for at
	// least 1hr if the SLAAC prefix is valid for at least that time.
	MinMaxTempAddrPreferredLifetime = defaultRegenAdvanceDuration + MaxDesyncFactor + time.Hour

	// MinMaxTempAddrValidLifetime is the minimum value allowed for the
	// maximum valid lifetime for temporary SLAAC addresses.
	//
	// This value guarantees that a temporary address is valid for at least
	// 2hrs if the SLAAC prefix is valid for at least that time.
	MinMaxTempAddrValidLifetime = 2 * time.Hour
)

// NDPEndpoint is an endpoint that supports NDP.
type NDPEndpoint interface {
	// SetNDPConfigurations sets the NDP configurations.
	SetNDPConfigurations(NDPConfigurations)
}

// DHCPv6ConfigurationFromNDPRA is a configuration available via DHCPv6 that an
// NDP Router Advertisement informed the Stack about.
type DHCPv6ConfigurationFromNDPRA int

const (
	_ DHCPv6ConfigurationFromNDPRA = iota

	// DHCPv6NoConfiguration indicates that no configurations are available via
	// DHCPv6.
	DHCPv6NoConfiguration

	// DHCPv6ManagedAddress indicates that addresses are available via DHCPv6.
	//
	// DHCPv6ManagedAddress also implies DHCPv6OtherConfigurations because DHCPv6
	// returns all available configuration information when serving addresses.
	DHCPv6ManagedAddress

	// DHCPv6OtherConfigurations indicates that other configuration information is
	// available via DHCPv6.
	//
	// Other configurations are configurations other than addresses. Examples of
	// other configurations are recursive DNS server list, DNS search lists and
	// default gateway.
	DHCPv6OtherConfigurations
)

// NDPDispatcher is the interface integrators of netstack must implement to
// receive and handle NDP related events.
type NDPDispatcher interface {
	// OnDuplicateAddressDetectionResult is called when the DAD process for an
	// address on a NIC completes.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	OnDuplicateAddressDetectionResult(tcpip.NICID, tcpip.Address, stack.DADResult)

	// OnOffLinkRouteUpdated is called when an off-link route is updated.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	OnOffLinkRouteUpdated(tcpip.NICID, tcpip.Subnet, tcpip.Address, header.NDPRoutePreference)

	// OnOffLinkRouteInvalidated is called when an off-link route is invalidated.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	OnOffLinkRouteInvalidated(tcpip.NICID, tcpip.Subnet, tcpip.Address)

	// OnOnLinkPrefixDiscovered is called when a new on-link prefix is discovered.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	OnOnLinkPrefixDiscovered(tcpip.NICID, tcpip.Subnet)

	// OnOnLinkPrefixInvalidated is called when a discovered on-link prefix that
	// was remembered is invalidated.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	OnOnLinkPrefixInvalidated(tcpip.NICID, tcpip.Subnet)

	// OnAutoGenAddress is called when a new prefix with its autonomous address-
	// configuration flag set is received and SLAAC was performed.
	//
	// This function is not permitted to block indefinitely. It must not
	// call functions on the stack itself.
	OnAutoGenAddress(tcpip.NICID, tcpip.AddressWithPrefix)

	// OnAutoGenAddressDeprecated is called when an auto-generated address (SLAAC)
	// is deprecated, but is still considered valid. Note, if an address is
	// invalidated at the same ime it is deprecated, the deprecation event may not
	// be received.
	//
	// This function is not permitted to block indefinitely. It must not
	// call functions on the stack itself.
	OnAutoGenAddressDeprecated(tcpip.NICID, tcpip.AddressWithPrefix)

	// OnAutoGenAddressInvalidated is called when an auto-generated address
	// (SLAAC) is invalidated.
	//
	// This function is not permitted to block indefinitely. It must not
	// call functions on the stack itself.
	OnAutoGenAddressInvalidated(tcpip.NICID, tcpip.AddressWithPrefix)

	// OnRecursiveDNSServerOption is called when the stack learns of DNS servers
	// through NDP. Note, the addresses may contain link-local addresses.
	//
	// It is up to the caller to use the DNS Servers only for their valid
	// lifetime. OnRecursiveDNSServerOption may be called for new or
	// already known DNS servers. If called with known DNS servers, their
	// valid lifetimes must be refreshed to the lifetime (it may be increased,
	// decreased, or completely invalidated when the lifetime = 0).
	//
	// This function is not permitted to block indefinitely. It must not
	// call functions on the stack itself.
	OnRecursiveDNSServerOption(tcpip.NICID, []tcpip.Address, time.Duration)

	// OnDNSSearchListOption is called when the stack learns of DNS search lists
	// through NDP.
	//
	// It is up to the caller to use the domain names in the search list
	// for only their valid lifetime. OnDNSSearchListOption may be called
	// with new or already known domain names. If called with known domain
	// names, their valid lifetimes must be refreshed to the lifetime (it may
	// be increased, decreased or completely invalidated when the lifetime = 0.
	OnDNSSearchListOption(tcpip.NICID, []string, time.Duration)

	// OnDHCPv6Configuration is called with an updated configuration that is
	// available via DHCPv6 for the passed NIC.
	//
	// This function is not permitted to block indefinitely. It must not
	// call functions on the stack itself.
	OnDHCPv6Configuration(tcpip.NICID, DHCPv6ConfigurationFromNDPRA)
}

var _ fmt.Stringer = HandleRAsConfiguration(0)

// HandleRAsConfiguration enumerates when RAs may be handled.
type HandleRAsConfiguration int

const (
	// HandlingRAsDisabled indicates that Router Advertisements will not be
	// handled.
	HandlingRAsDisabled HandleRAsConfiguration = iota

	// HandlingRAsEnabledWhenForwardingDisabled indicates that router
	// advertisements will only be handled when forwarding is disabled.
	HandlingRAsEnabledWhenForwardingDisabled

	// HandlingRAsAlwaysEnabled indicates that Router Advertisements will always
	// be handled, even when forwarding is enabled.
	HandlingRAsAlwaysEnabled
)

// String implements fmt.Stringer.
func (c HandleRAsConfiguration) String() string {
	switch c {
	case HandlingRAsDisabled:
		return "HandlingRAsDisabled"
	case HandlingRAsEnabledWhenForwardingDisabled:
		return "HandlingRAsEnabledWhenForwardingDisabled"
	case HandlingRAsAlwaysEnabled:
		return "HandlingRAsAlwaysEnabled"
	default:
		return fmt.Sprintf("HandleRAsConfiguration(%d)", c)
	}
}

// enabled returns true iff Router Advertisements may be handled given the
// specified forwarding status.
func (c HandleRAsConfiguration) enabled(forwarding bool) bool {
	switch c {
	case HandlingRAsDisabled:
		return false
	case HandlingRAsEnabledWhenForwardingDisabled:
		return !forwarding
	case HandlingRAsAlwaysEnabled:
		return true
	default:
		panic(fmt.Sprintf("unhandled HandleRAsConfiguration = %d", c))
	}
}

// NDPConfigurations is the NDP configurations for the netstack.
type NDPConfigurations struct {
	// The number of Router Solicitation messages to send when the IPv6 endpoint
	// becomes enabled.
	//
	// Ignored unless configured to handle Router Advertisements.
	MaxRtrSolicitations uint8

	// The amount of time between transmitting Router Solicitation messages.
	//
	// Must be greater than or equal to 0.5s.
	RtrSolicitationInterval time.Duration

	// The maximum amount of time before transmitting the first Router
	// Solicitation message.
	//
	// Must be greater than or equal to 0s.
	MaxRtrSolicitationDelay time.Duration

	// HandleRAs is the configuration for when Router Advertisements should be
	// handled.
	HandleRAs HandleRAsConfiguration

	// DiscoverDefaultRouters determines whether or not default routers are
	// discovered from Router Advertisements, as per RFC 4861 section 6. This
	// configuration is ignored if RAs will not be processed (see HandleRAs).
	DiscoverDefaultRouters bool

	// DiscoverMoreSpecificRoutes determines whether or not more specific routes
	// are discovered from Router Advertisements, as per RFC 4191. This
	// configuration is ignored if RAs will not be processed (see HandleRAs).
	DiscoverMoreSpecificRoutes bool

	// DiscoverOnLinkPrefixes determines whether or not on-link prefixes are
	// discovered from Router Advertisements' Prefix Information option, as per
	// RFC 4861 section 6. This configuration is ignored if RAs will not be
	// processed (see HandleRAs).
	DiscoverOnLinkPrefixes bool

	// AutoGenGlobalAddresses determines whether or not an IPv6 endpoint performs
	// SLAAC to auto-generate global SLAAC addresses in response to Prefix
	// Information options, as per RFC 4862.
	//
	// Note, if an address was already generated for some unique prefix, as
	// part of SLAAC, this option does not affect whether or not the
	// lifetime(s) of the generated address changes; this option only
	// affects the generation of new addresses as part of SLAAC.
	AutoGenGlobalAddresses bool

	// AutoGenAddressConflictRetries determines how many times to attempt to retry
	// generation of a permanent auto-generated address in response to DAD
	// conflicts.
	//
	// If the method used to generate the address does not support creating
	// alternative addresses (e.g. IIDs based on the modified EUI64 of a NIC's
	// MAC address), then no attempt is made to resolve the conflict.
	AutoGenAddressConflictRetries uint8

	// AutoGenTempGlobalAddresses determines whether or not temporary SLAAC
	// addresses are generated for an IPv6 endpoint as part of SLAAC privacy
	// extensions, as per RFC 4941.
	//
	// Ignored if AutoGenGlobalAddresses is false.
	AutoGenTempGlobalAddresses bool

	// MaxTempAddrValidLifetime is the maximum valid lifetime for temporary
	// SLAAC addresses.
	MaxTempAddrValidLifetime time.Duration

	// MaxTempAddrPreferredLifetime is the maximum preferred lifetime for
	// temporary SLAAC addresses.
	MaxTempAddrPreferredLifetime time.Duration

	// RegenAdvanceDuration is the duration before the deprecation of a temporary
	// address when a new address will be generated.
	RegenAdvanceDuration time.Duration
}

// DefaultNDPConfigurations returns an NDPConfigurations populated with
// default values.
func DefaultNDPConfigurations() NDPConfigurations {
	return NDPConfigurations{
		MaxRtrSolicitations:          defaultMaxRtrSolicitations,
		RtrSolicitationInterval:      defaultRtrSolicitationInterval,
		MaxRtrSolicitationDelay:      defaultMaxRtrSolicitationDelay,
		HandleRAs:                    defaultHandleRAs,
		DiscoverDefaultRouters:       defaultDiscoverDefaultRouters,
		DiscoverMoreSpecificRoutes:   defaultDiscoverMoreSpecificRoutes,
		DiscoverOnLinkPrefixes:       defaultDiscoverOnLinkPrefixes,
		AutoGenGlobalAddresses:       defaultAutoGenGlobalAddresses,
		AutoGenTempGlobalAddresses:   defaultAutoGenTempGlobalAddresses,
		MaxTempAddrValidLifetime:     defaultMaxTempAddrValidLifetime,
		MaxTempAddrPreferredLifetime: defaultMaxTempAddrPreferredLifetime,
		RegenAdvanceDuration:         defaultRegenAdvanceDuration,
	}
}

// validate modifies an NDPConfigurations with valid values. If invalid values
// are present in c, the corresponding default values are used instead.
func (c *NDPConfigurations) validate() {
	if c.RtrSolicitationInterval < minimumRtrSolicitationInterval {
		c.RtrSolicitationInterval = defaultRtrSolicitationInterval
	}

	if c.MaxRtrSolicitationDelay < minimumMaxRtrSolicitationDelay {
		c.MaxRtrSolicitationDelay = defaultMaxRtrSolicitationDelay
	}

	if c.MaxTempAddrValidLifetime < MinMaxTempAddrValidLifetime {
		c.MaxTempAddrValidLifetime = MinMaxTempAddrValidLifetime
	}

	if c.MaxTempAddrPreferredLifetime < MinMaxTempAddrPreferredLifetime || c.MaxTempAddrPreferredLifetime > c.MaxTempAddrValidLifetime {
		c.MaxTempAddrPreferredLifetime = MinMaxTempAddrPreferredLifetime
	}

	if c.RegenAdvanceDuration < minRegenAdvanceDuration {
		c.RegenAdvanceDuration = minRegenAdvanceDuration
	}
}

type timer struct {
	// done indicates to the timer that the timer was stopped.
	done *bool

	timer tcpip.Timer
}

type offLinkRoute struct {
	dest   tcpip.Subnet
	router tcpip.Address
}

// ndpState is the per-Interface NDP state.
type ndpState struct {
	// Do not allow overwriting this state.
	_ sync.NoCopy

	// The IPv6 endpoint this ndpState is for.
	ep *endpoint

	// configs is the per-interface NDP configurations.
	configs NDPConfigurations

	// The DAD timers to send the next NS message, or resolve the address.
	dad ip.DAD

	// The off-link routes discovered through Router Advertisements.
	offLinkRoutes map[offLinkRoute]offLinkRouteState

	// rtrSolicitTimer is the timer used to send the next router solicitation
	// message.
	//
	// rtrSolicitTimer is the zero value when NDP is not soliciting routers.
	rtrSolicitTimer timer

	// The on-link prefixes discovered through Router Advertisements' Prefix
	// Information option.
	onLinkPrefixes map[tcpip.Subnet]onLinkPrefixState

	// The SLAAC prefixes discovered through Router Advertisements' Prefix
	// Information option.
	slaacPrefixes map[tcpip.Subnet]slaacPrefixState

	// The last learned DHCPv6 configuration from an NDP RA.
	dhcpv6Configuration DHCPv6ConfigurationFromNDPRA

	// temporaryIIDHistory is the history value used to generate a new temporary
	// IID.
	temporaryIIDHistory [header.IIDSize]byte

	// temporaryAddressDesyncFactor is the preferred lifetime's desync factor for
	// temporary SLAAC addresses.
	temporaryAddressDesyncFactor time.Duration
}

// offLinkRouteState holds data associated with an off-link route discovered by
// a Router Advertisement (RA).
type offLinkRouteState struct {
	prf header.NDPRoutePreference

	// Job to invalidate the route.
	//
	// Must not be nil.
	invalidationJob *tcpip.Job
}

// onLinkPrefixState holds data associated with an on-link prefix discovered by
// a Router Advertisement's Prefix Information option (PI) when the NDP
// configurations was configured to do so.
type onLinkPrefixState struct {
	// Job to invalidate the on-link prefix.
	//
	// Must not be nil.
	invalidationJob *tcpip.Job
}

// tempSLAACAddrState holds state associated with a temporary SLAAC address.
type tempSLAACAddrState struct {
	// Job to deprecate the temporary SLAAC address.
	//
	// Must not be nil.
	deprecationJob *tcpip.Job

	// Job to invalidate the temporary SLAAC address.
	//
	// Must not be nil.
	invalidationJob *tcpip.Job

	// Job to regenerate the temporary SLAAC address.
	//
	// Must not be nil.
	regenJob *tcpip.Job

	createdAt tcpip.MonotonicTime

	// The address's endpoint.
	//
	// Must not be nil.
	addressEndpoint stack.AddressEndpoint

	// Has a new temporary SLAAC address already been regenerated?
	regenerated bool
}

// slaacPrefixState holds state associated with a SLAAC prefix.
type slaacPrefixState struct {
	// Job to deprecate the prefix.
	//
	// Must not be nil.
	deprecationJob *tcpip.Job

	// Job to invalidate the prefix.
	//
	// Must not be nil.
	invalidationJob *tcpip.Job

	// nil iff the address is valid forever.
	validUntil *tcpip.MonotonicTime

	// nil iff the address is preferred forever.
	preferredUntil *tcpip.MonotonicTime

	// State associated with the stable address generated for the prefix.
	stableAddr struct {
		// The address's endpoint.
		//
		// May only be nil when the address is being (re-)generated. Otherwise,
		// must not be nil as all SLAAC prefixes must have a stable address.
		addressEndpoint stack.AddressEndpoint

		// The number of times an address has been generated locally where the IPv6
		// endpoint already had the generated address.
		localGenerationFailures uint8
	}

	// The temporary (short-lived) addresses generated for the SLAAC prefix.
	tempAddrs map[tcpip.Address]tempSLAACAddrState

	// The next two fields are used by both stable and temporary addresses
	// generated for a SLAAC prefix. This is safe as only 1 address is in the
	// generation and DAD process at any time. That is, no two addresses are
	// generated at the same time for a given SLAAC prefix.

	// The number of times an address has been generated and added to the IPv6
	// endpoint.
	//
	// Addresses may be regenerated in reseponse to a DAD conflicts.
	generationAttempts uint8

	// The maximum number of times to attempt regeneration of a SLAAC address
	// in response to DAD conflicts.
	maxGenerationAttempts uint8
}

// startDuplicateAddressDetection performs Duplicate Address Detection.
//
// This function must only be called by IPv6 addresses that are currently
// tentative.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) startDuplicateAddressDetection(addr tcpip.Address, addressEndpoint stack.AddressEndpoint) tcpip.Error {
	// addr must be a valid unicast IPv6 address.
	if !header.IsV6UnicastAddress(addr) {
		return &tcpip.ErrAddressFamilyNotSupported{}
	}

	if addressEndpoint.GetKind() != stack.PermanentTentative {
		// The endpoint should be marked as tentative since we are starting DAD.
		panic(fmt.Sprintf("ndpdad: addr %s is not tentative on NIC(%d)", addr, ndp.ep.nic.ID()))
	}

	ret := ndp.dad.CheckDuplicateAddressLocked(addr, func(r stack.DADResult) {
		if addressEndpoint.GetKind() != stack.PermanentTentative {
			// The endpoint should still be marked as tentative since we are still
			// performing DAD on it.
			panic(fmt.Sprintf("ndpdad: addr %s is no longer tentative on NIC(%d)", addr, ndp.ep.nic.ID()))
		}

		var dadSucceeded bool
		switch r.(type) {
		case *stack.DADAborted, *stack.DADError, *stack.DADDupAddrDetected:
			dadSucceeded = false
		case *stack.DADSucceeded:
			dadSucceeded = true
		default:
			panic(fmt.Sprintf("unrecognized DAD result = %T", r))
		}

		if dadSucceeded {
			addressEndpoint.SetKind(stack.Permanent)
		}

		if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
			ndpDisp.OnDuplicateAddressDetectionResult(ndp.ep.nic.ID(), addr, r)
		}

		if dadSucceeded {
			if addressEndpoint.ConfigType() == stack.AddressConfigSlaac {
				// Reset the generation attempts counter as we are starting the
				// generation of a new address for the SLAAC prefix.
				ndp.regenerateTempSLAACAddr(addressEndpoint.AddressWithPrefix().Subnet(), true /* resetGenAttempts */)
			}

			ndp.ep.onAddressAssignedLocked(addr)
		}
	})

	switch ret {
	case stack.DADStarting:
	case stack.DADAlreadyRunning:
		panic(fmt.Sprintf("ndpdad: already performing DAD for addr %s on NIC(%d)", addr, ndp.ep.nic.ID()))
	case stack.DADDisabled:
		addressEndpoint.SetKind(stack.Permanent)

		// Consider DAD to have resolved even if no DAD messages were actually
		// transmitted.
		if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
			ndpDisp.OnDuplicateAddressDetectionResult(ndp.ep.nic.ID(), addr, &stack.DADSucceeded{})
		}

		ndp.ep.onAddressAssignedLocked(addr)
	}

	return nil
}

// stopDuplicateAddressDetection ends a running Duplicate Address Detection
// process. Note, this may leave the DAD process for a tentative address in
// such a state forever, unless some other external event resolves the DAD
// process (receiving an NA from the true owner of addr, or an NS for addr
// (implying another node is attempting to use addr)). It is up to the caller
// of this function to handle such a scenario.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) stopDuplicateAddressDetection(addr tcpip.Address, reason stack.DADResult) {
	ndp.dad.StopLocked(addr, reason)
}

// handleRA handles a Router Advertisement message that arrived on the NIC
// this ndp is for. Does nothing if the NIC is configured to not handle RAs.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) handleRA(ip tcpip.Address, ra header.NDPRouterAdvert) {
	// Is the IPv6 endpoint configured to handle RAs at all?
	//
	// Currently, the stack does not determine router interface status on a
	// per-interface basis; it is a protocol-wide configuration, so we check the
	// protocol's forwarding flag to determine if the IPv6 endpoint is forwarding
	// packets.
	if !ndp.configs.HandleRAs.enabled(ndp.ep.Forwarding()) {
		ndp.ep.stats.localStats.UnhandledRouterAdvertisements.Increment()
		return
	}

	// Only worry about the DHCPv6 configuration if we have an NDPDispatcher as we
	// only inform the dispatcher on configuration changes. We do nothing else
	// with the information.
	if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
		var configuration DHCPv6ConfigurationFromNDPRA
		switch {
		case ra.ManagedAddrConfFlag():
			configuration = DHCPv6ManagedAddress

		case ra.OtherConfFlag():
			configuration = DHCPv6OtherConfigurations

		default:
			configuration = DHCPv6NoConfiguration
		}

		if ndp.dhcpv6Configuration != configuration {
			ndp.dhcpv6Configuration = configuration
			ndpDisp.OnDHCPv6Configuration(ndp.ep.nic.ID(), configuration)
		}
	}

	// Is the IPv6 endpoint configured to discover default routers?
	if ndp.configs.DiscoverDefaultRouters {
		prf := ra.DefaultRouterPreference()
		if prf == header.ReservedRoutePreference {
			// As per RFC 4191 section 2.2,
			//
			//   Prf (Default Router Preference)
			//
			//     If the Reserved (10) value is received, the receiver MUST treat the
			//     value as if it were (00).
			//
			// Note that the value 00 is the medium (default) router preference value.
			prf = header.MediumRoutePreference
		}

		// We represent default routers with a default (off-link) route through the
		// router.
		ndp.handleOffLinkRouteDiscovery(offLinkRoute{dest: header.IPv6EmptySubnet, router: ip}, ra.RouterLifetime(), prf)
	}

	// TODO(b/141556115): Do (RetransTimer, ReachableTime)) Parameter
	//                    Discovery.

	// We know the options is valid as far as wire format is concerned since
	// we got the Router Advertisement, as documented by this fn. Given this
	// we do not check the iterator for errors on calls to Next.
	it, _ := ra.Options().Iter(false)
	for opt, done, _ := it.Next(); !done; opt, done, _ = it.Next() {
		switch opt := opt.(type) {
		case header.NDPRecursiveDNSServer:
			if ndp.ep.protocol.options.NDPDisp == nil {
				continue
			}

			addrs, _ := opt.Addresses()
			ndp.ep.protocol.options.NDPDisp.OnRecursiveDNSServerOption(ndp.ep.nic.ID(), addrs, opt.Lifetime())

		case header.NDPDNSSearchList:
			if ndp.ep.protocol.options.NDPDisp == nil {
				continue
			}

			domainNames, _ := opt.DomainNames()
			ndp.ep.protocol.options.NDPDisp.OnDNSSearchListOption(ndp.ep.nic.ID(), domainNames, opt.Lifetime())

		case header.NDPPrefixInformation:
			prefix := opt.Subnet()

			// Is the prefix a link-local?
			if header.IsV6LinkLocalUnicastAddress(prefix.ID()) {
				// ...Yes, skip as per RFC 4861 section 6.3.4,
				// and RFC 4862 section 5.5.3.b (for SLAAC).
				continue
			}

			// Is the Prefix Length 0?
			if prefix.Prefix() == 0 {
				// ...Yes, skip as this is an invalid prefix
				// as all IPv6 addresses cannot be on-link.
				continue
			}

			if opt.OnLinkFlag() {
				ndp.handleOnLinkPrefixInformation(opt)
			}

			if opt.AutonomousAddressConfigurationFlag() {
				ndp.handleAutonomousPrefixInformation(opt)
			}

		case header.NDPRouteInformation:
			if !ndp.configs.DiscoverMoreSpecificRoutes {
				continue
			}

			dest, err := opt.Prefix()
			if err != nil {
				panic(fmt.Sprintf("%T.Prefix(): %s", opt, err))
			}

			prf := opt.RoutePreference()
			if prf == header.ReservedRoutePreference {
				// As per RFC 4191 section 2.3,
				//
				//   Prf (Route Preference)
				//       2-bit signed integer.  The Route Preference indicates
				//       whether to prefer the router associated with this prefix
				//       over others, when multiple identical prefixes (for
				//       different routers) have been received.  If the Reserved
				//       (10) value is received, the Route Information Option MUST
				//       be ignored.
				continue
			}

			ndp.handleOffLinkRouteDiscovery(offLinkRoute{dest: dest, router: ip}, opt.RouteLifetime(), prf)
		}

		// TODO(b/141556115): Do (MTU) Parameter Discovery.
	}
}

// invalidateOffLinkRoute invalidates a discovered off-link route.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) invalidateOffLinkRoute(route offLinkRoute) {
	state, ok := ndp.offLinkRoutes[route]
	if !ok {
		return
	}

	state.invalidationJob.Cancel()
	delete(ndp.offLinkRoutes, route)

	// Let the integrator know a discovered off-link route is invalidated.
	if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
		ndpDisp.OnOffLinkRouteInvalidated(ndp.ep.nic.ID(), route.dest, route.router)
	}
}

// handleOffLinkRouteDiscovery handles the discovery of an off-link route.
//
// Precondition: ndp.ep.mu must be locked.
func (ndp *ndpState) handleOffLinkRouteDiscovery(route offLinkRoute, lifetime time.Duration, prf header.NDPRoutePreference) {
	ndpDisp := ndp.ep.protocol.options.NDPDisp
	if ndpDisp == nil {
		return
	}

	state, ok := ndp.offLinkRoutes[route]
	switch {
	case !ok && lifetime != 0:
		// This is a new route we are discovering.
		//
		// Only remember it if we currently know about less than
		// MaxDiscoveredOffLinkRoutes routers.
		if len(ndp.offLinkRoutes) < MaxDiscoveredOffLinkRoutes {
			// Inform the integrator when we discovered an off-link route.
			ndpDisp.OnOffLinkRouteUpdated(ndp.ep.nic.ID(), route.dest, route.router, prf)

			state := offLinkRouteState{
				prf: prf,
				invalidationJob: tcpip.NewJob(ndp.ep.protocol.stack.Clock(), &ndp.ep.mu, func() {
					ndp.invalidateOffLinkRoute(route)
				}),
			}

			state.invalidationJob.Schedule(lifetime)

			ndp.offLinkRoutes[route] = state
		}

	case ok && lifetime != 0:
		// This is an already discovered off-link route. Update the lifetime.
		state.invalidationJob.Cancel()
		state.invalidationJob.Schedule(lifetime)

		if prf != state.prf {
			state.prf = prf

			// Inform the integrator about route preference updates.
			ndpDisp.OnOffLinkRouteUpdated(ndp.ep.nic.ID(), route.dest, route.router, prf)
		}

		ndp.offLinkRoutes[route] = state

	case ok && lifetime == 0:
		// The already discovered off-link route is no longer considered valid so we
		// invalidate it immediately.
		ndp.invalidateOffLinkRoute(route)
	}
}

// rememberOnLinkPrefix remembers a newly discovered on-link prefix with IPv6
// address with prefix prefix with lifetime l.
//
// The prefix identified by prefix MUST NOT already be known.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) rememberOnLinkPrefix(prefix tcpip.Subnet, l time.Duration) {
	ndpDisp := ndp.ep.protocol.options.NDPDisp
	if ndpDisp == nil {
		return
	}

	// Inform the integrator when we discovered an on-link prefix.
	ndpDisp.OnOnLinkPrefixDiscovered(ndp.ep.nic.ID(), prefix)

	state := onLinkPrefixState{
		invalidationJob: tcpip.NewJob(ndp.ep.protocol.stack.Clock(), &ndp.ep.mu, func() {
			ndp.invalidateOnLinkPrefix(prefix)
		}),
	}

	if l < header.NDPInfiniteLifetime {
		state.invalidationJob.Schedule(l)
	}

	ndp.onLinkPrefixes[prefix] = state
}

// invalidateOnLinkPrefix invalidates a discovered on-link prefix.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) invalidateOnLinkPrefix(prefix tcpip.Subnet) {
	s, ok := ndp.onLinkPrefixes[prefix]

	// Is the on-link prefix still discovered?
	if !ok {
		// ...Nope, do nothing further.
		return
	}

	s.invalidationJob.Cancel()
	delete(ndp.onLinkPrefixes, prefix)

	// Let the integrator know a discovered on-link prefix is invalidated.
	if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
		ndpDisp.OnOnLinkPrefixInvalidated(ndp.ep.nic.ID(), prefix)
	}
}

// handleOnLinkPrefixInformation handles a Prefix Information option with
// its on-link flag set, as per RFC 4861 section 6.3.4.
//
// handleOnLinkPrefixInformation assumes that the prefix this pi is for is
// not the link-local prefix and the on-link flag is set.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) handleOnLinkPrefixInformation(pi header.NDPPrefixInformation) {
	prefix := pi.Subnet()
	prefixState, ok := ndp.onLinkPrefixes[prefix]
	vl := pi.ValidLifetime()

	if !ok && vl == 0 {
		// Don't know about this prefix but it has a zero valid
		// lifetime, so just ignore.
		return
	}

	if !ok && vl != 0 {
		// This is a new on-link prefix we are discovering
		//
		// Only remember it if we currently know about less than
		// MaxDiscoveredOnLinkPrefixes on-link prefixes.
		if ndp.configs.DiscoverOnLinkPrefixes && len(ndp.onLinkPrefixes) < MaxDiscoveredOnLinkPrefixes {
			ndp.rememberOnLinkPrefix(prefix, vl)
		}
		return
	}

	if ok && vl == 0 {
		// We know about the on-link prefix, but it is
		// no longer to be considered on-link, so
		// invalidate it.
		ndp.invalidateOnLinkPrefix(prefix)
		return
	}

	// This is an already discovered on-link prefix with a
	// new non-zero valid lifetime.
	//
	// Update the invalidation job.

	prefixState.invalidationJob.Cancel()

	if vl < header.NDPInfiniteLifetime {
		// Prefix is valid for a finite lifetime, schedule the job to execute after
		// the new valid lifetime.
		prefixState.invalidationJob.Schedule(vl)
	}

	ndp.onLinkPrefixes[prefix] = prefixState
}

// handleAutonomousPrefixInformation handles a Prefix Information option with
// its autonomous flag set, as per RFC 4862 section 5.5.3.
//
// handleAutonomousPrefixInformation assumes that the prefix this pi is for is
// not the link-local prefix and the autonomous flag is set.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) handleAutonomousPrefixInformation(pi header.NDPPrefixInformation) {
	vl := pi.ValidLifetime()
	pl := pi.PreferredLifetime()

	// If the preferred lifetime is greater than the valid lifetime,
	// silently ignore the Prefix Information option, as per RFC 4862
	// section 5.5.3.c.
	if pl > vl {
		return
	}

	prefix := pi.Subnet()

	// Check if we already maintain SLAAC state for prefix.
	if state, ok := ndp.slaacPrefixes[prefix]; ok {
		// As per RFC 4862 section 5.5.3.e, refresh prefix's SLAAC lifetimes.
		ndp.refreshSLAACPrefixLifetimes(prefix, &state, pl, vl)
		ndp.slaacPrefixes[prefix] = state
		return
	}

	// prefix is a new SLAAC prefix. Do the work as outlined by RFC 4862 section
	// 5.5.3.d if ndp is configured to auto-generate new addresses via SLAAC.
	if !ndp.configs.AutoGenGlobalAddresses {
		return
	}

	ndp.doSLAAC(prefix, pl, vl)
}

// doSLAAC generates a new SLAAC address with the provided lifetimes
// for prefix.
//
// pl is the new preferred lifetime. vl is the new valid lifetime.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) doSLAAC(prefix tcpip.Subnet, pl, vl time.Duration) {
	// If we do not already have an address for this prefix and the valid
	// lifetime is 0, no need to do anything further, as per RFC 4862
	// section 5.5.3.d.
	if vl == 0 {
		return
	}

	// Make sure the prefix is valid (as far as its length is concerned) to
	// generate a valid IPv6 address from an interface identifier (IID), as
	// per RFC 4862 sectiion 5.5.3.d.
	if prefix.Prefix() != validPrefixLenForAutoGen {
		return
	}

	state := slaacPrefixState{
		deprecationJob: tcpip.NewJob(ndp.ep.protocol.stack.Clock(), &ndp.ep.mu, func() {
			state, ok := ndp.slaacPrefixes[prefix]
			if !ok {
				panic(fmt.Sprintf("ndp: must have a slaacPrefixes entry for the deprecated SLAAC prefix %s", prefix))
			}

			ndp.deprecateSLAACAddress(state.stableAddr.addressEndpoint)
		}),
		invalidationJob: tcpip.NewJob(ndp.ep.protocol.stack.Clock(), &ndp.ep.mu, func() {
			state, ok := ndp.slaacPrefixes[prefix]
			if !ok {
				panic(fmt.Sprintf("ndp: must have a slaacPrefixes entry for the invalidated SLAAC prefix %s", prefix))
			}

			ndp.invalidateSLAACPrefix(prefix, state)
		}),
		tempAddrs:             make(map[tcpip.Address]tempSLAACAddrState),
		maxGenerationAttempts: ndp.configs.AutoGenAddressConflictRetries + 1,
	}

	now := ndp.ep.protocol.stack.Clock().NowMonotonic()

	// The time an address is preferred until is needed to properly generate the
	// address.
	if pl < header.NDPInfiniteLifetime {
		t := now.Add(pl)
		state.preferredUntil = &t
	}

	if !ndp.generateSLAACAddr(prefix, &state) {
		// We were unable to generate an address for the prefix, we do not nothing
		// further as there is no reason to maintain state or jobs for a prefix we
		// do not have an address for.
		return
	}

	// Setup the initial jobs to deprecate and invalidate prefix.

	if pl < header.NDPInfiniteLifetime && pl != 0 {
		state.deprecationJob.Schedule(pl)
	}

	if vl < header.NDPInfiniteLifetime {
		state.invalidationJob.Schedule(vl)
		t := now.Add(vl)
		state.validUntil = &t
	}

	// If the address is assigned (DAD resolved), generate a temporary address.
	if state.stableAddr.addressEndpoint.GetKind() == stack.Permanent {
		// Reset the generation attempts counter as we are starting the generation
		// of a new address for the SLAAC prefix.
		ndp.generateTempSLAACAddr(prefix, &state, true /* resetGenAttempts */)
	}

	ndp.slaacPrefixes[prefix] = state
}

// addAndAcquireSLAACAddr adds a SLAAC address to the IPv6 endpoint.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) addAndAcquireSLAACAddr(addr tcpip.AddressWithPrefix, configType stack.AddressConfigType, deprecated bool) stack.AddressEndpoint {
	// Inform the integrator that we have a new SLAAC address.
	ndpDisp := ndp.ep.protocol.options.NDPDisp
	if ndpDisp == nil {
		return nil
	}

	addressEndpoint, err := ndp.ep.addAndAcquirePermanentAddressLocked(addr, stack.AddressProperties{
		PEB:        stack.FirstPrimaryEndpoint,
		ConfigType: configType,
		Deprecated: deprecated,
	})
	if err != nil {
		panic(fmt.Sprintf("ndp: error when adding SLAAC address %+v: %s", addr, err))
	}

	ndpDisp.OnAutoGenAddress(ndp.ep.nic.ID(), addr)

	return addressEndpoint
}

// generateSLAACAddr generates a SLAAC address for prefix.
//
// Returns true if an address was successfully generated.
//
// Panics if the prefix is not a SLAAC prefix or it already has an address.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) generateSLAACAddr(prefix tcpip.Subnet, state *slaacPrefixState) bool {
	if addressEndpoint := state.stableAddr.addressEndpoint; addressEndpoint != nil {
		panic(fmt.Sprintf("ndp: SLAAC prefix %s already has a permenant address %s", prefix, addressEndpoint.AddressWithPrefix()))
	}

	// If we have already reached the maximum address generation attempts for the
	// prefix, do not generate another address.
	if state.generationAttempts == state.maxGenerationAttempts {
		return false
	}

	var generatedAddr tcpip.AddressWithPrefix
	addrBytes := []byte(prefix.ID())

	for i := 0; ; i++ {
		// If we were unable to generate an address after the maximum SLAAC address
		// local regeneration attempts, do nothing further.
		if i == maxSLAACAddrLocalRegenAttempts {
			return false
		}

		dadCounter := state.generationAttempts + state.stableAddr.localGenerationFailures
		if oIID := ndp.ep.protocol.options.OpaqueIIDOpts; oIID.NICNameFromID != nil {
			addrBytes = header.AppendOpaqueInterfaceIdentifier(
				addrBytes[:header.IIDOffsetInIPv6Address],
				prefix,
				oIID.NICNameFromID(ndp.ep.nic.ID(), ndp.ep.nic.Name()),
				dadCounter,
				oIID.SecretKey,
			)
		} else if dadCounter == 0 {
			// Modified-EUI64 based IIDs have no way to resolve DAD conflicts, so if
			// the DAD counter is non-zero, we cannot use this method.
			//
			// Only attempt to generate an interface-specific IID if we have a valid
			// link address.
			//
			// TODO(b/141011931): Validate a LinkEndpoint's link address (provided by
			// LinkEndpoint.LinkAddress) before reaching this point.
			linkAddr := ndp.ep.nic.LinkAddress()
			if !header.IsValidUnicastEthernetAddress(linkAddr) {
				return false
			}

			// Generate an address within prefix from the modified EUI-64 of ndp's
			// NIC's Ethernet MAC address.
			header.EthernetAdddressToModifiedEUI64IntoBuf(linkAddr, addrBytes[header.IIDOffsetInIPv6Address:])
		} else {
			// We have no way to regenerate an address in response to an address
			// conflict when addresses are not generated with opaque IIDs.
			return false
		}

		generatedAddr = tcpip.AddressWithPrefix{
			Address:   tcpip.Address(addrBytes),
			PrefixLen: validPrefixLenForAutoGen,
		}

		if !ndp.ep.hasPermanentAddressRLocked(generatedAddr.Address) {
			break
		}

		state.stableAddr.localGenerationFailures++
	}

	deprecated := state.preferredUntil != nil && !state.preferredUntil.After(ndp.ep.protocol.stack.Clock().NowMonotonic())
	if addressEndpoint := ndp.addAndAcquireSLAACAddr(generatedAddr, stack.AddressConfigSlaac, deprecated); addressEndpoint != nil {
		state.stableAddr.addressEndpoint = addressEndpoint
		state.generationAttempts++
		return true
	}

	return false
}

// regenerateSLAACAddr regenerates an address for a SLAAC prefix.
//
// If generating a new address for the prefix fails, the prefix is invalidated.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) regenerateSLAACAddr(prefix tcpip.Subnet) {
	state, ok := ndp.slaacPrefixes[prefix]
	if !ok {
		panic(fmt.Sprintf("ndp: SLAAC prefix state not found to regenerate address for %s", prefix))
	}

	if ndp.generateSLAACAddr(prefix, &state) {
		ndp.slaacPrefixes[prefix] = state
		return
	}

	// We were unable to generate a permanent address for the SLAAC prefix so
	// invalidate the prefix as there is no reason to maintain state for a
	// SLAAC prefix we do not have an address for.
	ndp.invalidateSLAACPrefix(prefix, state)
}

// generateTempSLAACAddr generates a new temporary SLAAC address.
//
// If resetGenAttempts is true, the prefix's generation counter is reset.
//
// Returns true if a new address was generated.
func (ndp *ndpState) generateTempSLAACAddr(prefix tcpip.Subnet, prefixState *slaacPrefixState, resetGenAttempts bool) bool {
	// Are we configured to auto-generate new temporary global addresses for the
	// prefix?
	if !ndp.configs.AutoGenTempGlobalAddresses || prefix == header.IPv6LinkLocalPrefix.Subnet() {
		return false
	}

	if resetGenAttempts {
		prefixState.generationAttempts = 0
		prefixState.maxGenerationAttempts = ndp.configs.AutoGenAddressConflictRetries + 1
	}

	// If we have already reached the maximum address generation attempts for the
	// prefix, do not generate another address.
	if prefixState.generationAttempts == prefixState.maxGenerationAttempts {
		return false
	}

	stableAddr := prefixState.stableAddr.addressEndpoint.AddressWithPrefix().Address
	now := ndp.ep.protocol.stack.Clock().NowMonotonic()

	// As per RFC 4941 section 3.3 step 4, the valid lifetime of a temporary
	// address is the lower of the valid lifetime of the stable address or the
	// maximum temporary address valid lifetime.
	vl := ndp.configs.MaxTempAddrValidLifetime
	if prefixState.validUntil != nil {
		if prefixVL := prefixState.validUntil.Sub(now); vl > prefixVL {
			vl = prefixVL
		}
	}

	if vl <= 0 {
		// Cannot create an address without a valid lifetime.
		return false
	}

	// As per RFC 4941 section 3.3 step 4, the preferred lifetime of a temporary
	// address is the lower of the preferred lifetime of the stable address or the
	// maximum temporary address preferred lifetime - the temporary address desync
	// factor.
	pl := ndp.configs.MaxTempAddrPreferredLifetime - ndp.temporaryAddressDesyncFactor
	if prefixState.preferredUntil != nil {
		if prefixPL := prefixState.preferredUntil.Sub(now); pl > prefixPL {
			// Respect the preferred lifetime of the prefix, as per RFC 4941 section
			// 3.3 step 4.
			pl = prefixPL
		}
	}

	// As per RFC 4941 section 3.3 step 5, a temporary address is created only if
	// the calculated preferred lifetime is greater than the advance regeneration
	// duration. In particular, we MUST NOT create a temporary address with a zero
	// Preferred Lifetime.
	if pl <= ndp.configs.RegenAdvanceDuration {
		return false
	}

	// Attempt to generate a new address that is not already assigned to the IPv6
	// endpoint.
	var generatedAddr tcpip.AddressWithPrefix
	for i := 0; ; i++ {
		// If we were unable to generate an address after the maximum SLAAC address
		// local regeneration attempts, do nothing further.
		if i == maxSLAACAddrLocalRegenAttempts {
			return false
		}

		generatedAddr = header.GenerateTempIPv6SLAACAddr(ndp.temporaryIIDHistory[:], stableAddr)
		if !ndp.ep.hasPermanentAddressRLocked(generatedAddr.Address) {
			break
		}
	}

	// As per RFC RFC 4941 section 3.3 step 5, we MUST NOT create a temporary
	// address with a zero preferred lifetime. The checks above ensure this
	// so we know the address is not deprecated.
	addressEndpoint := ndp.addAndAcquireSLAACAddr(generatedAddr, stack.AddressConfigSlaacTemp, false /* deprecated */)
	if addressEndpoint == nil {
		return false
	}

	state := tempSLAACAddrState{
		deprecationJob: tcpip.NewJob(ndp.ep.protocol.stack.Clock(), &ndp.ep.mu, func() {
			prefixState, ok := ndp.slaacPrefixes[prefix]
			if !ok {
				panic(fmt.Sprintf("ndp: must have a slaacPrefixes entry for %s to deprecate temporary address %s", prefix, generatedAddr))
			}

			tempAddrState, ok := prefixState.tempAddrs[generatedAddr.Address]
			if !ok {
				panic(fmt.Sprintf("ndp: must have a tempAddr entry to deprecate temporary address %s", generatedAddr))
			}

			ndp.deprecateSLAACAddress(tempAddrState.addressEndpoint)
		}),
		invalidationJob: tcpip.NewJob(ndp.ep.protocol.stack.Clock(), &ndp.ep.mu, func() {
			prefixState, ok := ndp.slaacPrefixes[prefix]
			if !ok {
				panic(fmt.Sprintf("ndp: must have a slaacPrefixes entry for %s to invalidate temporary address %s", prefix, generatedAddr))
			}

			tempAddrState, ok := prefixState.tempAddrs[generatedAddr.Address]
			if !ok {
				panic(fmt.Sprintf("ndp: must have a tempAddr entry to invalidate temporary address %s", generatedAddr))
			}

			ndp.invalidateTempSLAACAddr(prefixState.tempAddrs, generatedAddr.Address, tempAddrState)
		}),
		regenJob: tcpip.NewJob(ndp.ep.protocol.stack.Clock(), &ndp.ep.mu, func() {
			prefixState, ok := ndp.slaacPrefixes[prefix]
			if !ok {
				panic(fmt.Sprintf("ndp: must have a slaacPrefixes entry for %s to regenerate temporary address after %s", prefix, generatedAddr))
			}

			tempAddrState, ok := prefixState.tempAddrs[generatedAddr.Address]
			if !ok {
				panic(fmt.Sprintf("ndp: must have a tempAddr entry to regenerate temporary address after %s", generatedAddr))
			}

			// If an address has already been regenerated for this address, don't
			// regenerate another address.
			if tempAddrState.regenerated {
				return
			}

			// Reset the generation attempts counter as we are starting the generation
			// of a new address for the SLAAC prefix.
			tempAddrState.regenerated = ndp.generateTempSLAACAddr(prefix, &prefixState, true /* resetGenAttempts */)
			prefixState.tempAddrs[generatedAddr.Address] = tempAddrState
			ndp.slaacPrefixes[prefix] = prefixState
		}),
		createdAt:       now,
		addressEndpoint: addressEndpoint,
	}

	state.deprecationJob.Schedule(pl)
	state.invalidationJob.Schedule(vl)
	state.regenJob.Schedule(pl - ndp.configs.RegenAdvanceDuration)

	prefixState.generationAttempts++
	prefixState.tempAddrs[generatedAddr.Address] = state

	return true
}

// regenerateTempSLAACAddr regenerates a temporary address for a SLAAC prefix.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) regenerateTempSLAACAddr(prefix tcpip.Subnet, resetGenAttempts bool) {
	state, ok := ndp.slaacPrefixes[prefix]
	if !ok {
		panic(fmt.Sprintf("ndp: SLAAC prefix state not found to regenerate temporary address for %s", prefix))
	}

	ndp.generateTempSLAACAddr(prefix, &state, resetGenAttempts)
	ndp.slaacPrefixes[prefix] = state
}

// refreshSLAACPrefixLifetimes refreshes the lifetimes of a SLAAC prefix.
//
// pl is the new preferred lifetime. vl is the new valid lifetime.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) refreshSLAACPrefixLifetimes(prefix tcpip.Subnet, prefixState *slaacPrefixState, pl, vl time.Duration) {
	// If the preferred lifetime is zero, then the prefix should be deprecated.
	deprecated := pl == 0
	if deprecated {
		ndp.deprecateSLAACAddress(prefixState.stableAddr.addressEndpoint)
	} else {
		prefixState.stableAddr.addressEndpoint.SetDeprecated(false)
	}

	// If prefix was preferred for some finite lifetime before, cancel the
	// deprecation job so it can be reset.
	prefixState.deprecationJob.Cancel()

	now := ndp.ep.protocol.stack.Clock().NowMonotonic()

	// Schedule the deprecation job if prefix has a finite preferred lifetime.
	if pl < header.NDPInfiniteLifetime {
		if !deprecated {
			prefixState.deprecationJob.Schedule(pl)
		}
		t := now.Add(pl)
		prefixState.preferredUntil = &t
	} else {
		prefixState.preferredUntil = nil
	}

	// As per RFC 4862 section 5.5.3.e, update the valid lifetime for prefix:
	//
	// 1) If the received Valid Lifetime is greater than 2 hours or greater than
	//    RemainingLifetime, set the valid lifetime of the prefix to the
	//    advertised Valid Lifetime.
	//
	// 2) If RemainingLifetime is less than or equal to 2 hours, ignore the
	//    advertised Valid Lifetime.
	//
	// 3) Otherwise, reset the valid lifetime of the prefix to 2 hours.

	if vl >= header.NDPInfiniteLifetime {
		// Handle the infinite valid lifetime separately as we do not schedule a
		// job in this case.
		prefixState.invalidationJob.Cancel()
		prefixState.validUntil = nil
	} else {
		var effectiveVl time.Duration
		var rl time.Duration

		// If the prefix was originally set to be valid forever, assume the
		// remaining time to be the maximum possible value.
		if prefixState.validUntil == nil {
			rl = header.NDPInfiniteLifetime
		} else {
			rl = prefixState.validUntil.Sub(now)
		}

		if vl > MinPrefixInformationValidLifetimeForUpdate || vl > rl {
			effectiveVl = vl
		} else if rl > MinPrefixInformationValidLifetimeForUpdate {
			effectiveVl = MinPrefixInformationValidLifetimeForUpdate
		}

		if effectiveVl != 0 {
			prefixState.invalidationJob.Cancel()
			prefixState.invalidationJob.Schedule(effectiveVl)
			t := now.Add(effectiveVl)
			prefixState.validUntil = &t
		}
	}

	// If DAD is not yet complete on the stable address, there is no need to do
	// work with temporary addresses.
	if prefixState.stableAddr.addressEndpoint.GetKind() != stack.Permanent {
		return
	}

	// Note, we do not need to update the entries in the temporary address map
	// after updating the jobs because the jobs are held as pointers.
	var regenForAddr tcpip.Address
	allAddressesRegenerated := true
	for tempAddr, tempAddrState := range prefixState.tempAddrs {
		// As per RFC 4941 section 3.3 step 4, the valid lifetime of a temporary
		// address is the lower of the valid lifetime of the stable address or the
		// maximum temporary address valid lifetime. Note, the valid lifetime of a
		// temporary address is relative to the address's creation time.
		validUntil := tempAddrState.createdAt.Add(ndp.configs.MaxTempAddrValidLifetime)
		if prefixState.validUntil != nil && prefixState.validUntil.Before(validUntil) {
			validUntil = *prefixState.validUntil
		}

		// If the address is no longer valid, invalidate it immediately. Otherwise,
		// reset the invalidation job.
		newValidLifetime := validUntil.Sub(now)
		if newValidLifetime <= 0 {
			ndp.invalidateTempSLAACAddr(prefixState.tempAddrs, tempAddr, tempAddrState)
			continue
		}
		tempAddrState.invalidationJob.Cancel()
		tempAddrState.invalidationJob.Schedule(newValidLifetime)

		// As per RFC 4941 section 3.3 step 4, the preferred lifetime of a temporary
		// address is the lower of the preferred lifetime of the stable address or
		// the maximum temporary address preferred lifetime - the temporary address
		// desync factor. Note, the preferred lifetime of a temporary address is
		// relative to the address's creation time.
		preferredUntil := tempAddrState.createdAt.Add(ndp.configs.MaxTempAddrPreferredLifetime - ndp.temporaryAddressDesyncFactor)
		if prefixState.preferredUntil != nil && prefixState.preferredUntil.Before(preferredUntil) {
			preferredUntil = *prefixState.preferredUntil
		}

		// If the address is no longer preferred, deprecate it immediately.
		// Otherwise, schedule the deprecation job again.
		newPreferredLifetime := preferredUntil.Sub(now)
		tempAddrState.deprecationJob.Cancel()

		if newPreferredLifetime <= 0 {
			ndp.deprecateSLAACAddress(tempAddrState.addressEndpoint)
		} else {
			tempAddrState.addressEndpoint.SetDeprecated(false)
			tempAddrState.deprecationJob.Schedule(newPreferredLifetime)
		}

		tempAddrState.regenJob.Cancel()
		if tempAddrState.regenerated {
		} else {
			allAddressesRegenerated = false

			if newPreferredLifetime <= ndp.configs.RegenAdvanceDuration {
				// The new preferred lifetime is less than the advance regeneration
				// duration so regenerate an address for this temporary address
				// immediately after we finish iterating over the temporary addresses.
				regenForAddr = tempAddr
			} else {
				tempAddrState.regenJob.Schedule(newPreferredLifetime - ndp.configs.RegenAdvanceDuration)
			}
		}
	}

	// Generate a new temporary address if all of the existing temporary addresses
	// have been regenerated, or we need to immediately regenerate an address
	// due to an update in preferred lifetime.
	//
	// If each temporay address has already been regenerated, no new temporary
	// address is generated. To ensure continuation of temporary SLAAC addresses,
	// we manually try to regenerate an address here.
	if len(regenForAddr) != 0 || allAddressesRegenerated {
		// Reset the generation attempts counter as we are starting the generation
		// of a new address for the SLAAC prefix.
		if state, ok := prefixState.tempAddrs[regenForAddr]; ndp.generateTempSLAACAddr(prefix, prefixState, true /* resetGenAttempts */) && ok {
			state.regenerated = true
			prefixState.tempAddrs[regenForAddr] = state
		}
	}
}

// deprecateSLAACAddress marks the address as deprecated and notifies the NDP
// dispatcher that address has been deprecated.
//
// deprecateSLAACAddress does nothing if the address is already deprecated.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) deprecateSLAACAddress(addressEndpoint stack.AddressEndpoint) {
	if addressEndpoint.Deprecated() {
		return
	}

	addressEndpoint.SetDeprecated(true)
	if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
		ndpDisp.OnAutoGenAddressDeprecated(ndp.ep.nic.ID(), addressEndpoint.AddressWithPrefix())
	}
}

// invalidateSLAACPrefix invalidates a SLAAC prefix.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) invalidateSLAACPrefix(prefix tcpip.Subnet, state slaacPrefixState) {
	ndp.cleanupSLAACPrefixResources(prefix, state)

	if addressEndpoint := state.stableAddr.addressEndpoint; addressEndpoint != nil {
		if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
			ndpDisp.OnAutoGenAddressInvalidated(ndp.ep.nic.ID(), addressEndpoint.AddressWithPrefix())
		}

		if err := ndp.ep.removePermanentEndpointInnerLocked(addressEndpoint, &stack.DADAborted{}); err != nil {
			panic(fmt.Sprintf("ndp: error removing stable SLAAC address %s: %s", addressEndpoint.AddressWithPrefix(), err))
		}
	}
}

// cleanupSLAACAddrResourcesAndNotify cleans up an invalidated SLAAC address's
// resources.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) cleanupSLAACAddrResourcesAndNotify(addr tcpip.AddressWithPrefix, invalidatePrefix bool) {
	if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
		ndpDisp.OnAutoGenAddressInvalidated(ndp.ep.nic.ID(), addr)
	}

	prefix := addr.Subnet()
	state, ok := ndp.slaacPrefixes[prefix]
	if !ok || state.stableAddr.addressEndpoint == nil || addr.Address != state.stableAddr.addressEndpoint.AddressWithPrefix().Address {
		return
	}

	if !invalidatePrefix {
		// If the prefix is not being invalidated, disassociate the address from the
		// prefix and do nothing further.
		state.stableAddr.addressEndpoint.DecRef()
		state.stableAddr.addressEndpoint = nil
		ndp.slaacPrefixes[prefix] = state
		return
	}

	ndp.cleanupSLAACPrefixResources(prefix, state)
}

// cleanupSLAACPrefixResources cleans up a SLAAC prefix's jobs and entry.
//
// Panics if the SLAAC prefix is not known.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) cleanupSLAACPrefixResources(prefix tcpip.Subnet, state slaacPrefixState) {
	// Invalidate all temporary addresses.
	for tempAddr, tempAddrState := range state.tempAddrs {
		ndp.invalidateTempSLAACAddr(state.tempAddrs, tempAddr, tempAddrState)
	}

	if state.stableAddr.addressEndpoint != nil {
		state.stableAddr.addressEndpoint.DecRef()
		state.stableAddr.addressEndpoint = nil
	}
	state.deprecationJob.Cancel()
	state.invalidationJob.Cancel()
	delete(ndp.slaacPrefixes, prefix)
}

// invalidateTempSLAACAddr invalidates a temporary SLAAC address.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) invalidateTempSLAACAddr(tempAddrs map[tcpip.Address]tempSLAACAddrState, tempAddr tcpip.Address, tempAddrState tempSLAACAddrState) {
	ndp.cleanupTempSLAACAddrResourcesAndNotifyInner(tempAddrs, tempAddr, tempAddrState)

	if err := ndp.ep.removePermanentEndpointInnerLocked(tempAddrState.addressEndpoint, &stack.DADAborted{}); err != nil {
		panic(fmt.Sprintf("error removing temporary SLAAC address %s: %s", tempAddrState.addressEndpoint.AddressWithPrefix(), err))
	}
}

// cleanupTempSLAACAddrResourcesAndNotify cleans up an invalidated temporary
// SLAAC address's resources from ndp and notifies the NDP dispatcher that the
// address was invalidated.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) cleanupTempSLAACAddrResourcesAndNotify(addr tcpip.AddressWithPrefix) {
	prefix := addr.Subnet()
	state, ok := ndp.slaacPrefixes[prefix]
	if !ok {
		panic(fmt.Sprintf("ndp: must have a slaacPrefixes entry to clean up temp addr %s resources", addr))
	}

	tempAddrState, ok := state.tempAddrs[addr.Address]
	if !ok {
		panic(fmt.Sprintf("ndp: must have a tempAddr entry to clean up temp addr %s resources", addr))
	}

	ndp.cleanupTempSLAACAddrResourcesAndNotifyInner(state.tempAddrs, addr.Address, tempAddrState)
}

// cleanupTempSLAACAddrResourcesAndNotifyInner is like
// cleanupTempSLAACAddrResourcesAndNotify except it does not lookup the
// temporary address's state in ndp - it assumes the passed state is valid.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) cleanupTempSLAACAddrResourcesAndNotifyInner(tempAddrs map[tcpip.Address]tempSLAACAddrState, tempAddr tcpip.Address, tempAddrState tempSLAACAddrState) {
	if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
		ndpDisp.OnAutoGenAddressInvalidated(ndp.ep.nic.ID(), tempAddrState.addressEndpoint.AddressWithPrefix())
	}

	tempAddrState.addressEndpoint.DecRef()
	tempAddrState.addressEndpoint = nil
	tempAddrState.deprecationJob.Cancel()
	tempAddrState.invalidationJob.Cancel()
	tempAddrState.regenJob.Cancel()
	delete(tempAddrs, tempAddr)
}

// cleanupState cleans up ndp's state.
//
// This function invalidates all discovered on-link prefixes, discovered
// routers, and auto-generated addresses.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) cleanupState() {
	for prefix, state := range ndp.slaacPrefixes {
		ndp.invalidateSLAACPrefix(prefix, state)
	}

	for prefix := range ndp.onLinkPrefixes {
		ndp.invalidateOnLinkPrefix(prefix)
	}

	if got := len(ndp.onLinkPrefixes); got != 0 {
		panic(fmt.Sprintf("ndp: still have discovered on-link prefixes after cleaning up; found = %d", got))
	}

	for route := range ndp.offLinkRoutes {
		ndp.invalidateOffLinkRoute(route)
	}

	if got := len(ndp.offLinkRoutes); got != 0 {
		panic(fmt.Sprintf("ndp: still have discovered off-link routes after cleaning up; found = %d", got))
	}

	ndp.dhcpv6Configuration = 0
}

// startSolicitingRouters starts soliciting routers, as per RFC 4861 section
// 6.3.7. If routers are already being solicited, this function does nothing.
//
// If ndp is not configured to handle Router Advertisements, routers will not
// be solicited as there is no point soliciting routers if we don't handle their
// advertisements.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) startSolicitingRouters() {
	if ndp.rtrSolicitTimer.timer != nil {
		// We are already soliciting routers.
		return
	}

	remaining := ndp.configs.MaxRtrSolicitations
	if remaining == 0 {
		return
	}

	if !ndp.configs.HandleRAs.enabled(ndp.ep.Forwarding()) {
		return
	}

	// Calculate the random delay before sending our first RS, as per RFC
	// 4861 section 6.3.7.
	var delay time.Duration
	if ndp.configs.MaxRtrSolicitationDelay > 0 {
		delay = time.Duration(ndp.ep.protocol.stack.Rand().Int63n(int64(ndp.configs.MaxRtrSolicitationDelay)))
	}

	// Protected by ndp.ep.mu.
	done := false

	ndp.rtrSolicitTimer = timer{
		done: &done,
		timer: ndp.ep.protocol.stack.Clock().AfterFunc(delay, func() {
			// As per RFC 4861 section 4.1:
			//
			//   IP Fields:
			//     Source Address
			//       An IP address assigned to the sending interface, or
			//       the unspecified address if no address is assigned
			//       to the sending interface.
			localAddr := header.IPv6Any
			if addressEndpoint := ndp.ep.AcquireOutgoingPrimaryAddress(header.IPv6AllRoutersLinkLocalMulticastAddress, false); addressEndpoint != nil {
				localAddr = addressEndpoint.AddressWithPrefix().Address
				addressEndpoint.DecRef()
			}

			// As per RFC 4861 section 4.1, an NDP RS SHOULD include the source
			// link-layer address option if the source address of the NDP RS is
			// specified. This option MUST NOT be included if the source address is
			// unspecified.
			//
			// TODO(b/141011931): Validate a LinkEndpoint's link address (provided by
			// LinkEndpoint.LinkAddress) before reaching this point.
			var optsSerializer header.NDPOptionsSerializer
			linkAddress := ndp.ep.nic.LinkAddress()
			if localAddr != header.IPv6Any && header.IsValidUnicastEthernetAddress(linkAddress) {
				optsSerializer = header.NDPOptionsSerializer{
					header.NDPSourceLinkLayerAddressOption(linkAddress),
				}
			}
			payloadSize := header.ICMPv6HeaderSize + header.NDPRSMinimumSize + optsSerializer.Length()
			icmpData := header.ICMPv6(buffer.NewView(payloadSize))
			icmpData.SetType(header.ICMPv6RouterSolicit)
			rs := header.NDPRouterSolicit(icmpData.MessageBody())
			rs.Options().Serialize(optsSerializer)
			icmpData.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header: icmpData,
				Src:    localAddr,
				Dst:    header.IPv6AllRoutersLinkLocalMulticastAddress,
			}))

			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				ReserveHeaderBytes: int(ndp.ep.MaxHeaderLength()),
				Data:               buffer.View(icmpData).ToVectorisedView(),
			})
			defer pkt.DecRef()

			sent := ndp.ep.stats.icmp.packetsSent
			if err := addIPHeader(localAddr, header.IPv6AllRoutersLinkLocalMulticastAddress, pkt, stack.NetworkHeaderParams{
				Protocol: header.ICMPv6ProtocolNumber,
				TTL:      header.NDPHopLimit,
			}, nil /* extensionHeaders */); err != nil {
				panic(fmt.Sprintf("failed to add IP header: %s", err))
			}

			if err := ndp.ep.nic.WritePacketToRemote(header.EthernetAddressFromMulticastIPv6Address(header.IPv6AllRoutersLinkLocalMulticastAddress), pkt); err != nil {
				sent.dropped.Increment()
				// Don't send any more messages if we had an error.
				remaining = 0
			} else {
				sent.routerSolicit.Increment()
				remaining--
			}

			ndp.ep.mu.Lock()
			defer ndp.ep.mu.Unlock()

			if done {
				// Router solicitation was stopped.
				return
			}

			if remaining == 0 {
				// We are done soliciting routers.
				ndp.stopSolicitingRouters()
				return
			}

			ndp.rtrSolicitTimer.timer.Reset(ndp.configs.RtrSolicitationInterval)
		}),
	}
}

// forwardingChanged handles a change in forwarding configuration.
//
// If transitioning to a host, router solicitation will be started. Otherwise,
// router solicitation will be stopped if NDP is not configured to handle RAs
// as a router.
//
// Precondition: ndp.ep.mu must be locked.
func (ndp *ndpState) forwardingChanged(forwarding bool) {
	if forwarding {
		if ndp.configs.HandleRAs.enabled(forwarding) {
			return
		}

		ndp.stopSolicitingRouters()
		return
	}

	// Solicit routers when transitioning to a host.
	//
	// If the endpoint is not currently enabled, routers will be solicited when
	// the endpoint becomes enabled (if it is still a host).
	if ndp.ep.Enabled() {
		ndp.startSolicitingRouters()
	}
}

// stopSolicitingRouters stops soliciting routers. If routers are not currently
// being solicited, this function does nothing.
//
// The IPv6 endpoint that ndp belongs to MUST be locked.
func (ndp *ndpState) stopSolicitingRouters() {
	if ndp.rtrSolicitTimer.timer == nil {
		// Nothing to do.
		return
	}

	ndp.rtrSolicitTimer.timer.Stop()
	*ndp.rtrSolicitTimer.done = true
	ndp.rtrSolicitTimer = timer{}
}

func (ndp *ndpState) init(ep *endpoint, dadOptions ip.DADOptions) {
	if ndp.offLinkRoutes != nil {
		panic("attempted to initialize NDP state twice")
	}

	ndp.ep = ep
	ndp.configs = ep.protocol.options.NDPConfigs
	ndp.dad.Init(&ndp.ep.mu, ep.protocol.options.DADConfigs, dadOptions)
	ndp.offLinkRoutes = make(map[offLinkRoute]offLinkRouteState)
	ndp.onLinkPrefixes = make(map[tcpip.Subnet]onLinkPrefixState)
	ndp.slaacPrefixes = make(map[tcpip.Subnet]slaacPrefixState)

	header.InitialTempIID(ndp.temporaryIIDHistory[:], ndp.ep.protocol.options.TempIIDSeed, ndp.ep.nic.ID())
	ndp.temporaryAddressDesyncFactor = time.Duration(ep.protocol.stack.Rand().Int63n(int64(MaxDesyncFactor)))
}

func (ndp *ndpState) SendDADMessage(addr tcpip.Address, nonce []byte) tcpip.Error {
	snmc := header.SolicitedNodeAddr(addr)
	return ndp.ep.sendNDPNS(header.IPv6Any, snmc, addr, header.EthernetAddressFromMulticastIPv6Address(snmc), header.NDPOptionsSerializer{
		header.NDPNonceOption(nonce),
	})
}

func (e *endpoint) sendNDPNS(srcAddr, dstAddr, targetAddr tcpip.Address, remoteLinkAddr tcpip.LinkAddress, opts header.NDPOptionsSerializer) tcpip.Error {
	icmp := header.ICMPv6(buffer.NewView(header.ICMPv6NeighborSolicitMinimumSize + opts.Length()))
	icmp.SetType(header.ICMPv6NeighborSolicit)
	ns := header.NDPNeighborSolicit(icmp.MessageBody())
	ns.SetTargetAddress(targetAddr)
	ns.Options().Serialize(opts)
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmp,
		Src:    srcAddr,
		Dst:    dstAddr,
	}))

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(e.MaxHeaderLength()),
		Data:               buffer.View(icmp).ToVectorisedView(),
	})
	defer pkt.DecRef()

	if err := addIPHeader(srcAddr, dstAddr, pkt, stack.NetworkHeaderParams{
		Protocol: header.ICMPv6ProtocolNumber,
		TTL:      header.NDPHopLimit,
	}, nil /* extensionHeaders */); err != nil {
		panic(fmt.Sprintf("failed to add IP header: %s", err))
	}

	sent := e.stats.icmp.packetsSent
	err := e.nic.WritePacketToRemote(remoteLinkAddr, pkt)
	if err != nil {
		sent.dropped.Increment()
	} else {
		sent.neighborSolicit.Increment()
	}
	return err
}
