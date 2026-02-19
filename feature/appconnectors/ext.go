// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appconnectors

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"sync"

	"tailscale.com/appc"
	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/tailcfg"
	"tailscale.com/types/appctype"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/execqueue"
)

// featureName is the name of the feature implemented by this package.
// It is also the [extension] name and the log prefix.
const featureName = "appconnectors"

func init() {
	feature.Register(featureName)
	ipnext.RegisterExtension(featureName, newExtension)
}

type extension struct {
	logf logger.Logf
	sb   ipnext.SafeBackend
	host ipnext.Host

	mu           sync.Mutex
	appConnector *appc.AppConnector // or nil; guarded by mu

	busClient *eventbus.Client
	task      execqueue.ExecQueue // serializes route update processing
}

func newExtension(logf logger.Logf, sb ipnext.SafeBackend) (ipnext.Extension, error) {
	return &extension{
		logf: logger.WithPrefix(logf, "appconnectors: "),
		sb:   sb,
	}, nil
}

func (e *extension) Name() string { return featureName }

func (e *extension) Init(h ipnext.Host) error {
	e.host = h
	h.Hooks().OnAuthReconfig.Add(e.onAuthReconfig)
	h.Hooks().OfferingAppConnector.Set(e.offeringAppConnector)
	h.Hooks().ObserveDNSResponse.Add(e.observeDNSResponse)
	h.Hooks().ExtraLocalAddrs.Add(e.extraLocalAddrs)
	h.Hooks().ClearAutoRoutes.Set(e.clearRoutes)

	bus := e.sb.Sys().Bus.Get()
	e.busClient = bus.Client("appconnectors")
	eventbus.SubscribeFunc(e.busClient, e.onRouteUpdate)
	eventbus.SubscribeFunc(e.busClient, e.onStoreRoutes)
	return nil
}

// Wait waits for the app connector's internal queue to finish processing.
// It is used in tests to synchronize with asynchronous operations.
func (e *extension) Wait(ctx context.Context) {
	e.mu.Lock()
	ac := e.appConnector
	e.mu.Unlock()
	if ac != nil {
		ac.Wait(ctx)
	}
}

func (e *extension) Shutdown() error {
	e.task.Shutdown()
	if e.busClient != nil {
		e.busClient.Close()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.appConnector.Close() // safe on nil
	e.appConnector = nil
	return nil
}

// onAuthReconfig is called asynchronously after the backend reconfigures
// in response to a netmap or prefs change. It manages the lifecycle of
// the AppConnector: creating, reconfiguring, or destroying it.
func (e *extension) onAuthReconfig(selfNode tailcfg.NodeView, prefs ipn.PrefsView) {
	const appConnectorCapName = "tailscale.com/app-connectors"

	e.mu.Lock()
	defer e.mu.Unlock()

	// App connectors have been disabled.
	if !prefs.AppConnector().Advertise {
		e.appConnector.Close() // clean up a previous connector (safe on nil)
		e.appConnector = nil
		return
	}

	// We don't (yet) have an app connector configured, or the configured
	// connector has a different route persistence setting.
	shouldStoreRoutes := e.sb.Sys().ControlKnobs().AppCStoreRoutes.Load()
	if e.appConnector == nil || (shouldStoreRoutes != e.appConnector.ShouldStoreRoutes()) {
		ri, err := e.readRouteInfo()
		if err != nil && err != ipn.ErrStateNotExist {
			e.logf("Unsuccessful Read RouteInfo: %v", err)
		}
		e.appConnector.Close() // clean up a previous connector (safe on nil)
		e.appConnector = appc.NewAppConnector(appc.Config{
			Logf:            e.logf,
			EventBus:        e.sb.Sys().Bus.Get(),
			RouteInfo:       ri,
			HasStoredRoutes: shouldStoreRoutes,
		})
	}
	if !selfNode.Valid() {
		return
	}

	attrs, err := tailcfg.UnmarshalNodeCapViewJSON[appctype.AppConnectorAttr](selfNode.CapMap(), appConnectorCapName)
	if err != nil {
		e.logf("[unexpected] error parsing app connector mapcap: %v", err)
		return
	}

	// Geometric cost, assumes that the number of advertised tags is small
	selfHasTag := func(attrTags []string) bool {
		return selfNode.Tags().ContainsFunc(func(tag string) bool {
			return slices.Contains(attrTags, tag)
		})
	}

	var (
		domains []string
		routes  []netip.Prefix
	)
	for _, attr := range attrs {
		if slices.Contains(attr.Connectors, "*") || selfHasTag(attr.Connectors) {
			domains = append(domains, attr.Domains...)
			routes = append(routes, attr.Routes...)
		}
	}
	slices.Sort(domains)
	slices.SortFunc(routes, func(i, j netip.Prefix) int { return i.Addr().Compare(j.Addr()) })
	domains = slices.Compact(domains)
	routes = slices.Compact(routes)
	e.appConnector.UpdateDomainsAndRoutes(domains, routes)

	// Re-advertise the stored routes, in case stored state got out of
	// sync with previously advertised routes in prefs.
	e.readvertiseRoutesLocked()
}

// readvertiseRoutesLocked re-advertises routes from the app connector's
// DomainRoutes. e.mu must be held.
func (e *extension) readvertiseRoutesLocked() {
	if e.appConnector == nil {
		return
	}
	domainRoutes := e.appConnector.DomainRoutes()
	if domainRoutes == nil {
		return
	}
	var prefixes []netip.Prefix
	for _, ips := range domainRoutes {
		for _, ip := range ips {
			prefixes = append(prefixes, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	if len(prefixes) > 0 {
		e.host.AdvertiseRoutesAsync(prefixes)
	}
}

// onRouteUpdate handles route update events from the AppConnector.
func (e *extension) onRouteUpdate(ru appctype.RouteUpdate) {
	e.task.Add(func() {
		e.host.AdvertiseRoutesAsync(ru.Advertise)
		e.host.UnadvertiseRoutesAsync(ru.Unadvertise)
	})
}

// onStoreRoutes handles route store events from the AppConnector.
func (e *extension) onStoreRoutes(ri appctype.RouteInfo) {
	shouldStoreRoutes := e.sb.Sys().ControlKnobs().AppCStoreRoutes.Load()
	if shouldStoreRoutes {
		if err := e.storeRouteInfo(ri); err != nil {
			e.logf("failed to store route info: %v", err)
		}
	}
}

// observeDNSResponse passes a DNS response payload to the AppConnector.
func (e *extension) observeDNSResponse(res []byte) {
	e.mu.Lock()
	ac := e.appConnector
	e.mu.Unlock()
	if ac == nil {
		return
	}
	if err := ac.ObserveDNSResponse(res); err != nil {
		e.logf("ObserveDNSResponse error: %v", err)
	}
}

// offeringAppConnector reports whether the AppConnector is active.
func (e *extension) offeringAppConnector() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.appConnector != nil
}

// extraLocalAddrs returns additional addresses for the packet filter's
// local network set when the app connector is active.
func (e *extension) extraLocalAddrs() []netip.Addr {
	e.mu.Lock()
	isActive := e.appConnector != nil
	e.mu.Unlock()
	if !isActive {
		return nil
	}
	prefs := e.host.Profiles().CurrentPrefs()
	if !prefs.AppConnector().Advertise {
		return nil
	}
	return []netip.Addr{
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("::0"),
	}
}

// clearRoutes clears auto-discovered routes from the AppConnector.
func (e *extension) clearRoutes() error {
	e.mu.Lock()
	ac := e.appConnector
	e.mu.Unlock()
	if ac != nil {
		return ac.ClearRoutes()
	}
	return nil
}

const routeInfoStateStoreKey ipn.StateKey = "_routeInfo"

// readRouteInfo reads the stored route info from the state store.
func (e *extension) readRouteInfo() (*appctype.RouteInfo, error) {
	profile, _ := e.host.Profiles().CurrentProfileState()
	if profile.ID() == "" {
		return &appctype.RouteInfo{}, nil
	}
	key := profile.Key() + "||" + routeInfoStateStoreKey
	bs, err := e.sb.Sys().StateStore.Get().ReadState(key)
	if err != nil {
		return nil, err
	}
	ri := &appctype.RouteInfo{}
	if err := json.Unmarshal(bs, ri); err != nil {
		return nil, err
	}
	return ri, nil
}

// storeRouteInfo writes route info to the state store.
func (e *extension) storeRouteInfo(ri appctype.RouteInfo) error {
	profile, _ := e.host.Profiles().CurrentProfileState()
	if profile.ID() == "" {
		return nil
	}
	key := profile.Key() + "||" + routeInfoStateStoreKey
	bs, err := json.Marshal(ri)
	if err != nil {
		return err
	}
	return e.sb.Sys().StateStore.Get().WriteState(key, bs)
}
