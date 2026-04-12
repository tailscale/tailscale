// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"net/netip"
	"strings"

	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/syspolicy/policyclient"
)

// androidManager implements OSConfigurator for Android. Unlike noopManager,
// it can return the system's current DNS servers via GetBaseConfig by reading
// the values cached by the Android JNI layer via netmon.UpdateLastKnownDNSServers.
type androidManager struct{}

func (m androidManager) SetDNS(OSConfig) error  { return nil }
func (m androidManager) SupportsSplitDNS() bool { return false }
func (m androidManager) Close() error           { return nil }
func (m androidManager) GetBaseConfig() (OSConfig, error) {
	serversStr := netmon.LastKnownDNSServers()
	if serversStr == "" {
		return OSConfig{}, ErrGetBaseConfigNotSupported
	}
	var nameservers []netip.Addr
	for _, s := range strings.Split(serversStr, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ip, err := netip.ParseAddr(s); err == nil {
			nameservers = append(nameservers, ip)
		}
	}
	if len(nameservers) == 0 {
		return OSConfig{}, ErrGetBaseConfigNotSupported
	}
	return OSConfig{Nameservers: nameservers}, nil
}

// NewOSConfigurator creates a new OS configurator for Android.
//
// The health tracker and the knobs may be nil and are ignored on this platform.
func NewOSConfigurator(logger.Logf, *health.Tracker, *eventbus.Bus, policyclient.Client, *controlknobs.Knobs, string) (OSConfigurator, error) {
	return androidManager{}, nil
}
