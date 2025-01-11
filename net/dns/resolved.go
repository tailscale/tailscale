// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package dns

import (
	"context"
	"errors"
	"strings"

	"tailscale.com/health"
	"tailscale.com/types/logger"
)

// DBus entities we talk to.
//
// DBus is an RPC bus. In particular, the bus we're talking to is the
// system-wide bus (there is also a per-user session bus for
// user-specific applications).
//
// Daemons connect to the bus, and advertise themselves under a
// well-known object name. That object exposes paths, and each path
// implements one or more interfaces that contain methods, properties,
// and signals.
//
// Clients connect to the bus and walk that same hierarchy to invoke
// RPCs, get/set properties, or listen for signals.
const (
	dbusResolvedObject    = "org.freedesktop.resolve1"
	dbusResolvedPath      = "/org/freedesktop/resolve1"
	dbusResolvedInterface = "org.freedesktop.resolve1.Manager"
	dbusPath              = "/org/freedesktop/DBus"
	dbusInterface         = "org.freedesktop.DBus"
	dbusOwnerSignal       = "NameOwnerChanged" // broadcast when a well-known name's owning process changes.
)

type resolvedLinkNameserver struct {
	Family  int32
	Address []byte
}

type resolvedLinkDomain struct {
	Domain      string
	RoutingOnly bool
}

// changeRequest tracks latest OSConfig and related error responses to update.
type changeRequest struct {
	config OSConfig     // configs OSConfigs, one per each SetDNS call
	res    chan<- error // response channel
}

// resolvedManager is an OSConfigurator which uses the systemd-resolved DBus API.
type resolvedManager struct {
	ctx    context.Context
	cancel func() // terminate the context, for close

	logf   logger.Logf
	health *health.Tracker
	ifidx  int

	configCR chan changeRequest // tracks OSConfigs changes and error responses
}

func newResolvedManager(logf logger.Logf, health *health.Tracker, interfaceName string) (*resolvedManager, error) {
	return nil, errors.New("lanscaping")
}

func (m *resolvedManager) SetDNS(config OSConfig) error {
	return errors.New("lanscaping")
}

func (m *resolvedManager) SupportsSplitDNS() bool {
	return true
}

func (m *resolvedManager) GetBaseConfig() (OSConfig, error) {
	return OSConfig{}, ErrGetBaseConfigNotSupported
}

func (m *resolvedManager) Close() error {
	m.cancel() // stops the 'run' method goroutine
	return nil
}

// linkDomainsWithoutReverseDNS returns a copy of v without
// *.arpa. entries.
func linkDomainsWithoutReverseDNS(v []resolvedLinkDomain) (ret []resolvedLinkDomain) {
	for _, d := range v {
		if strings.HasSuffix(d.Domain, ".arpa.") {
			// Oh well. At least the rest will work.
			continue
		}
		ret = append(ret, d)
	}
	return ret
}
