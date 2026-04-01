// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_routecheck

// Package routecheck registers support for RouteCheck,
// which checks the reachability of overlapping routers.
package routecheck

import (
	"fmt"

	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/routecheck"
	"tailscale.com/types/logger"
)

// FeatureName is the name of the feature implemented by this package.
// It is also the [extension] name and the log prefix.
const featureName = "routecheck"

func init() {
	ipnext.RegisterExtension(featureName, func(logf logger.Logf, b ipnext.SafeBackend) (ipnext.Extension, error) {
		return &Extension{
			logf:    logger.WithPrefix(logf, featureName+": "),
			backend: b,
		}, nil
	})
}

// Extension implements the [ipnext.Extension] interface.
type Extension struct {
	Client *routecheck.Client

	logf    logger.Logf
	backend ipnext.SafeBackend
	nb      nodeBackender
}

var _ ipnext.Extension = new(Extension)

// Name implements the [ipnext.Extension.Name] interface method.
func (e *Extension) Name() string {
	return featureName
}

// Init implements the [ipnext.Extension.Init] interface method.
func (e *Extension) Init(h ipnext.Host) error {
	e.nb = nodeBackender{h}

	pinger := e.backend.Sys().Engine.Get()
	nm, ok := e.backend.(routecheck.NetMapWaiter)
	if !ok {
		return fmt.Errorf("backend %T does not implement routecheck.NetMapWaiter", e.backend)
	}

	c, err := routecheck.NewClient(e.logf, e.nb, nm, pinger)
	if err != nil {
		return err
	}
	e.Client = c

	return nil
}

// Shutdown implements the [ipnext.Extension.Shutdown] interface method.
func (e *Extension) Shutdown() error {
	return nil
}
