// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package router

import (
	"go4.org/netipx"
	"tailscale.com/types/logger"
)

// ConsolidatingRoutes wraps a Router with logic that consolidates Routes
// whenever Set is called. It attempts to consolidate cfg.Routes into the
// smallest possible set.
func ConsolidatingRoutes(logf logger.Logf, router Router) Router {
	return &consolidatingRouter{Router: router, logf: logger.WithPrefix(logf, "router: ")}
}

type consolidatingRouter struct {
	Router
	logf logger.Logf
}

// Set implements Router and attempts to consolidate cfg.Routes into the
// smallest possible set.
func (cr *consolidatingRouter) Set(cfg *Config) error {
	return cr.Router.Set(cr.consolidateRoutes(cfg))
}

func (cr *consolidatingRouter) consolidateRoutes(cfg *Config) *Config {
	if cfg == nil {
		return nil
	}
	if len(cfg.Routes) < 2 {
		return cfg
	}
	if len(cfg.Routes) == 2 && cfg.Routes[0].Addr().Is4() != cfg.Routes[1].Addr().Is4() {
		return cfg
	}
	var builder netipx.IPSetBuilder
	for _, route := range cfg.Routes {
		builder.AddPrefix(route)
	}
	set, err := builder.IPSet()
	if err != nil {
		cr.logf("consolidateRoutes failed, keeping existing routes: %s", err)
		return cfg
	}
	newRoutes := set.Prefixes()
	oldLength := len(cfg.Routes)
	newLength := len(newRoutes)
	if oldLength == newLength {
		// Nothing consolidated, return as-is.
		return cfg
	}
	cr.logf("consolidated %d routes down to %d", oldLength, newLength)
	newCfg := *cfg
	newCfg.Routes = newRoutes
	return &newCfg
}
