// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/taildrop"
	"tailscale.com/types/logger"
)

func init() {
	ipnext.RegisterExtension("taildrop", newExtension)
}

func newExtension(logf logger.Logf, b ipnext.SafeBackend) (ipnext.Extension, error) {
	return &extension{
		logf: logger.WithPrefix(logf, "taildrop: "),
	}, nil
}

type extension struct {
	logf logger.Logf
	sb   ipnext.SafeBackend
	mgr  *taildrop.Manager
}

func (e *extension) Name() string {
	return "taildrop"
}

func (e *extension) Init(h ipnext.Host) error {
	// TODO(bradfitz): move init of taildrop.Manager from ipnlocal/peerapi.go to
	// here
	e.mgr = nil

	return nil
}

func (e *extension) Shutdown() error {
	lb, ok := e.sb.(*ipnlocal.LocalBackend)
	if !ok {
		return nil
	}
	if mgr, err := lb.TaildropManager(); err == nil {
		mgr.Shutdown()
	} else {
		e.logf("taildrop: failed to shutdown taildrop manager: %v", err)
	}
	return nil
}
