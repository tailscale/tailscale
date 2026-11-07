// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || ts_omit_tswg

package wgengine

import (
	"errors"
	"sync/atomic"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/wgcfg"
)

// kernelDataplane is the tswg kernel data plane, which only exists on
// Linux, and only without the ts_omit_tswg build tag.
type kernelDataplane struct{}

func newKernelDataplane(logger.Logf, string, *atomic.Pointer[func(key.NodePublic) (wgcfg.PeerConfig, bool)]) *kernelDataplane {
	return &kernelDataplane{}
}

func (*kernelDataplane) start(*magicsock.Conn) error {
	return errors.New("tswg kernel data plane not supported on this platform or build")
}

func (*kernelDataplane) Close() error                               { return nil }
func (*kernelDataplane) setPrivateKey(key.NodePrivate)              {}
func (*kernelDataplane) kickReconcile()                             {}
func (*kernelDataplane) injectFromMagicsock(key.NodePublic, []byte) {}
func (*kernelDataplane) peerStatuses() []ipnstate.PeerStatusLite    { return nil }
