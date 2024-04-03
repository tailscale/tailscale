// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tsd (short for "Tailscale Daemon") contains a System type that
// containing all the subsystems a Tailscale node (tailscaled or platform
// equivalent) uses.
//
// The goal of this package (as of 2023-05-03) is to eventually unify
// initialization across tailscaled, tailscaled as a Windows services, the mac
// GUI, tsnet, wasm, tests, and other places that wire up all the subsystems.
// And doing so without weird optional interface accessors on some subsystems
// that return other subsystems. It's all a work in progress.
//
// This package depends on nearly all parts of Tailscale, so it should not be
// imported by (or thus passed to) any package that does not want to depend on
// the world. In practice this means that only things like cmd/tailscaled,
// ipn/ipnlocal, and ipn/ipnserver should import this package.
package tsd

import (
	"fmt"
	"reflect"

	"tailscale.com/control/controlknobs"
	"tailscale.com/drive"
	"tailscale.com/ipn"
	"tailscale.com/ipn/conffile"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/proxymap"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/router"
)

// System contains all the subsystems of a Tailscale node (tailscaled, etc.)
type System struct {
	Dialer         SubSystem[*tsdial.Dialer]
	DNSManager     SubSystem[*dns.Manager] // can get its *resolver.Resolver from DNSManager.Resolver
	Engine         SubSystem[wgengine.Engine]
	NetMon         SubSystem[*netmon.Monitor]
	MagicSock      SubSystem[*magicsock.Conn]
	NetstackRouter SubSystem[bool] // using Netstack at all (either entirely or at least for subnets)
	Router         SubSystem[router.Router]
	Tun            SubSystem[*tstun.Wrapper]
	StateStore     SubSystem[ipn.StateStore]
	Netstack       SubSystem[NetstackImpl] // actually a *netstack.Impl
	DriveForLocal  SubSystem[drive.FileSystemForLocal]
	DriveForRemote SubSystem[drive.FileSystemForRemote]

	// InitialConfig is initial server config, if any.
	// It is nil if the node is not in declarative mode.
	// This value is never updated after startup.
	// LocalBackend tracks the current config after any reloads.
	InitialConfig *conffile.Config

	// onlyNetstack is whether the Tun value is a fake TUN device
	// and we're using netstack for everything.
	onlyNetstack bool

	controlKnobs controlknobs.Knobs
	proxyMap     proxymap.Mapper
}

// NetstackImpl is the interface that *netstack.Impl implements.
// It's an interface for circular dependency reasons: netstack.Impl
// references LocalBackend, and LocalBackend has a tsd.System.
type NetstackImpl interface {
	UpdateNetstackIPs(*netmap.NetworkMap)
}

// Set is a convenience method to set a subsystem value.
// It panics if the type is unknown or has that type
// has already been set.
func (s *System) Set(v any) {
	switch v := v.(type) {
	case *netmon.Monitor:
		s.NetMon.Set(v)
	case *dns.Manager:
		s.DNSManager.Set(v)
	case *tsdial.Dialer:
		s.Dialer.Set(v)
	case wgengine.Engine:
		s.Engine.Set(v)
	case router.Router:
		s.Router.Set(v)
	case *tstun.Wrapper:
		type ft interface {
			IsFakeTun() bool
		}
		if _, ok := v.Unwrap().(ft); ok {
			s.onlyNetstack = true
		}
		s.Tun.Set(v)
	case *magicsock.Conn:
		s.MagicSock.Set(v)
	case ipn.StateStore:
		s.StateStore.Set(v)
	case NetstackImpl:
		s.Netstack.Set(v)
	case drive.FileSystemForLocal:
		s.DriveForLocal.Set(v)
	case drive.FileSystemForRemote:
		s.DriveForRemote.Set(v)
	default:
		panic(fmt.Sprintf("unknown type %T", v))
	}
}

// IsNetstackRouter reports whether Tailscale is either fully netstack based
// (without TUN) or is at least using netstack for routing.
func (s *System) IsNetstackRouter() bool {
	if v, ok := s.NetstackRouter.GetOK(); ok && v {
		return true
	}
	return s.IsNetstack()
}

// IsNetstack reports whether Tailscale is running as a netstack-based TUN-free engine.
func (s *System) IsNetstack() bool {
	return s.onlyNetstack
}

// ControlKnobs returns the control knobs for this node.
func (s *System) ControlKnobs() *controlknobs.Knobs {
	return &s.controlKnobs
}

// ProxyMapper returns the ephemeral ip:port mapper.
func (s *System) ProxyMapper() *proxymap.Mapper {
	return &s.proxyMap
}

// SubSystem represents some subsystem of the Tailscale node daemon.
//
// A subsystem can be set to a value, and then later retrieved. A subsystem
// value tracks whether it's been set and, once set, doesn't allow the value to
// change.
type SubSystem[T any] struct {
	set bool
	v   T
}

// Set sets p to v.
//
// It panics if p is already set to a different value.
//
// Set must not be called concurrently with other Sets or Gets.
func (p *SubSystem[T]) Set(v T) {
	if p.set {
		var oldVal any = p.v
		var newVal any = v
		if oldVal == newVal {
			// Allow setting to the same value.
			// Note we had to box them through "any" to force them to be comparable.
			// We can't set the type constraint T to be "comparable" because the interfaces
			// aren't comparable. (See https://github.com/golang/go/issues/52531 and
			// https://github.com/golang/go/issues/52614 for some background)
			return
		}

		var z *T
		panic(fmt.Sprintf("%v is already set", reflect.TypeOf(z).Elem().String()))
	}
	p.v = v
	p.set = true
}

// Get returns the value of p, panicking if it hasn't been set.
func (p *SubSystem[T]) Get() T {
	if !p.set {
		var z *T
		panic(fmt.Sprintf("%v is not set", reflect.TypeOf(z).Elem().String()))
	}
	return p.v
}

// GetOK returns the value of p (if any) and whether it's been set.
func (p *SubSystem[T]) GetOK() (_ T, ok bool) {
	return p.v, p.set
}
