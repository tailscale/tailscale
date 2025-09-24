// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package portlist contains code to poll the local system for open ports
// and report them to the control plane, if enabled on the tailnet.
package portlist

import (
	"context"
	"sync/atomic"

	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/policy"
	"tailscale.com/portlist"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/version"
)

func init() {
	ipnext.RegisterExtension("portlist", newExtension)
}

func newExtension(logf logger.Logf, sb ipnext.SafeBackend) (ipnext.Extension, error) {
	busClient := sb.Sys().Bus.Get().Client("portlist")
	e := &Extension{
		sb:         sb,
		busClient:  busClient,
		logf:       logger.WithPrefix(logf, "portlist: "),
		pub:        eventbus.Publish[ipnlocal.PortlistServices](busClient),
		pollerDone: make(chan struct{}),
		wakePoller: make(chan struct{}),
	}
	e.ctx, e.ctxCancel = context.WithCancel(context.Background())
	return e, nil
}

// Extension implements the portlist extension.
type Extension struct {
	ctx        context.Context
	ctxCancel  context.CancelFunc
	pollerDone chan struct{} // close-only chan when poller goroutine exits
	wakePoller chan struct{} // best effort chan to wake poller from sleep
	busClient  *eventbus.Client
	pub        *eventbus.Publisher[ipnlocal.PortlistServices]
	logf       logger.Logf
	sb         ipnext.SafeBackend
	host       ipnext.Host // from Init

	shieldsUp                  atomic.Bool
	shouldUploadServicesAtomic atomic.Bool
}

func (e *Extension) Name() string { return "portlist" }
func (e *Extension) Shutdown() error {
	e.ctxCancel()
	e.busClient.Close()
	<-e.pollerDone
	return nil
}

func (e *Extension) Init(h ipnext.Host) error {
	if !envknob.BoolDefaultTrue("TS_PORTLIST") {
		return ipnext.SkipExtension
	}

	e.host = h
	h.Hooks().ShouldUploadServices.Set(e.shouldUploadServicesAtomic.Load)
	h.Hooks().ProfileStateChange.Add(e.onChangeProfile)
	h.Hooks().OnSelfChange.Add(e.onSelfChange)

	// TODO(nickkhyl): remove this after the profileManager refactoring.
	// See tailscale/tailscale#15974.
	// This same workaround appears in feature/taildrop/ext.go.
	profile, prefs := h.Profiles().CurrentProfileState()
	e.onChangeProfile(profile, prefs, false)

	go e.runPollLoop()
	return nil
}

func (e *Extension) onSelfChange(tailcfg.NodeView) {
	e.updateShouldUploadServices()
}

func (e *Extension) onChangeProfile(_ ipn.LoginProfileView, prefs ipn.PrefsView, sameNode bool) {
	e.shieldsUp.Store(prefs.ShieldsUp())
	e.updateShouldUploadServices()
}

func (e *Extension) updateShouldUploadServices() {
	v := !e.shieldsUp.Load() && e.host.NodeBackend().CollectServices()
	if e.shouldUploadServicesAtomic.CompareAndSwap(!v, v) && v {
		// Upon transition from false to true (enabling service reporting), try
		// to wake the poller to do an immediate poll if it's sleeping.
		// It's not a big deal if we miss waking it. It'll get to it soon enough.
		select {
		case e.wakePoller <- struct{}{}:
		default:
		}
	}
}

// runPollLoop is a goroutine that periodically checks the open
// ports and publishes them if they've changed.
func (e *Extension) runPollLoop() {
	defer close(e.pollerDone)

	var poller portlist.Poller

	ticker, tickerChannel := e.sb.Clock().NewTicker(portlist.PollInterval())
	defer ticker.Stop()
	for {
		select {
		case <-tickerChannel:
		case <-e.wakePoller:
		case <-e.ctx.Done():
			return
		}

		if !e.shouldUploadServicesAtomic.Load() {
			continue
		}

		ports, changed, err := poller.Poll()
		if err != nil {
			e.logf("Poll: %v", err)
			// TODO: this is kinda weird that we just return here and never try
			// again. Maybe that was because all errors are assumed to be
			// permission errors and thus permanent? Audit varioys OS
			// implementation and check error types, and then make this check
			// for permanent vs temporary errors and keep looping with a backoff
			// for temporary errors? But for now we just give up, like we always
			// have.
			return
		}
		if !changed {
			continue
		}
		sl := []tailcfg.Service{}
		for _, p := range ports {
			s := tailcfg.Service{
				Proto:       tailcfg.ServiceProto(p.Proto),
				Port:        p.Port,
				Description: p.Process,
			}
			if policy.IsInterestingService(s, version.OS()) {
				sl = append(sl, s)
			}
		}
		e.pub.Publish(ipnlocal.PortlistServices(sl))
	}
}
