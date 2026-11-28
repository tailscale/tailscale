// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package portlist contains code to poll the local system for open ports
// and report them to the control plane, if enabled on the tailnet.
package portlist

import (
	"context"
	"sync/atomic"

	"tailscale.com/envknob"
	"tailscale.com/feature"
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
	if !feature.Register("portlist") {
		return
	}
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

	// collectServicesFn reports whether the active node backend's tailnet has
	// service collection enabled. It is set in Init, and is a field so tests
	// can drive the handlers without an [ipnext.Host].
	collectServicesFn func() bool

	// shieldsUp is the last value seen from prefs, which the hook delivers
	// synchronously as the prefs change is applied.
	shieldsUp atomic.Bool

	// wokeFor is the decision this extension last woke the poller for. It is
	// deliberately not authoritative — shouldUploadServices never consults it —
	// so if it is wrong the cost is a missed or spurious wake, recovered by the
	// next tick.
	wokeFor atomic.Bool
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

	e.collectServicesFn = func() bool { return h.NodeBackend().CollectServices() }
	h.Hooks().ShouldUploadServices.Set(e.shouldUploadServices)
	h.Hooks().ProfileStateChange.Add(e.onChangeProfile)
	h.Hooks().OnSelfChange.Add(e.onSelfChange)

	// Subscribe after the skip check above, so an extension that skipped leaves
	// no subscriber behind: [ipnext.ExtensionHost] only shuts down the
	// extensions it activated.
	eventbus.SubscribeFunc(e.busClient, e.onCollectServices)

	// TODO(nickkhyl): remove this after the profileManager refactoring.
	// See tailscale/tailscale#15974.
	// This same workaround appears in feature/taildrop/ext.go.
	profile, prefs := h.Profiles().CurrentProfileState()
	e.onChangeProfile(profile, prefs, false)

	go e.runPollLoop()
	return nil
}

func (e *Extension) onSelfChange(tailcfg.NodeView) {
	e.wakePollerIfNowUploading()
}

func (e *Extension) onChangeProfile(_ ipn.LoginProfileView, prefs ipn.PrefsView, sameNode bool) {
	e.shieldsUp.Store(prefs.ShieldsUp())
	e.wakePollerIfNowUploading()
}

// onCollectServices handles an [ipnlocal.CollectServicesChanged] event by
// waking the poller, so a netmap change is noticed without waiting for the
// next tick.
func (e *Extension) onCollectServices(ipnlocal.CollectServicesChanged) {
	e.wakePollerIfNowUploading()
}

// shouldUploadServices reports whether this node's open ports may be reported
// to the control plane, reading both inputs at the point of use.
//
// Nothing derived from the netmap is stored: a stored copy can be written by
// two goroutines at once, outlive the profile whose netmap set it, or go stale
// while a tick reports ports the tailnet has stopped asking for.
//
// Safe to call from the [ipnext.Hooks] ShouldUploadServices hook, which runs
// with [ipnlocal.LocalBackend]'s lock held: resolving the node backend reads an
// atomic rather than taking that lock.
func (e *Extension) shouldUploadServices() bool {
	return !e.shieldsUp.Load() && e.collectServicesFn()
}

// wakePollerIfNowUploading wakes the poller if uploading just became allowed,
// so reporting starts now rather than at the next tick. It wakes only on a
// transition: a collecting node sees an event for every netmap, and waking each
// time would run a full port scan each time.
func (e *Extension) wakePollerIfNowUploading() {
	v := e.shouldUploadServices()
	if e.wokeFor.CompareAndSwap(!v, v) && v {
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
	defer poller.Close()

	ticker, tickerChannel := e.sb.Clock().NewTicker(portlist.PollInterval())
	defer ticker.Stop()
	for {
		select {
		case <-tickerChannel:
		case <-e.wakePoller:
		case <-e.ctx.Done():
			return
		}

		// Before we do potentially expensive work below (polling what might be
		// a ton of ports), double check that we actually need to do it.
		if !e.shouldUploadServices() {
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
