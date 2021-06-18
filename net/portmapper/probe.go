// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portmapper

import (
	"context"
	"time"

	"tailscale.com/syncs"
)

// Prober periodically pings the network and checks for port-mapping services.
type Prober struct {
	// stop will stop the prober
	stop func()

	// Each of the SubResults below is intended to expose whether a specific service is available
	// for use on a client, and the most recent seen time. Should not be modified externally, and
	// will be periodically updated.

	// PMP stores the result of probing pmp services and is populated by the prober.
	PMP syncs.WaitableResult
	// PCP stores the result of probing pcp services and is populated by the prober.
	PCP syncs.WaitableResult
	// UPnP stores the result of probing pcp services and is populated by the prober.
	UPnP syncs.WaitableResult
}

// initProberLocked will start a prober if it does not exist on the given portmapping client.
// The prober will run until the context terminates or stop is called, probing whether services
// are available periodically. c.mu must be held.
func (c *Client) initProberLocked(ctx context.Context) {
	stop := make(chan struct{})
	p := &Prober{
		PMP:  syncs.NewWaitableResult(),
		PCP:  syncs.NewWaitableResult(),
		UPnP: syncs.NewWaitableResult(),
		stop: func() { close(stop) },
	}
	c.prober = p
	go func() {
		for {
			res, err := c.oldProbe(ctx)
			p.PMP.Set(res.PMP, err)
			p.PCP.Set(res.PCP, err)
			p.UPnP.Set(res.UPnP, err)

			select {
			case <-time.After(trustServiceStillAvailableDuration * 3 / 4):
			case <-ctx.Done():
				return
			case <-stop:
				return
			}
		}
	}()
}

// Close gracefully turns the Prober off, completing the current probes before exiting.
//
// Calling stop Close multiple times will have no additional effects.
func (p *Prober) Close() { p.stop() }

// Current returns the current results of the prober, regardless of whether they have completed
// or not. The returned probe result returns whether any of the services have been known to be
// detected and if a value is true it will be available. If any of the services recently
// returned an error due to inability to reach it, some failure of protocol, it will also be
// returned, but if one of the probe results returned true it can still be used. Notably, it is
// not an error to not yet have completed, or for a limited number of services to be available.
func (p *Prober) Current() (ProbeResult, error) {
	var res ProbeResult
	_, hasPMP, errPMP := p.PMP.Peek()
	res.PMP = hasPMP
	err := errPMP

	_, hasUPnP, errUPnP := p.UPnP.Peek()
	res.UPnP = hasUPnP
	if err == nil {
		err = errUPnP
	}

	_, hasPCP, errPCP := p.PCP.Peek()
	res.PCP = hasPCP
	if err == nil {
		err = errPCP
	}
	return res, err
}

// Complete blocks the caller until probing all services has completed, regardless of success
// or failure. It returns the result of probing each of UPnP, PMP, and PCP, and if there is an
// error on any service, it will be returned. If any result is true, that service completed without
// error and can be used.
func (p *Prober) Complete() (ProbeResult, error) {
	var res ProbeResult
	hasPMP, errPMP := p.PMP.Get()
	res.PMP = hasPMP
	err := errPMP

	hasUPnP, errUPnP := p.UPnP.Get()
	res.UPnP = hasUPnP
	if err == nil {
		err = errUPnP
	}

	hasPCP, errPCP := p.PCP.Get()
	res.PCP = hasPCP
	if err == nil {
		err = errPCP
	}
	return res, err
}
