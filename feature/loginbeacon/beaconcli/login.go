// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package beaconcli

import (
	"context"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/feature/loginbeacon/api"
)

// LoginAttempt ties one bounded broadcast to a CLI login's notification pump.
// The pump calls Start when a login URL becomes available and PumpDone on exit.
// Its owner calls Stop on completion or cancellation.
type LoginAttempt struct {
	client     *local.Client
	id         string
	config     api.Broadcast
	cancelPump context.CancelFunc
	pumpDone   chan struct{}
}

// NewLoginAttempt reserves a fresh attempt. It does not begin advertising.
func NewLoginAttempt(client *local.Client, hostname string, cancelPump context.CancelFunc) *LoginAttempt {
	return &LoginAttempt{
		client: client, id: api.NewID(),
		config:     api.Broadcast{Hostname: hostname, Expires: time.Now().Add(api.MaxBroadcastDuration)},
		cancelPump: cancelPump, pumpDone: make(chan struct{}),
	}
}

// Start advertises this attempt. Repeated calls use the same ID and expiry.
// Only the notification pump calls Start.
func (a *LoginAttempt) Start(ctx context.Context) error {
	return a.client.StartLoginBeacon(ctx, a.id, a.config)
}

// PumpDone releases Stop after the notification pump can no longer call Start.
// The pump must call this exactly once, including when it never calls Start.
func (a *LoginAttempt) PumpDone() { close(a.pumpDone) }

// Stop cancels and drains the pump before stopping the daemon attempt, so a
// delayed Start cannot re-arm it. Cleanup has its own bounded context because
// the login context may already be canceled.
func (a *LoginAttempt) Stop() error {
	a.cancelPump()
	<-a.pumpDone
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return a.client.StopLoginBeacon(ctx, a.id)
}
