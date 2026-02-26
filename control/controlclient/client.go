// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package controlclient implements the client for the Tailscale
// control plane.
//
// It handles authentication, port picking, and collects the local
// network configuration.
package controlclient

import (
	"context"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// LoginFlags is a bitmask of options to change the behavior of Client.Login
// and LocalBackend.
type LoginFlags int

const (
	LoginDefault     = LoginFlags(0)
	LoginInteractive = LoginFlags(1 << iota) // force user login and key refresh
	LoginEphemeral                           // set RegisterRequest.Ephemeral

	// LocalBackendStartKeyOSNeutral instructs NewLocalBackend to start the
	// LocalBackend without any OS-dependent StateStore StartKey behavior.
	//
	// See https://github.com/tailscale/tailscale/issues/6973.
	LocalBackendStartKeyOSNeutral
)

// Client represents a client connection to the control server.
// Currently this is done through a pair of polling https requests in
// the Auto client, but that might change eventually.
//
// The Client must be comparable as it is used by the Observer to detect stale
// clients.
type Client interface {
	// Shutdown closes this session, which should not be used any further
	// afterwards.
	Shutdown()
	// Login begins an interactive or non-interactive login process.
	// Client will eventually call the Status callback with either a
	// LoginFinished flag (on success) or an auth URL (if further
	// interaction is needed). It merely sets the process in motion,
	// and doesn't wait for it to complete.
	Login(LoginFlags)
	// Logout starts a synchronous logout process. It doesn't return
	// until the logout operation has been completed.
	Logout(context.Context) error
	// SetPaused pauses or unpauses the controlclient activity as much
	// as possible, without losing its internal state, to minimize
	// unnecessary network activity.
	// TODO: It might be better to simply shutdown the controlclient and
	// make a new one when it's time to unpause.
	SetPaused(bool)
	// AuthCantContinue returns whether authentication is blocked. If it
	// is, you either need to visit the auth URL (previously sent in a
	// Status callback) or call the Login function appropriately.
	// TODO: this probably belongs in the Status itself instead.
	AuthCantContinue() bool
	// SetHostinfo changes the Hostinfo structure that will be sent in
	// subsequent node registration requests.
	// TODO: a server-side change would let us simply upload this
	// in a separate http request. It has nothing to do with the rest of
	// the state machine.
	SetHostinfo(*tailcfg.Hostinfo)
	// SetNetinfo changes the NetIinfo structure that will be sent in
	// subsequent node registration requests.
	// TODO: a server-side change would let us simply upload this
	// in a separate http request. It has nothing to do with the rest of
	// the state machine.
	SetNetInfo(*tailcfg.NetInfo)
	// SetTKAHead changes the TKA head hash value that will be sent in
	// subsequent netmap requests.
	SetTKAHead(headHash string)
	// UpdateEndpoints changes the Endpoint structure that will be sent
	// in subsequent node registration requests.
	// TODO: a server-side change would let us simply upload this
	// in a separate http request. It has nothing to do with the rest of
	// the state machine.
	// Note: the auto client uploads the new endpoints to control immediately.
	UpdateEndpoints(endpoints []tailcfg.Endpoint)
	// SetDiscoPublicKey updates the disco public key that will be sent in
	// future map requests. This should be called after rotating the discovery key.
	// Note: the auto client uploads the new key to control immediately.
	SetDiscoPublicKey(key.DiscoPublic)
	// ClientID returns the ClientID of a client. This ID is meant to
	// distinguish one client from another.
	ClientID() int64
}
