// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package healthmsg contains some constants for health messages.
//
// It's a leaf so both the server and CLI can depend on it without bringing too
// much in to the CLI binary.
package healthmsg

const (
	WarnAcceptRoutesOff = "Some peers are advertising routes but --accept-routes is false"
	TailscaleSSHOnBut   = "Tailscale SSH enabled, but " // + ... something from caller
	LockedOut           = "this node is locked out; it will not have connectivity until it is signed. For more info, see https://tailscale.com/s/locked-out"
	WarnExitNodeUsage   = "The following issues on your machine will likely make usage of exit nodes impossible"
)
