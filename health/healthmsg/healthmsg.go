// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package healthmsg contains some constants for health messages.
//
// It's a leaf so both the server and CLI can depend on it without bringing too
// much in to the CLI binary.
package healthmsg

const (
	WarnAcceptRoutesOff = "Some peers are advertising routes but --accept-routes is false"
	TailscaleSSHOnBut   = "Tailscale SSH enabled, but " // + ... something from caller
)
