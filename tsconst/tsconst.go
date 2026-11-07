// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package tsconst exports some constants used elsewhere in the
// codebase.
package tsconst

// WintunInterfaceDesc is the description attached to Tailscale
// interfaces on Windows. This is set by the WinTun driver.
const WintunInterfaceDesc = "Tailscale Tunnel"
const WintunInterfaceDesc0_14 = "Wintun Userspace Tunnel"

// WintunInterfaceGUID is the GUID of the Tailscale interface on Windows.
const WintunInterfaceGUID = "{37217669-42da-4657-a55b-0d995d328250}"

// TailnetLockNotTrustedMsg is the error message used by tailnet lock
// and sniffed (via substring) out of an error sent over the network.
const TailnetLockNotTrustedMsg = "this node is not trusted by Tailnet Lock"
