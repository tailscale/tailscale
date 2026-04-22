// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package tsconst exports some constants used elsewhere in the
// codebase.
package tsconst

// WintunInterfaceDesc is the description attached to Tailscale
// interfaces on Windows. This is set by the WinTun driver.
const WintunInterfaceDesc = "Tailscale Tunnel"
const WintunInterfaceDesc0_14 = "Wintun Userspace Tunnel"

// TailnetLockNotTrustedMsg is the error message used by network lock
// and sniffed (via substring) out of an error sent over the network.
const TailnetLockNotTrustedMsg = "this node is not trusted by network lock"

// MapResponseErrorCode is a unique string identifier for map response errors.
type MapResponseErrorCode string

// ErrCodeNodeNotFound indicates that the requested node was not found
// in the control plane database.
const ErrCodeNodeNotFound MapResponseErrorCode = "node-not-found"

// ErrCodeInvalidRequest indicates that the client sent a malformed
// or invalid request.
const ErrCodeInvalidRequest MapResponseErrorCode = "invalid-request"

// ErrCodeInternalError indicates that an internal server error
// occurred while processing the request.
const ErrCodeInternalError MapResponseErrorCode = "internal-error"

// ErrCodeMaintenanceMode indicates that the server is currently
// in maintenance mode and cannot process requests.
const ErrCodeMaintenanceMode MapResponseErrorCode = "maintenance-mode"

// ErrCodeRequestSuperseded indicates that the request was replaced
// by a newer request from the same client before it could complete.
const ErrCodeRequestSuperseded MapResponseErrorCode = "request-superseded"

// ErrCodeUserNotFound indicates that the requested user was not found
// in the control plane database.
const ErrCodeUserNotFound MapResponseErrorCode = "user-not-found"

// ErrCodeUnauthorized indicates that the client is not authorized
// to perform the requested operation.
const ErrCodeUnauthorized MapResponseErrorCode = "unauthorized"
