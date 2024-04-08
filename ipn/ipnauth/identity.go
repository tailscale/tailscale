// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"context"
	"net"

	"tailscale.com/ipn"
	"tailscale.com/types/logger"
)

// Identity is any caller identity.
//
// It typically represents a specific OS user, indicating that an operation
// is performed on behalf of this user, should be evaluated against their
// access rights, and performed in their security context when applicable.
//
// However, it can also represent an unrestricted identity (e.g. ipnauth.Self) when an operation
// is executed on behalf of tailscaled itself, in response to a control plane request,
// or when a user's access rights have been verified via other means.
type Identity interface {
	// UserID returns an OS-specific UID of the user represented by the identity,
	// or "" if the receiver does not represent a specific user.
	// As of 2024-04-08, it is only used on Windows.
	UserID() ipn.WindowsUserID
	// Username returns the user name associated with the receiver,
	// or "" if the receiver does not represent a specific user.
	Username() (string, error)
	// CheckAccess reports whether the receiver is allowed or denied the requested device access.
	//
	// This method ignores environment factors, Group Policy, and MDM settings that might
	// override access permissions at a higher level than individual user identities.
	// Therefore, most callers should use ipnauth.CheckAccess instead.
	CheckAccess(requested DeviceAccess) AccessCheckResult
	// CheckProfileAccess reports whether the receiver is allowed or denied the requested access
	// to a specific profile and its prefs.
	//
	// This method ignores environment factors, Group Policy, and MDM settings that might
	// override access permissions at a higher level than individual user identities.
	// Therefore, most callers should use ipnauth.CheckProfileAccess instead.
	CheckProfileAccess(profile ipn.LoginProfileView, prefs ipn.PrefsGetter, requested ProfileAccess) AccessCheckResult
}

type identityContextKey struct{}

var errNoSecContext = ipn.NewAccessDeniedError("security context not available")

// RequestIdentity returns a user identity associated with ctx,
// or an error if the context does not carry a user's identity.
func RequestIdentity(ctx context.Context) (Identity, error) {
	switch v := ctx.Value(identityContextKey{}).(type) {
	case Identity:
		return v, nil
	case error:
		return nil, v
	case nil:
		return nil, errNoSecContext
	default:
		panic("unreachable")
	}
}

// ContextWithConnIdentity returns a new context that carries the identity of the user
// owning the other end of the connection.
func ContextWithConnIdentity(ctx context.Context, logf logger.Logf, c net.Conn) context.Context {
	ci, err := GetConnIdentity(logf, c)
	if err != nil {
		return context.WithValue(ctx, identityContextKey{}, err)
	}
	return context.WithValue(ctx, identityContextKey{}, ci)
}
