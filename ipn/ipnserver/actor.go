// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"time"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/types/logger"
	"tailscale.com/util/ctxkey"
	"tailscale.com/util/osuser"
	"tailscale.com/version"
)

var _ ipnauth.Actor = (*actor)(nil)

// actor implements [ipnauth.Actor] and provides additional functionality that is
// specific to the current (as of 2024-08-27) permission model.
//
// Deprecated: this type exists for compatibility reasons and will be removed as
// we progress on tailscale/corp#18342.
type actor struct {
	logf logger.Logf
	ci   *ipnauth.ConnIdentity

	clientID ipnauth.ClientID
	userID   ipn.WindowsUserID // cached Windows user ID of the connected client process.
	// accessOverrideReason specifies the reason for overriding certain access restrictions,
	// such as permitting a user to disconnect when the always-on mode is enabled,
	// provided that such justification is allowed by the policy.
	accessOverrideReason string
	isLocalSystem        bool // whether the actor is the Windows' Local System identity.
}

func newActor(logf logger.Logf, c net.Conn) (*actor, error) {
	ci, err := ipnauth.GetConnIdentity(logf, c)
	if err != nil {
		return nil, err
	}
	var clientID ipnauth.ClientID
	if pid := ci.Pid(); pid != 0 {
		// Derive [ipnauth.ClientID] from the PID of the connected client process.
		// TODO(nickkhyl): This is transient and will be re-worked as we
		// progress on tailscale/corp#18342. At minimum, we should use a 2-tuple
		// (PID + StartTime) or a 3-tuple (PID + StartTime + UID) to identify
		// the client process. This helps prevent security issues where a
		// terminated client process's PID could be reused by a different
		// process. This is not currently an issue as we allow only one user to
		// connect anyway.
		// Additionally, we should consider caching authentication results since
		// operations like retrieving a username by SID might require network
		// connectivity on domain-joined devices and/or be slow.
		clientID = ipnauth.ClientIDFrom(pid)
	}
	return &actor{
			logf:          logf,
			ci:            ci,
			clientID:      clientID,
			userID:        ci.WindowsUserID(),
			isLocalSystem: connIsLocalSystem(ci),
		},
		nil
}

// actorWithAccessOverride returns a new actor that carries the specified
// reason for overriding certain access restrictions, if permitted by the
// policy. If the reason is "", it returns the base actor.
func actorWithAccessOverride(baseActor *actor, reason string) *actor {
	if reason == "" {
		return baseActor
	}
	return &actor{
		logf:                 baseActor.logf,
		ci:                   baseActor.ci,
		clientID:             baseActor.clientID,
		userID:               baseActor.userID,
		accessOverrideReason: reason,
		isLocalSystem:        baseActor.isLocalSystem,
	}
}

// CheckProfileAccess implements [ipnauth.Actor].
func (a *actor) CheckProfileAccess(profile ipn.LoginProfileView, requestedAccess ipnauth.ProfileAccess, auditLogger ipnauth.AuditLogFunc) error {
	// TODO(nickkhyl): return errors of more specific types and have them
	// translated to the appropriate HTTP status codes in the API handler.
	if profile.LocalUserID() != a.UserID() {
		return errors.New("the target profile does not belong to the user")
	}
	switch requestedAccess {
	case ipnauth.Disconnect:
		// Disconnect is allowed if a user owns the profile and the policy permits it.
		return ipnauth.CheckDisconnectPolicy(a, profile, a.accessOverrideReason, auditLogger)
	default:
		return errors.New("the requested operation is not allowed")
	}
}

// IsLocalSystem implements [ipnauth.Actor].
func (a *actor) IsLocalSystem() bool {
	return a.isLocalSystem
}

// IsLocalAdmin implements [ipnauth.Actor].
func (a *actor) IsLocalAdmin(operatorUID string) bool {
	return a.isLocalSystem || connIsLocalAdmin(a.logf, a.ci, operatorUID)
}

// UserID implements [ipnauth.Actor].
func (a *actor) UserID() ipn.WindowsUserID {
	return a.userID
}

func (a *actor) pid() int {
	return a.ci.Pid()
}

// ClientID implements [ipnauth.Actor].
func (a *actor) ClientID() (_ ipnauth.ClientID, ok bool) {
	return a.clientID, a.clientID != ipnauth.NoClientID
}

// Context implements [ipnauth.Actor].
func (a *actor) Context() context.Context { return context.Background() }

// Username implements [ipnauth.Actor].
func (a *actor) Username() (string, error) {
	if a.ci == nil {
		a.logf("[unexpected] missing ConnIdentity in ipnserver.actor")
		return "", errors.New("missing ConnIdentity")
	}
	switch runtime.GOOS {
	case "windows":
		tok, err := a.ci.WindowsToken()
		if err != nil {
			return "", fmt.Errorf("get windows token: %w", err)
		}
		defer tok.Close()
		return tok.Username()
	case "darwin", "linux", "illumos", "solaris", "openbsd":
		creds := a.ci.Creds()
		if creds == nil {
			return "", errors.New("peer credentials not implemented on this OS")
		}
		uid, ok := creds.UserID()
		if !ok {
			return "", errors.New("missing user ID")
		}
		u, err := osuser.LookupByUID(uid)
		if err != nil {
			return "", fmt.Errorf("lookup user: %w", err)
		}
		return u.Username, nil
	default:
		return "", errors.New("unsupported OS")
	}
}

type actorOrError struct {
	actor ipnauth.Actor
	err   error
}

func (a actorOrError) unwrap() (ipnauth.Actor, error) {
	return a.actor, a.err
}

var errNoActor = errors.New("connection actor not available")

var actorKey = ctxkey.New("ipnserver.actor", actorOrError{err: errNoActor})

// contextWithActor returns a new context that carries the identity of the actor
// owning the other end of the [net.Conn]. It can be retrieved with [actorFromContext].
func contextWithActor(ctx context.Context, logf logger.Logf, c net.Conn) context.Context {
	actor, err := newActor(logf, c)
	return actorKey.WithValue(ctx, actorOrError{actor: actor, err: err})
}

// NewContextWithActorForTest returns a new context that carries the identity
// of the specified actor. It is used in tests only.
func NewContextWithActorForTest(ctx context.Context, actor ipnauth.Actor) context.Context {
	return actorKey.WithValue(ctx, actorOrError{actor: actor})
}

// actorFromContext returns an [ipnauth.Actor] associated with ctx,
// or an error if the context does not carry an actor's identity.
func actorFromContext(ctx context.Context) (ipnauth.Actor, error) {
	return actorKey.Value(ctx).unwrap()
}

func connIsLocalSystem(ci *ipnauth.ConnIdentity) bool {
	token, err := ci.WindowsToken()
	return err == nil && token.IsLocalSystem()
}

// connIsLocalAdmin reports whether the connected client has administrative
// access to the local machine, for whatever that means with respect to the
// current OS.
//
// This is useful because tailscaled itself always runs with elevated rights:
// we want to avoid privilege escalation for certain mutative operations.
func connIsLocalAdmin(logf logger.Logf, ci *ipnauth.ConnIdentity, operatorUID string) bool {
	if ci == nil {
		logf("[unexpected] missing ConnIdentity in LocalAPI Handler")
		return false
	}
	switch runtime.GOOS {
	case "windows":
		tok, err := ci.WindowsToken()
		if err != nil {
			if !errors.Is(err, ipnauth.ErrNotImplemented) {
				logf("ipnauth.ConnIdentity.WindowsToken() error: %v", err)
			}
			return false
		}
		defer tok.Close()

		return tok.IsElevated()

	case "darwin":
		// Unknown, or at least unchecked on sandboxed macOS variants. Err on
		// the side of less permissions.
		//
		// authorizeServeConfigForGOOSAndUserContext should not call
		// connIsLocalAdmin on sandboxed variants anyway.
		if version.IsSandboxedMacOS() {
			return false
		}
		// This is a standalone tailscaled setup, use the same logic as on
		// Linux.
		fallthrough
	case "linux":
		if !buildfeatures.HasUnixSocketIdentity {
			// Everybody is an admin if support for unix socket identities
			// is omitted for the build.
			return true
		}
		uid, ok := ci.Creds().UserID()
		if !ok {
			return false
		}
		// root is always admin.
		if uid == "0" {
			return true
		}
		// if non-root, must be operator AND able to execute "sudo tailscale".
		if operatorUID != "" && uid != operatorUID {
			return false
		}
		u, err := osuser.LookupByUID(uid)
		if err != nil {
			return false
		}
		// Short timeout just in case sudo hangs for some reason.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := exec.CommandContext(ctx, "sudo", "--other-user="+u.Name, "--list", "tailscale").Run(); err != nil {
			return false
		}
		return true

	default:
		return false
	}
}
