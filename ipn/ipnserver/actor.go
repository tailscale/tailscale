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

	isLocalSystem bool // whether the actor is the Windows' Local System identity.
}

func newActor(logf logger.Logf, c net.Conn) (*actor, error) {
	ci, err := ipnauth.GetConnIdentity(logf, c)
	if err != nil {
		return nil, err
	}
	return &actor{logf: logf, ci: ci, isLocalSystem: connIsLocalSystem(ci)}, nil
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
	return a.ci.WindowsUserID()
}

func (a *actor) pid() int {
	return a.ci.Pid()
}

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
	case "darwin", "linux":
		uid, ok := a.ci.Creds().UserID()
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
	actor *actor
	err   error
}

func (a actorOrError) unwrap() (*actor, error) {
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

// actorFromContext returns an [actor] associated with ctx,
// or an error if the context does not carry an actor's identity.
func actorFromContext(ctx context.Context) (*actor, error) {
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
