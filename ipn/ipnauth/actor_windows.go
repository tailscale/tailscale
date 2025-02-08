// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"context"
	"errors"

	"golang.org/x/sys/windows"
	"tailscale.com/ipn"
	"tailscale.com/types/lazy"
)

// WindowsActor implements [Actor].
var _ Actor = (*WindowsActor)(nil)

// WindowsActor represents a logged in Windows user.
type WindowsActor struct {
	ctx       context.Context
	cancelCtx context.CancelFunc
	token     WindowsToken
	uid       ipn.WindowsUserID
	username  lazy.SyncValue[string]
}

// NewWindowsActorWithToken returns a new [WindowsActor] for the user
// represented by the given [windows.Token].
// It takes ownership of the token.
func NewWindowsActorWithToken(t windows.Token) (_ *WindowsActor, err error) {
	tok := newToken(t)
	uid, err := tok.UID()
	if err != nil {
		t.Close()
		return nil, err
	}
	ctx, cancelCtx := context.WithCancel(context.Background())
	return &WindowsActor{ctx: ctx, cancelCtx: cancelCtx, token: tok, uid: uid}, nil
}

// UserID implements [Actor].
func (a *WindowsActor) UserID() ipn.WindowsUserID {
	return a.uid
}

// Username implements [Actor].
func (a *WindowsActor) Username() (string, error) {
	return a.username.GetErr(a.token.Username)
}

// ClientID implements [Actor].
func (a *WindowsActor) ClientID() (_ ClientID, ok bool) {
	// TODO(nickkhyl): assign and return a client ID when the actor
	// represents a connected LocalAPI client.
	return NoClientID, false
}

// Context implements [Actor].
func (a *WindowsActor) Context() context.Context {
	return a.ctx
}

// CheckProfileAccess implements [Actor].
func (a *WindowsActor) CheckProfileAccess(profile ipn.LoginProfileView, _ ProfileAccess, _ AuditLogFunc) error {
	if profile.LocalUserID() != a.UserID() {
		// TODO(nickkhyl): return errors of more specific types and have them
		// translated to the appropriate HTTP status codes in the API handler.
		return errors.New("the target profile does not belong to the user")
	}
	return nil
}

// IsLocalSystem implements [Actor].
//
// Deprecated: this method exists for compatibility with the current (as of 2025-02-06)
// permission model and will be removed as we progress on tailscale/corp#18342.
func (a *WindowsActor) IsLocalSystem() bool {
	// https://web.archive.org/web/2024/https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
	const systemUID = ipn.WindowsUserID("S-1-5-18")
	return a.uid == systemUID
}

// IsLocalAdmin implements [Actor].
//
// Deprecated: this method exists for compatibility with the current (as of 2025-02-06)
// permission model and will be removed as we progress on tailscale/corp#18342.
func (a *WindowsActor) IsLocalAdmin(operatorUID string) bool {
	return a.token.IsElevated()
}

// Close releases resources associated with the actor
// and cancels its context.
func (a *WindowsActor) Close() error {
	if a.token != nil {
		if err := a.token.Close(); err != nil {
			return err
		}
		a.token = nil
	}
	a.cancelCtx()
	return nil
}
