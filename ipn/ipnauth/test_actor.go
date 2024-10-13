// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"tailscale.com/ipn"
)

var _ Actor = (*TestActor)(nil)

// TestActor is an [Actor] used exclusively for testing purposes.
type TestActor struct {
	UID         ipn.WindowsUserID // OS-specific UID of the user, if the actor represents a local Windows user
	Name        string            // username associated with the actor, or ""
	NameErr     error             // error to be returned by [TestActor.Username]
	CID         ClientID          // non-zero if the actor represents a connected LocalAPI client
	LocalSystem bool              // whether the actor represents the special Local System account on Windows
	LocalAdmin  bool              // whether the actor has local admin access

}

// UserID implements [Actor].
func (a *TestActor) UserID() ipn.WindowsUserID { return a.UID }

// Username implements [Actor].
func (a *TestActor) Username() (string, error) { return a.Name, a.NameErr }

// ClientID implements [Actor].
func (a *TestActor) ClientID() (_ ClientID, ok bool) { return a.CID, a.CID != NoClientID }

// IsLocalSystem implements [Actor].
func (a *TestActor) IsLocalSystem() bool { return a.LocalSystem }

// IsLocalAdmin implements [Actor].
func (a *TestActor) IsLocalAdmin(operatorUID string) bool { return a.LocalAdmin }
