// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"errors"
	"fmt"

	"tailscale.com/ipn"
	"tailscale.com/util/syspolicy"
)

// CheckDisconnectPolicy checks if the policy allows the specified actor to disconnect
// Tailscale with the given optional reason. It returns nil if the operation is allowed,
// or an error if it is not. If auditLogger is non-nil, it is called to log the action
// when required by the policy.
//
// Note: this function only checks the policy and does not check whether the actor has
// the necessary access rights to the device or profile. It is intended to be used by
// [Actor] implementations on platforms where [syspolicy] is supported.
//
// TODO(nickkhyl): unexport it when we move [ipn.Actor] implementations from [ipnserver]
// and corp to this package.
func CheckDisconnectPolicy(actor Actor, profile ipn.LoginProfileView, reason string, auditLogger AuditLogFunc) error {
	if alwaysOn, _ := syspolicy.GetBoolean(syspolicy.AlwaysOn, false); !alwaysOn {
		return nil
	}
	if allowWithReason, _ := syspolicy.GetBoolean(syspolicy.AlwaysOnOverrideWithReason, false); !allowWithReason {
		return errors.New("disconnect not allowed: always-on mode is enabled")
	}
	if reason == "" {
		return errors.New("disconnect not allowed: reason required")
	}
	if auditLogger != nil {
		var details string
		if username, _ := actor.Username(); username != "" { // best-effort; we don't have it on all platforms
			details = fmt.Sprintf("%q is being disconnected by %q: %v", profile.Name(), username, reason)
		} else {
			details = fmt.Sprintf("%q is being disconnected: %v", profile.Name(), reason)
		}
		// TODO(nickkhyl,barnstar): use a const for DISCONNECT_NODE.
		auditLogger("DISCONNECT_NODE", details)
	}
	return nil
}
