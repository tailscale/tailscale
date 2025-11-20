// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"errors"
	"fmt"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
)

type actorWithPolicyChecks struct{ Actor }

// WithPolicyChecks returns an [Actor] that wraps the given actor and
// performs additional policy checks on top of the access checks
// implemented by the wrapped actor.
func WithPolicyChecks(actor Actor) Actor {
	// TODO(nickkhyl): We should probably exclude the Windows Local System
	// account from policy checks as well.
	switch actor.(type) {
	case unrestricted:
		return actor
	default:
		return &actorWithPolicyChecks{Actor: actor}
	}
}

// CheckProfileAccess implements [Actor].
func (a actorWithPolicyChecks) CheckProfileAccess(profile ipn.LoginProfileView, requestedAccess ProfileAccess, auditLogger AuditLogFunc) error {
	if err := a.Actor.CheckProfileAccess(profile, requestedAccess, auditLogger); err != nil {
		return err
	}
	requestReason := apitype.RequestReasonKey.Value(a.Context())
	return CheckDisconnectPolicy(a.Actor, profile, requestReason, auditLogger)
}

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
func CheckDisconnectPolicy(actor Actor, profile ipn.LoginProfileView, reason string, auditFn AuditLogFunc) error {
	if !buildfeatures.HasSystemPolicy {
		return nil
	}
	if alwaysOn, _ := policyclient.Get().GetBoolean(pkey.AlwaysOn, false); !alwaysOn {
		return nil
	}
	if allowWithReason, _ := policyclient.Get().GetBoolean(pkey.AlwaysOnOverrideWithReason, false); !allowWithReason {
		return errors.New("disconnect not allowed: always-on mode is enabled")
	}
	if reason == "" {
		return errors.New("disconnect not allowed: reason required")
	}
	if auditFn != nil {
		var details string
		if username, _ := actor.Username(); username != "" { // best-effort; we don't have it on all platforms
			details = fmt.Sprintf("%q is being disconnected by %q: %v", profile.Name(), username, reason)
		} else {
			details = fmt.Sprintf("%q is being disconnected: %v", profile.Name(), reason)
		}
		if err := auditFn(tailcfg.AuditNodeDisconnect, details); err != nil {
			return err
		}
	}
	return nil
}
