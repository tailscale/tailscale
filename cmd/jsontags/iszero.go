// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package jsontags

import (
	"go/types"
	"reflect"

	"tailscale.com/util/set"
)

var _ = reflect.Value.IsZero // refer for hot-linking purposes

var pureIsZeroMethods map[string]set.Set[string]

// hasPureIsZeroMethod reports whether the IsZero method is truly
// identical to [reflect.Value.IsZero].
func hasPureIsZeroMethod(t types.Type) bool {
	// TODO: Detect this automatically by checking the method AST?
	path, name := typeName(t)
	return pureIsZeroMethods[path].Contains(name)
}

// PureIsZeroMethodsInTailscaleModule is a list of known IsZero methods
// in the "tailscale.com" module that are pure.
var PureIsZeroMethodsInTailscaleModule = map[string]set.Set[string]{
	"tailscale.com/net/packet": set.Of(
		"TailscaleRejectReason",
	),
	"tailscale.com/tailcfg": set.Of(
		"UserID",
		"LoginID",
		"NodeID",
		"StableNodeID",
	),
	"tailscale.com/tka": set.Of(
		"AUMHash",
	),
	"tailscale.com/types/geo": set.Of(
		"Point",
	),
	"tailscale.com/tstime/mono": set.Of(
		"Time",
	),
	"tailscale.com/types/key": set.Of(
		"NLPrivate",
		"NLPublic",
		"DERPMesh",
		"MachinePrivate",
		"MachinePublic",
		"ControlPrivate",
		"DiscoPrivate",
		"DiscoPublic",
		"DiscoShared",
		"HardwareAttestationPublic",
		"ChallengePublic",
		"NodePrivate",
		"NodePublic",
	),
	"tailscale.com/types/netlogtype": set.Of(
		"Connection",
		"Counts",
	),
}

// RegisterPureIsZeroMethods specifies a list of pure IsZero methods
// where it is identical to calling [reflect.Value.IsZero] on the receiver.
// This is not strictly necessary, but allows for more accurate
// detection of improper use of `json` tags.
//
// This must be called at init and the input must not be mutated.
func RegisterPureIsZeroMethods(methods map[string]set.Set[string]) {
	pureIsZeroMethods = methods
}
