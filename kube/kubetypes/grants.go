// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package kubetypes contains types and constants related to the Tailscale
// Kubernetes Operator.
// These are split into a separate package for consumption of
// non-Kubernetes shared libraries and binaries. Be mindful of not increasing
// dependency size for those consumers when adding anything new here.
package kubetypes

import "net/netip"

// KubernetesCapRule is a rule provided via PeerCapabilityKubernetes capability.
type KubernetesCapRule struct {
	// Impersonate is a list of rules that specify how to impersonate the caller
	// when proxying to the Kubernetes API.
	Impersonate *ImpersonateRule `json:"impersonate,omitempty"`
	// Recorders defines a tag of a tsrecorder instance(s) that a recording
	// of a 'kubectl exec' session, matching `src` of this grant, to an API
	// server proxy, matching `dst` of this grant, should be sent to.
	// This list must not contain more than one tag. The field
	// name matches the `Recorder` field with equal semantics for Tailscale
	// SSH session recorder. This field is set by users in ACL grants and is
	// then parsed by control, which resolves the tags and populates `RecorderAddrs``.
	// https://tailscale.com/kb/1246/tailscale-ssh-session-recording#turn-on-session-recording-in-acls
	Recorders []string `json:"recorder,omitempty"`
	// RecorderAddrs is a list of addresses that should be addresses of one
	// or more tsrecorder instance(s). If set, any `kubectl exec` session
	// from a client matching `src` of this grant to an API server proxy
	// matching `dst` of this grant will be recorded and the recording will
	// be sent to the tsrecorder. This field does not exist in the user
	// provided ACL grants - it is populated by control, which obtains the
	// addresses by resolving the tags provided via `Recorders` field.
	RecorderAddrs []netip.AddrPort `json:"recorderAddrs,omitempty"`
	// EnforceRecorder defines whether a kubectl exec session from a client
	// matching `src` to an API server proxy matching `dst` should fail
	// closed if it cannot be recorded (i.e if no recorder can be reached).
	// Default is to fail open.
	// The field name matches `EnforceRecorder` field with equal semantics for Tailscale SSH
	// session recorder.
	// https://tailscale.com/kb/1246/tailscale-ssh-session-recording#turn-on-session-recording-in-acls
	EnforceRecorder bool `json:"enforceRecorder,omitempty"`
}

// ImpersonateRule defines how a request from the tailnet identity matching
// 'src' of this grant should be impersonated.
type ImpersonateRule struct {
	// Groups can be used to set a list of groups that a request to
	// Kubernetes API server should be impersonated as from. Groups in
	// Kubernetes only exist as subjects that RBAC rules refer to. Caller
	// can choose to use an existing group, such as system:masters, or
	// create RBAC for a new group.
	// https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-subjects
	Groups []string `json:"groups,omitempty"`
}
