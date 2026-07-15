// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package peerrelay

import (
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

func (r *Reconciler) peerRelayTags(pr *tsapi.PeerRelay) []string {
	tags := pr.Spec.Tags.Stringify()
	if len(tags) == 0 {
		return r.defaultTags
	}
	return tags
}
