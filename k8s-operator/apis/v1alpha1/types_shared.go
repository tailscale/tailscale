// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package v1alpha1

type Image struct {
	// Repo is the image repository, e.g. tailscale/k8s-nameserver.
	// +optional
	Repo string `json:"repo,omitempty"`
	// Tag defaults to operator's own tag.
	// +optional
	Tag string `json:"tag,omitempty"`
}
