// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package kube contains types and utilities for the Tailscale Kubernetes Operator.
package kube

const EgressServiceAlphaV = "v1alpha1"

type EgressServices struct {
	Version  string                   `json:"version"`
	Services map[string]EgressService `json:"services"`
}

type EgressService struct {
	// fwegress pod IPs
	ClusterSources  []string `json:"clusterSources"`
	TailnetTargetIP string   `json:"tailnetTargetIP"`
}
