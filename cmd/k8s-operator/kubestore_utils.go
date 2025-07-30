// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package main contains shared utilities for working with kubestore secrets.
// Kubestore is Tailscale's Kubernetes-backed state storage mechanism that
// stores device state in pod-named secrets for StatefulSet workloads.
package main

import (
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"tailscale.com/tailcfg"
)

const (
	// currentProfileKey is the key in kubestore secrets that contains the current profile name
	currentProfileKey = "_current-profile"
)

// kubeclientPrefs is a partial definition of ipn.Prefs, with just the fields we need.
type kubeclientPrefs struct {
	Config *kubeclientConfig `json:"Config"`
}

type kubeclientConfig struct {
	NodeID      tailcfg.StableNodeID `json:"NodeID"`
	UserProfile tailcfg.UserProfile  `json:"UserProfile"`
}

// nodePrefs is the legacy type used by existing code
type nodePrefs struct {
	Config            *nodeConfig `json:"Config"`
	AdvertiseServices []string    `json:"AdvertiseServices"`
}

type nodeConfig struct {
	NodeID      tailcfg.StableNodeID `json:"NodeID"`
	UserProfile tailcfg.UserProfile  `json:"UserProfile"`
}

// getDevicePrefsFromKubestore extracts device preferences from a kubestore state secret.
// kubestore secrets have a different format than traditional state secrets.
// Returns the preferences, whether they were found, and any error.
func getDevicePrefsFromKubestore(secret *corev1.Secret) (prefs kubeclientPrefs, ok bool, err error) {
	// kubestore stores the current profile key
	currentProfile, ok := secret.Data[currentProfileKey]
	if !ok {
		return prefs, false, nil
	}

	// Get the profile data
	profileBytes, ok := secret.Data[string(currentProfile)]
	if !ok {
		return prefs, false, nil
	}

	if err := json.Unmarshal(profileBytes, &prefs); err != nil {
		return prefs, false, fmt.Errorf("failed to extract node profile info from state Secret %s: %w", secret.Name, err)
	}

	ok = prefs.Config != nil && prefs.Config.NodeID != ""
	return prefs, ok, nil
}

// getDevicePrefs is a backward-compatible wrapper for getDevicePrefsFromKubestore
// that returns prefs in the format expected by existing code.
func getDevicePrefs(secret *corev1.Secret) (prefs nodePrefs, ok bool, err error) {
	kubePrefs, ok, err := getDevicePrefsFromKubestore(secret)
	if err != nil || !ok {
		return prefs, ok, err
	}

	prefs.Config = &nodeConfig{
		NodeID:      kubePrefs.Config.NodeID,
		UserProfile: kubePrefs.Config.UserProfile,
	}

	// Try to extract AdvertiseServices if available
	if profileBytes, ok := secret.Data[string(secret.Data[currentProfileKey])]; ok {
		var fullPrefs nodePrefs
		if json.Unmarshal(profileBytes, &fullPrefs) == nil {
			prefs.AdvertiseServices = fullPrefs.AdvertiseServices
		}
	}

	return prefs, true, nil
}
