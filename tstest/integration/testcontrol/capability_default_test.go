// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !experiment.reco

package testcontrol_test

// The original test server also implements legacy map protocol versions.
const minTestControlCapabilityVersion = 0
