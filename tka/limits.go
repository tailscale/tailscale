// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tka

const (
	// Upper bound on checkpoint elements, chosen arbitrarily. Intended
	// to cap the size of large AUMs.
	maxDisablementSecrets = 32
	maxKeys               = 512

	// Max amount of metadata that can be associated with a key, chosen arbitrarily.
	// Intended to avoid people abusing TKA as a key-value score.
	maxMetaBytes = 512

	// Max iterations searching for any intersection during the sync process.
	maxSyncIter = 2000

	// Max iterations searching for a head intersection during the sync process.
	maxSyncHeadIntersectionIter = 400

	// Limit on scanning AUM trees, chosen arbitrarily.
	maxScanIterations = 2000
)
