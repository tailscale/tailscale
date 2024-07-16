// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prefs

// Options are used to configure additional parameters of a preference.
type Options func(s *metadata)

var (
	// ReadOnly is an option that marks preference as read-only.
	ReadOnly Options = markReadOnly
	// Managed is an option that marks preference as managed.
	Managed Options = markManaged
)

func markReadOnly(s *metadata) {
	s.ReadOnly = true
}

func markManaged(s *metadata) {
	s.Managed = true
}
