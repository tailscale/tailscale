// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package setting

// Key is a string that uniquely identifies a policy and must remain unchanged
// once established and documented for a given policy setting. It may contain
// alphanumeric characters and zero or more [KeyPathSeparator]s to group
// individual policy settings into categories.
type Key string

// KeyPathSeparator allows logical grouping of policy settings into categories.
const KeyPathSeparator = '/'
