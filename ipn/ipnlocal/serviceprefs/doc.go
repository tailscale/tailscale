// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package serviceprefs stores service preferences for each login profile from a
// user's last launched service: the last selected client app, the last entered
// username and database name, and the last used timestamp, keyed by
// "<service>:<port>".
//
// It defines the Store interface with two implementations: a disk backed file
// store and an in-memory store. The file store uses the in-memory store as a
// cache. Both use time based retention. Either can be swapped or migrated to a
// different implementation in the future.
package serviceprefs
