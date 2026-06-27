// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package tsdnsjsonv0 provides types for unmarshalling the JSON output of the
// "tailscale dns --json" command:
//
//   - [QueryResponse] will unmarshal the output of "tailscale dns query --json=1"
//   - [StatusResponse] will unmarshal the output of "tailscale dns status --json=1".
//
// # WARNING: unstable
//
// Format is "v0" and is subject to change.
// There is no guarantee of backwards or forwards compatibility.
package tsdnsjsonv0
