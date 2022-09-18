// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// c2n (control-to-node) API types.

package tailcfg

// C2NSSHUsernamesRequest is the request for the /ssh/usernames.
// A GET request without a request body is equivalent to the zero value of this type.
// Otherwise, a POST request with a JSON-encoded request body is expected.
type C2NSSHUsernamesRequest struct {
	// Exclude optionally specifies usernames to exclude
	// from the response.
	Exclude map[string]bool `json:",omitempty"`

	// Max is the maximum number of usernames to return.
	// If zero, a default limit is used.
	Max int `json:",omitempty"`
}

// C2NSSHUsernamesResponse is the response (from node to control) from the
// /ssh/usernames handler.
//
// It returns username auto-complete suggestions for a user to SSH to this node.
// It's only shown to people who already have SSH access to the node. If this
// returns multiple usernames, only the usernames that would have access per the
// tailnet's ACLs are shown to the user so as to not leak the existence of
// usernames.
type C2NSSHUsernamesResponse struct {
	// Usernames is the list of usernames to suggest. If the machine has many
	// users, this list may be truncated. If getting the list of usernames might
	// be too slow or unavailable, this list might be empty. This is effectively
	// just a best effort set of hints.
	Usernames []string
}
