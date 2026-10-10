// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package identityheaders sets the Tailscale-* HTTP headers that identify the
// caller of a request to a proxied backend, as done by "tailscale serve" and
// tsnet-proxy.
package identityheaders

import (
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"tailscale.com/tailcfg"
)

// Names of the headers that tailscaled sets on proxied requests to describe the
// caller. [Strip] removes all of them. [Set] sets all except [FunnelRequest]
// and [AppCapabilities], which callers set themselves.
const (
	UserLogin      = "Tailscale-User-Login"
	UserName       = "Tailscale-User-Name"
	UserProfilePic = "Tailscale-User-Profile-Pic"
	NodeName       = "Tailscale-Node-Name"
	NodeTags       = "Tailscale-Node-Tags"
	FunnelRequest  = "Tailscale-Funnel-Request"
	HeadersInfo    = "Tailscale-Headers-Info"

	AppCapabilities = "Tailscale-App-Capabilities"
)

// headersInfoURL is the value of the [HeadersInfo] header.
const headersInfoURL = "https://tailscale.com/s/serve-headers"

// Strip removes every header that tailscaled sets on proxied requests: the
// identity headers, [FunnelRequest] and [AppCapabilities]. It must be called on
// every proxied request so that clients can't spoof them.
func Strip(h http.Header) {
	h.Del(UserLogin)
	h.Del(UserName)
	h.Del(UserProfilePic)
	h.Del(NodeName)
	h.Del(NodeTags)
	h.Del(FunnelRequest)
	h.Del(HeadersInfo)
	h.Del(AppCapabilities)
}

// Set adds identity headers for the caller to h. It does not remove existing
// ones; call [Strip] first.
//
// For nodes owned by a user, it sets the Tailscale-User-* headers from user.
// Tagged nodes have no user, so it sets [NodeName] and [NodeTags]
// (comma-separated) instead. It does nothing if node is invalid, or if node is
// not tagged and user is invalid.
func Set(h http.Header, node tailcfg.NodeView, user tailcfg.UserProfileView) {
	if !node.Valid() {
		return
	}
	if node.IsTagged() {
		h.Set(NodeName, Encode(strings.TrimSuffix(node.Name(), ".")))
		h.Set(NodeTags, Encode(strings.Join(node.Tags().AsSlice(), ",")))
	} else {
		if !user.Valid() {
			return
		}
		h.Set(UserLogin, Encode(user.LoginName()))
		h.Set(UserName, Encode(user.DisplayName()))
		h.Set(UserProfilePic, user.ProfilePicURL())
	}
	h.Set(HeadersInfo, headersInfoURL)
}

// Encode cleans or encodes as necessary v, to be suitable in an HTTP header
// value. See https://github.com/tailscale/tailscale/issues/11603.
//
// If v is not a valid UTF-8 string, it returns an empty string.
// If v is a valid ASCII string, it returns v unmodified.
// If v is a valid UTF-8 string with non-ASCII characters, it returns a
// RFC 2047 Q-encoded string.
func Encode(v string) string {
	if !utf8.ValidString(v) {
		return ""
	}
	return mime.QEncoding.Encode("utf-8", v)
}
