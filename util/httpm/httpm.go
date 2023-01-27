// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package httpm has shorter names for HTTP method constants.
//
// Some background: originally Go didn't have http.MethodGet, http.MethodPost
// and life was good and people just wrote readable "GET" and "POST". But then
// in a moment of weakness Brad and others maintaining net/http caved and let
// the http.MethodFoo constants be added and code's been less readable since.
// Now the substance of the method name is hidden away at the end after
// "http.Method" and they all blend together and it's hard to read code using
// them.
//
// This package is a compromise. It provides constants, but shorter and closer
// to how it used to look. It does violate Go style
// (https://github.com/golang/go/wiki/CodeReviewComments#mixed-caps) that says
// constants shouldn't be SCREAM_CASE. But this isn't INT_MAX; it's GET and
// POST, which are already defined as all caps.
//
// It would be tempting to make these constants be typed but then they wouldn't
// be assignable to things in net/http that just want string. Oh well.
package httpm

const (
	GET       = "GET"
	HEAD      = "HEAD"
	POST      = "POST"
	PUT       = "PUT"
	PATCH     = "PATCH"
	DELETE    = "DELETE"
	CONNECT   = "CONNECT"
	OPTIONS   = "OPTIONS"
	TRACE     = "TRACE"
	SPACEJUMP = "SPACEJUMP" // https://www.w3.org/Protocols/HTTP/Methods/SpaceJump.html
	BREW      = "BREW"      // https://datatracker.ietf.org/doc/html/rfc2324#section-2.1.1
)
