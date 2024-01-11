// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package httphdr

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

// TODO: Must authorization parameters be valid UTF-8?

// AuthScheme is an authorization scheme per RFC 7235.
// Per section 2.1, the "Authorization" header is formatted as:
//
//	Authorization: <auth-scheme> <auth-parameter>
//
// A scheme implementation must self-report the <auth-scheme> name and
// provide the ability to marshal and unmarshal the <auth-parameter>.
//
// For concrete implementations, see [Basic] and [Bearer].
type AuthScheme interface {
	// AuthScheme is the authorization scheme name.
	// It must be valid according to RFC 7230, section 3.2.6.
	AuthScheme() string

	// MarshalAuth marshals the authorization parameter for the scheme.
	MarshalAuth() (string, error)

	// UnmarshalAuth unmarshals the authorization parameter for the scheme.
	UnmarshalAuth(string) error
}

// BasicAuth is the Basic authorization scheme as defined in RFC 2617.
type BasicAuth struct {
	Username string // must not contain ':' per section 2
	Password string
}

func (BasicAuth) AuthScheme() string { return "Basic" }

func (a BasicAuth) MarshalAuth() (string, error) {
	if strings.IndexByte(a.Username, ':') >= 0 {
		return "", fmt.Errorf("invalid username: contains a colon")
	}
	return base64.StdEncoding.EncodeToString([]byte(a.Username + ":" + a.Password)), nil
}

func (a *BasicAuth) UnmarshalAuth(s string) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("invalid basic authorization: %w", err)
	}
	i := bytes.IndexByte(b, ':')
	if i < 0 {
		return fmt.Errorf("invalid basic authorization: missing a colon")
	}
	a.Username = string(b[:i])
	a.Password = string(b[i+len(":"):])
	return nil
}

// BearerAuth is the Bearer Token authorization scheme as defined in RFC 6750.
type BearerAuth struct {
	Token string // usually a base64-encoded string per section 2.1
}

func (BearerAuth) AuthScheme() string { return "Bearer" }

func (a BearerAuth) MarshalAuth() (string, error) {
	// TODO: Verify that token is valid base64?
	return a.Token, nil
}

func (a *BearerAuth) UnmarshalAuth(s string) error {
	// TODO: Verify that token is valid base64?
	a.Token = s
	return nil
}
