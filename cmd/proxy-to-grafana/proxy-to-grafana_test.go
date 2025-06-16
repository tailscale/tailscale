// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

type mockWhoisSource struct {
	id *apitype.WhoIsResponse
}

func (m *mockWhoisSource) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	if m.id == nil {
		return nil, fmt.Errorf("missing mock identity")
	}
	return m.id, nil
}

var whois = &apitype.WhoIsResponse{
	UserProfile: &tailcfg.UserProfile{
		LoginName:   "foobar@example.com",
		DisplayName: "Foobar",
	},
	Node: &tailcfg.Node{
		ID: 1,
	},
}

func TestModifyRequest_Login(t *testing.T) {
	req := httptest.NewRequest("GET", "/login", nil)
	modifyRequest(req, &mockWhoisSource{id: whois})

	if got := req.Header.Get("X-Webauth-User"); got != "foobar@example.com" {
		t.Errorf("X-Webauth-User = %q; want %q", got, "foobar@example.com")
	}

	if got := req.Header.Get("X-Webauth-Role"); got != "Viewer" {
		t.Errorf("X-Webauth-Role = %q; want %q", got, "Viewer")
	}
}

func TestModifyRequest_RemoveHeaders_Login(t *testing.T) {
	req := httptest.NewRequest("GET", "/login", nil)
	req.Header.Set("X-Webauth-User", "malicious@example.com")
	req.Header.Set("X-Webauth-Role", "Admin")

	modifyRequest(req, &mockWhoisSource{id: whois})

	if got := req.Header.Get("X-Webauth-User"); got != "foobar@example.com" {
		t.Errorf("X-Webauth-User = %q; want %q", got, "foobar@example.com")
	}
	if got := req.Header.Get("X-Webauth-Role"); got != "Viewer" {
		t.Errorf("X-Webauth-Role = %q; want %q", got, "Viewer")
	}
}

func TestModifyRequest_RemoveHeaders_API(t *testing.T) {
	req := httptest.NewRequest("DELETE", "/api/org/users/1", nil)
	req.Header.Set("X-Webauth-User", "malicious@example.com")
	req.Header.Set("X-Webauth-Role", "Admin")

	modifyRequest(req, &mockWhoisSource{id: whois})

	if got := req.Header.Get("X-Webauth-User"); got != "" {
		t.Errorf("X-Webauth-User = %q; want %q", got, "")
	}
	if got := req.Header.Get("X-Webauth-Role"); got != "" {
		t.Errorf("X-Webauth-Role = %q; want %q", got, "")
	}
}
