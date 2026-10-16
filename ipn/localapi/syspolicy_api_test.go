// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_syspolicy

package localapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tailscale.com/ipn/ipnauth"
	"tailscale.com/util/httpm"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/rsop"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/syspolicy/source"
)

func TestPolicyUsesCallerUserScope(t *testing.T) {
	setting.SetDefinitionsForTest(t,
		setting.NewDefinition(
			pkey.ManagedByOrganizationName,
			setting.UserSetting,
			setting.StringValue,
		),
	)

	const uid = "S-1-5-21-1001"

	store := source.NewTestStore(t)
	store.SetStrings(
		source.TestSettingOf(pkey.ManagedByOrganizationName, "UserCorp"),
	)
	rsop.RegisterStoreForTest(t, "UserStore", setting.UserScopeOf(uid), store)

	h := &Handler{
		PermitRead: true,
		Actor:      &ipnauth.TestActor{UID: uid},
	}

	req := httptest.NewRequest(httpm.GET, "/localapi/v0/policy/", nil)
	rec := httptest.NewRecorder()

	h.servePolicy(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(
			"status = %d; want %d; body = %s",
			rec.Code,
			http.StatusOK,
			rec.Body.String(),
		)
	}

	if got := rec.Body.String(); !strings.Contains(got, "UserCorp") {
		t.Fatalf("response does not contain user-scoped policy: %s", got)
	}
}

func TestPolicyUsesDefaultScopeForEmptyUserID(t *testing.T) {
	setting.SetDefinitionsForTest(t,
		setting.NewDefinition(
			pkey.ManagedByOrganizationName,
			setting.DeviceSetting,
			setting.StringValue,
		),
	)

	store := source.NewTestStore(t)
	store.SetStrings(
		source.TestSettingOf(pkey.ManagedByOrganizationName, "DeviceCorp"),
	)
	rsop.RegisterStoreForTest(t, "DeviceStore", setting.DefaultScope(), store)

	h := &Handler{
		PermitRead: true,
		Actor:      &ipnauth.TestActor{},
	}

	req := httptest.NewRequest(httpm.GET, "/localapi/v0/policy/", nil)
	rec := httptest.NewRecorder()

	h.servePolicy(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(
			"status = %d; want %d; body = %s",
			rec.Code,
			http.StatusOK,
			rec.Body.String(),
		)
	}

	if got := rec.Body.String(); !strings.Contains(got, "DeviceCorp") {
		t.Fatalf("response does not contain default-scope policy: %s", got)
	}
}
