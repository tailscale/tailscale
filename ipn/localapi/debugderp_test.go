// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_debug

package localapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// mockBackendForDERP implements the subset of LocalBackend methods needed for DERP tests
type mockBackendForDERP struct {
	ipnlocal.NoOpBackend
	derpMap *tailcfg.DERPMap
}

func (m *mockBackendForDERP) DERPMap() *tailcfg.DERPMap {
	return m.derpMap
}

// TestServeDebugDERPRegion_PermissionDenied tests permission check
func TestServeDebugDERPRegion_PermissionDenied(t *testing.T) {
	h := &Handler{
		PermitWrite: false,
		b:           &mockBackendForDERP{},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=1", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}

	body := w.Body.String()
	if !strings.Contains(body, "debug access denied") {
		t.Errorf("body = %q, want access denied error", body)
	}
}

// TestServeDebugDERPRegion_MethodNotAllowed tests POST requirement
func TestServeDebugDERPRegion_MethodNotAllowed(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b:           &mockBackendForDERP{},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-derp-region?region=1", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}

	body := w.Body.String()
	if !strings.Contains(body, "POST required") {
		t.Errorf("body = %q, want POST required error", body)
	}
}

// TestServeDebugDERPRegion_NoDERPMap tests nil DERP map
func TestServeDebugDERPRegion_NoDERPMap(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b:           &mockBackendForDERP{}, // nil derpMap
		logf:        t.Logf,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=1", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	// Always returns JSON, even on error
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should have error about no DERP map
	if len(report.Errors) == 0 {
		t.Error("expected errors about no DERP map")
	}

	if !strings.Contains(report.Errors[0], "no DERP map") {
		t.Errorf("error = %q, want no DERP map error", report.Errors[0])
	}
}

// TestServeDebugDERPRegion_NoSuchRegionByID tests non-existent region ID
func TestServeDebugDERPRegion_NoSuchRegionByID(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				RegionName: "Test Region",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "1a",
						RegionID: 1,
						HostName: "test1.example.com",
					},
				},
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: t.Logf,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=999", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	if len(report.Errors) == 0 {
		t.Error("expected errors about non-existent region")
	}

	if !strings.Contains(report.Errors[0], "no such region") {
		t.Errorf("error = %q, want no such region error", report.Errors[0])
	}
}

// TestServeDebugDERPRegion_NoSuchRegionByCode tests non-existent region code
func TestServeDebugDERPRegion_NoSuchRegionByCode(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "nyc",
				RegionName: "New York",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "1a",
						RegionID: 1,
						HostName: "nyc1.example.com",
					},
				},
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: t.Logf,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=sfo", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	if len(report.Errors) == 0 {
		t.Error("expected errors about non-existent region")
	}

	if !strings.Contains(report.Errors[0], "no such region") {
		t.Errorf("error = %q, want no such region error", report.Errors[0])
	}
}

// TestServeDebugDERPRegion_FindByRegionID tests finding region by numeric ID
func TestServeDebugDERPRegion_FindByRegionID(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				RegionName: "Test Region",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "1a",
						RegionID: 1,
						HostName: "test1.example.com",
						IPv4:     "1.2.3.4",
					},
				},
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: t.Logf,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=1", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should have info about the region
	if len(report.Info) == 0 {
		t.Error("expected info messages about region")
	}

	// First info should identify the region
	if !strings.Contains(report.Info[0], "Region 1") {
		t.Errorf("info[0] = %q, want region info", report.Info[0])
	}
}

// TestServeDebugDERPRegion_FindByRegionCode tests finding region by code
func TestServeDebugDERPRegion_FindByRegionCode(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "nyc",
				RegionName: "New York",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "1a",
						RegionID: 1,
						HostName: "nyc1.example.com",
						IPv4:     "192.0.2.1",
					},
				},
			},
			2: {
				RegionID:   2,
				RegionCode: "sfo",
				RegionName: "San Francisco",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "2a",
						RegionID: 2,
						HostName: "sfo1.example.com",
						IPv4:     "192.0.2.2",
					},
				},
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: t.Logf,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=sfo", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should have info about the SFO region
	if len(report.Info) == 0 {
		t.Fatal("expected info messages about region")
	}

	// First info should identify the region
	if !strings.Contains(report.Info[0], "Region 2") || !strings.Contains(report.Info[0], "sfo") {
		t.Errorf("info[0] = %q, want sfo region info", report.Info[0])
	}
}

// TestServeDebugDERPRegion_SingleRegionWarning tests warning for single region
func TestServeDebugDERPRegion_SingleRegionWarning(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "only",
				RegionName: "Only Region",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "1a",
						RegionID: 1,
						HostName: "only.example.com",
						IPv4:     "192.0.2.1",
					},
				},
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: t.Logf,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=1", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should have warning about single region
	if len(report.Warnings) == 0 {
		t.Fatal("expected warnings about single region")
	}

	found := false
	for _, w := range report.Warnings {
		if strings.Contains(w, "single DERP region") && strings.Contains(w, "single point of failure") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("warnings = %v, want single region warning", report.Warnings)
	}
}

// TestServeDebugDERPRegion_MultipleRegionsNoWarning tests no warning for multiple regions
func TestServeDebugDERPRegion_MultipleRegionsNoWarning(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "nyc",
				RegionName: "New York",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "1a",
						RegionID: 1,
						HostName: "nyc.example.com",
						IPv4:     "192.0.2.1",
					},
				},
			},
			2: {
				RegionID:   2,
				RegionCode: "sfo",
				RegionName: "San Francisco",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "2a",
						RegionID: 2,
						HostName: "sfo.example.com",
						IPv4:     "192.0.2.2",
					},
				},
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: t.Logf,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=1", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should NOT have warning about single region
	for _, w := range report.Warnings {
		if strings.Contains(w, "single DERP region") {
			t.Errorf("unexpected single region warning: %q", w)
		}
	}
}

// TestServeDebugDERPRegion_AvoidBitWarning tests warning for Avoid bit
func TestServeDebugDERPRegion_AvoidBitWarning(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "avoid",
				RegionName: "Avoided Region",
				Avoid:      true,
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "1a",
						RegionID: 1,
						HostName: "avoid.example.com",
						IPv4:     "192.0.2.1",
					},
				},
			},
			2: {
				RegionID:   2,
				RegionCode: "ok",
				RegionName: "OK Region",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "2a",
						RegionID: 2,
						HostName: "ok.example.com",
						IPv4:     "192.0.2.2",
					},
				},
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: t.Logf,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=1", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should have warning about Avoid bit
	found := false
	for _, w := range report.Warnings {
		if strings.Contains(w, "marked with Avoid bit") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("warnings = %v, want Avoid bit warning", report.Warnings)
	}
}

// TestServeDebugDERPRegion_NoAvoidBit tests no warning when Avoid is false
func TestServeDebugDERPRegion_NoAvoidBit(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "ok",
				RegionName: "OK Region",
				Avoid:      false,
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "1a",
						RegionID: 1,
						HostName: "ok.example.com",
						IPv4:     "192.0.2.1",
					},
				},
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: t.Logf,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=1", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should NOT have Avoid bit warning
	for _, w := range report.Warnings {
		if strings.Contains(w, "Avoid bit") {
			t.Errorf("unexpected Avoid bit warning: %q", w)
		}
	}
}

// TestServeDebugDERPRegion_NoNodesError tests error for region with no nodes
func TestServeDebugDERPRegion_NoNodesError(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "empty",
				RegionName: "Empty Region",
				Nodes:      []*tailcfg.DERPNode{}, // Empty!
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: t.Logf,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=1", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should have error about no nodes
	if len(report.Errors) == 0 {
		t.Fatal("expected errors about no nodes")
	}

	found := false
	for _, e := range report.Errors {
		if strings.Contains(e, "no nodes defined") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("errors = %v, want no nodes error", report.Errors)
	}
}

// TestServeDebugDERPRegion_NilNodesError tests error for nil nodes
func TestServeDebugDERPRegion_NilNodesError(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "nil",
				RegionName: "Nil Nodes Region",
				Nodes:      nil, // nil!
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: t.Logf,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=1", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should have error about no nodes
	if len(report.Errors) == 0 {
		t.Fatal("expected errors about no nodes")
	}

	found := false
	for _, e := range report.Errors {
		if strings.Contains(e, "no nodes") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("errors = %v, want no nodes error", report.Errors)
	}
}

// TestServeDebugDERPRegion_STUNOnlyNodeInfo tests info for STUN-only nodes
func TestServeDebugDERPRegion_STUNOnlyNodeInfo(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "stun",
				RegionName: "STUN Region",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "1a",
						RegionID: 1,
						HostName: "stun.example.com",
						IPv4:     "192.0.2.1",
						STUNOnly: true,
					},
				},
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: logger.Discard,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=1", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should have info about STUNOnly node
	found := false
	for _, i := range report.Info {
		if strings.Contains(i, "STUNOnly") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("info = %v, want STUNOnly info", report.Info)
	}
}

// TestServeDebugDERPRegion_EmptyRegionParameter tests empty region parameter
func TestServeDebugDERPRegion_EmptyRegionParameter(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				RegionName: "Test",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "1a",
						RegionID: 1,
						HostName: "test.example.com",
					},
				},
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: t.Logf,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should have error about no such region
	if len(report.Errors) == 0 {
		t.Error("expected errors about empty region parameter")
	}
}

// TestServeDebugDERPRegion_MissingRegionParameter tests missing region parameter
func TestServeDebugDERPRegion_MissingRegionParameter(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				RegionName: "Test",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "1a",
						RegionID: 1,
						HostName: "test.example.com",
					},
				},
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: t.Logf,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should have error about no such region
	if len(report.Errors) == 0 {
		t.Error("expected errors about missing region parameter")
	}
}

// TestServeDebugDERPRegion_ResponseStructure tests the response structure
func TestServeDebugDERPRegion_ResponseStructure(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				RegionName: "Test Region",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "1a",
						RegionID: 1,
						HostName: "test.example.com",
						IPv4:     "192.0.2.1",
					},
				},
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: logger.Discard,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=1", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	// Verify Content-Type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}

	// Verify response can be decoded
	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Report should have at least Info about the region
	if len(report.Info) == 0 {
		t.Error("expected at least one info message")
	}
}

// TestServeDebugDERPRegion_MultipleNodes tests region with multiple nodes
func TestServeDebugDERPRegion_MultipleNodes(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "multi",
				RegionName: "Multi-Node Region",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "1a",
						RegionID: 1,
						HostName: "node1.example.com",
						IPv4:     "192.0.2.1",
					},
					{
						Name:     "1b",
						RegionID: 1,
						HostName: "node2.example.com",
						IPv4:     "192.0.2.2",
					},
					{
						Name:     "1c",
						RegionID: 1,
						HostName: "node3.example.com",
						IPv4:     "192.0.2.3",
						STUNOnly: true,
					},
				},
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: logger.Discard,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=1", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should have info about the region
	if len(report.Info) == 0 {
		t.Error("expected info messages")
	}

	// With multiple nodes, there will be errors trying to connect
	// (since this is a test environment), but that's expected
}

// TestServeDebugDERPRegion_RegionIDZero tests region ID 0
func TestServeDebugDERPRegion_RegionIDZero(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			0: {
				RegionID:   0,
				RegionCode: "zero",
				RegionName: "Zero Region",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "0a",
						RegionID: 0,
						HostName: "zero.example.com",
						IPv4:     "192.0.2.1",
					},
				},
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: logger.Discard,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=0", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should find region 0
	if len(report.Info) == 0 {
		t.Fatal("expected info messages about region 0")
	}

	if !strings.Contains(report.Info[0], "Region 0") {
		t.Errorf("info[0] = %q, want region 0 info", report.Info[0])
	}
}

// TestServeDebugDERPRegion_NegativeRegionID tests negative region ID
func TestServeDebugDERPRegion_NegativeRegionID(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				RegionName: "Test",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "1a",
						RegionID: 1,
						HostName: "test.example.com",
					},
				},
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: t.Logf,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=-1", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should have error about no such region
	if len(report.Errors) == 0 {
		t.Error("expected errors about non-existent region")
	}
}

// TestServeDebugDERPRegion_VeryLargeRegionID tests very large region ID
func TestServeDebugDERPRegion_VeryLargeRegionID(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			999999: {
				RegionID:   999999,
				RegionCode: "huge",
				RegionName: "Huge ID Region",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "999999a",
						RegionID: 999999,
						HostName: "huge.example.com",
						IPv4:     "192.0.2.1",
					},
				},
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: logger.Discard,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=999999", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should find the region
	if len(report.Info) == 0 {
		t.Fatal("expected info messages")
	}

	if !strings.Contains(report.Info[0], "999999") {
		t.Errorf("info[0] = %q, want region 999999 info", report.Info[0])
	}
}

// TestServeDebugDERPRegion_SpecialCharactersInRegionCode tests special characters
func TestServeDebugDERPRegion_SpecialCharactersInRegionCode(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "us-west-2",
				RegionName: "US West 2",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "1a",
						RegionID: 1,
						HostName: "us-west-2.example.com",
						IPv4:     "192.0.2.1",
					},
				},
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: logger.Discard,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=us-west-2", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should find the region
	if len(report.Info) == 0 {
		t.Fatal("expected info messages")
	}

	if !strings.Contains(report.Info[0], "us-west-2") {
		t.Errorf("info[0] = %q, want us-west-2 info", report.Info[0])
	}
}

// TestServeDebugDERPRegion_CaseSensitiveRegionCode tests case sensitivity
func TestServeDebugDERPRegion_CaseSensitiveRegionCode(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "NYC",
				RegionName: "New York",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "1a",
						RegionID: 1,
						HostName: "nyc.example.com",
						IPv4:     "192.0.2.1",
					},
				},
			},
		},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: t.Logf,
	}

	// Try lowercase when region code is uppercase
	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=nyc", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should NOT find the region (case-sensitive)
	if len(report.Errors) == 0 {
		t.Error("expected errors about non-existent region (case mismatch)")
	}
}

// TestServeDebugDERPRegion_EmptyDERPMap tests empty DERP map
func TestServeDebugDERPRegion_EmptyDERPMap(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDERP{
			derpMap: derpMap,
		},
		logf: t.Logf,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-derp-region?region=1", nil)
	w := httptest.NewRecorder()

	h.serveDebugDERPRegion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var report ipnstate.DebugDERPRegionReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Should have error about no such region
	if len(report.Errors) == 0 {
		t.Error("expected errors about non-existent region")
	}
}
