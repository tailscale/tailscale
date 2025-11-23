// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_debug

package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/netmap"
)

// mockBackendForDebug implements the subset of LocalBackend methods needed for debug tests
type mockBackendForDebug struct {
	ipnlocal.NoOpBackend
	getEndpointChanges      func(context.Context, netip.Addr) (any, error)
	setComponentDebugLogging func(string, time.Time) error
	debugRebind             func() error
	debugReSTUN             func() error
	debugNotify             func(ipn.Notify)
	debugRotateDiscoKey     func() error
	setDevStateStore        func(key, value string) error
	netMap                  *netmap.NetworkMap
	controlKnobs            *tailcfg.ControlKnobs
}

func (m *mockBackendForDebug) GetPeerEndpointChanges(ctx context.Context, ip netip.Addr) (any, error) {
	if m.getEndpointChanges != nil {
		return m.getEndpointChanges(ctx, ip)
	}
	return nil, nil
}

func (m *mockBackendForDebug) SetComponentDebugLogging(component string, until time.Time) error {
	if m.setComponentDebugLogging != nil {
		return m.setComponentDebugLogging(component, until)
	}
	return nil
}

func (m *mockBackendForDebug) DebugRebind() error {
	if m.debugRebind != nil {
		return m.debugRebind()
	}
	return nil
}

func (m *mockBackendForDebug) DebugReSTUN() error {
	if m.debugReSTUN != nil {
		return m.debugReSTUN()
	}
	return nil
}

func (m *mockBackendForDebug) DebugNotify(n ipn.Notify) {
	if m.debugNotify != nil {
		m.debugNotify(n)
	}
}

func (m *mockBackendForDebug) DebugRotateDiscoKey() error {
	if m.debugRotateDiscoKey != nil {
		return m.debugRotateDiscoKey()
	}
	return nil
}

func (m *mockBackendForDebug) SetDevStateStore(key, value string) error {
	if m.setDevStateStore != nil {
		return m.setDevStateStore(key, value)
	}
	return nil
}

func (m *mockBackendForDebug) NetMap() *netmap.NetworkMap {
	return m.netMap
}

func (m *mockBackendForDebug) ControlKnobs() *tailcfg.ControlKnobs {
	if m.controlKnobs != nil {
		return m.controlKnobs
	}
	return &tailcfg.ControlKnobs{}
}

// TestServeDebugPeerEndpointChanges_MissingIP tests missing IP parameter
func TestServeDebugPeerEndpointChanges_MissingIP(t *testing.T) {
	h := &Handler{
		PermitRead: true,
		b:          &mockBackendForDebug{},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-peer-endpoint-changes", nil)
	w := httptest.NewRecorder()

	h.serveDebugPeerEndpointChanges(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	body := w.Body.String()
	if !strings.Contains(body, "missing 'ip' parameter") {
		t.Errorf("body = %q, want missing ip error", body)
	}
}

// TestServeDebugPeerEndpointChanges_InvalidIP tests invalid IP parameter
func TestServeDebugPeerEndpointChanges_InvalidIP(t *testing.T) {
	h := &Handler{
		PermitRead: true,
		b:          &mockBackendForDebug{},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-peer-endpoint-changes?ip=invalid", nil)
	w := httptest.NewRecorder()

	h.serveDebugPeerEndpointChanges(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	body := w.Body.String()
	if !strings.Contains(body, "invalid IP") {
		t.Errorf("body = %q, want invalid IP error", body)
	}
}

// TestServeDebugPeerEndpointChanges_Success tests successful endpoint changes retrieval
func TestServeDebugPeerEndpointChanges_Success(t *testing.T) {
	testIP := netip.MustParseAddr("100.64.0.1")
	mockChanges := map[string]interface{}{
		"changes": []string{"endpoint1", "endpoint2"},
		"count":   2,
	}

	h := &Handler{
		PermitRead: true,
		b: &mockBackendForDebug{
			getEndpointChanges: func(ctx context.Context, ip netip.Addr) (any, error) {
				if ip != testIP {
					t.Errorf("ip = %v, want %v", ip, testIP)
				}
				return mockChanges, nil
			},
		},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-peer-endpoint-changes?ip=100.64.0.1", nil)
	w := httptest.NewRecorder()

	h.serveDebugPeerEndpointChanges(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
}

// TestServeDebugPeerEndpointChanges_PermissionDenied tests permission check
func TestServeDebugPeerEndpointChanges_PermissionDenied(t *testing.T) {
	h := &Handler{
		PermitRead: false,
		b:          &mockBackendForDebug{},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-peer-endpoint-changes?ip=100.64.0.1", nil)
	w := httptest.NewRecorder()

	h.serveDebugPeerEndpointChanges(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// TestServeDebugPeerEndpointChanges_BackendError tests backend error handling
func TestServeDebugPeerEndpointChanges_BackendError(t *testing.T) {
	h := &Handler{
		PermitRead: true,
		b: &mockBackendForDebug{
			getEndpointChanges: func(ctx context.Context, ip netip.Addr) (any, error) {
				return nil, fmt.Errorf("backend error")
			},
		},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-peer-endpoint-changes?ip=100.64.0.1", nil)
	w := httptest.NewRecorder()

	h.serveDebugPeerEndpointChanges(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

// TestServeComponentDebugLogging_Success tests successful component logging
func TestServeComponentDebugLogging_Success(t *testing.T) {
	componentSeen := ""
	untilSeen := time.Time{}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			setComponentDebugLogging: func(component string, until time.Time) error {
				componentSeen = component
				untilSeen = until
				return nil
			},
		},
		clock: tstest.Clock{},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/component-debug-logging?component=magicsock&secs=60", nil)
	w := httptest.NewRecorder()

	h.serveComponentDebugLogging(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if componentSeen != "magicsock" {
		t.Errorf("component = %q, want magicsock", componentSeen)
	}

	var result struct {
		Error string
	}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	if result.Error != "" {
		t.Errorf("error = %q, want empty", result.Error)
	}
}

// TestServeComponentDebugLogging_PermissionDenied tests permission check
func TestServeComponentDebugLogging_PermissionDenied(t *testing.T) {
	h := &Handler{
		PermitWrite: false,
		b:           &mockBackendForDebug{},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/component-debug-logging?component=test&secs=30", nil)
	w := httptest.NewRecorder()

	h.serveComponentDebugLogging(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// TestServeComponentDebugLogging_BackendError tests backend error handling
func TestServeComponentDebugLogging_BackendError(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			setComponentDebugLogging: func(component string, until time.Time) error {
				return fmt.Errorf("logging error")
			},
		},
		clock: tstest.Clock{},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/component-debug-logging?component=test&secs=30", nil)
	w := httptest.NewRecorder()

	h.serveComponentDebugLogging(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var result struct {
		Error string
	}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	if result.Error != "logging error" {
		t.Errorf("error = %q, want 'logging error'", result.Error)
	}
}

// TestServeDebugRotateDiscoKey_Success tests successful disco key rotation
func TestServeDebugRotateDiscoKey_Success(t *testing.T) {
	rotateCalled := false

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			debugRotateDiscoKey: func() error {
				rotateCalled = true
				return nil
			},
		},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-rotate-disco-key", nil)
	w := httptest.NewRecorder()

	h.serveDebugRotateDiscoKey(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if !rotateCalled {
		t.Error("DebugRotateDiscoKey was not called")
	}

	body := w.Body.String()
	if body != "done\n" {
		t.Errorf("body = %q, want 'done\\n'", body)
	}
}

// TestServeDebugRotateDiscoKey_PermissionDenied tests permission check
func TestServeDebugRotateDiscoKey_PermissionDenied(t *testing.T) {
	h := &Handler{
		PermitWrite: false,
		b:           &mockBackendForDebug{},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-rotate-disco-key", nil)
	w := httptest.NewRecorder()

	h.serveDebugRotateDiscoKey(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// TestServeDebugRotateDiscoKey_MethodNotAllowed tests POST requirement
func TestServeDebugRotateDiscoKey_MethodNotAllowed(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b:           &mockBackendForDebug{},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-rotate-disco-key", nil)
	w := httptest.NewRecorder()

	h.serveDebugRotateDiscoKey(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// TestServeDebugRotateDiscoKey_BackendError tests backend error
func TestServeDebugRotateDiscoKey_BackendError(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			debugRotateDiscoKey: func() error {
				return fmt.Errorf("rotation failed")
			},
		},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-rotate-disco-key", nil)
	w := httptest.NewRecorder()

	h.serveDebugRotateDiscoKey(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}

	body := w.Body.String()
	if !strings.Contains(body, "rotation failed") {
		t.Errorf("body = %q, want rotation error", body)
	}
}

// TestServeDevSetStateStore_Success tests successful state store set
func TestServeDevSetStateStore_Success(t *testing.T) {
	keySeen := ""
	valueSeen := ""

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			setDevStateStore: func(key, value string) error {
				keySeen = key
				valueSeen = value
				return nil
			},
		},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/dev-set-state-store?key=testkey&value=testvalue", nil)
	w := httptest.NewRecorder()

	h.serveDevSetStateStore(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if keySeen != "testkey" {
		t.Errorf("key = %q, want testkey", keySeen)
	}

	if valueSeen != "testvalue" {
		t.Errorf("value = %q, want testvalue", valueSeen)
	}

	body := w.Body.String()
	if body != "done\n" {
		t.Errorf("body = %q, want 'done\\n'", body)
	}
}

// TestServeDevSetStateStore_PermissionDenied tests permission check
func TestServeDevSetStateStore_PermissionDenied(t *testing.T) {
	h := &Handler{
		PermitWrite: false,
		b:           &mockBackendForDebug{},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/dev-set-state-store?key=test&value=test", nil)
	w := httptest.NewRecorder()

	h.serveDevSetStateStore(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// TestServeDevSetStateStore_MethodNotAllowed tests POST requirement
func TestServeDevSetStateStore_MethodNotAllowed(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b:           &mockBackendForDebug{},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/dev-set-state-store", nil)
	w := httptest.NewRecorder()

	h.serveDevSetStateStore(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// TestServeDevSetStateStore_BackendError tests backend error
func TestServeDevSetStateStore_BackendError(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			setDevStateStore: func(key, value string) error {
				return fmt.Errorf("store error")
			},
		},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/dev-set-state-store?key=test&value=test", nil)
	w := httptest.NewRecorder()

	h.serveDevSetStateStore(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

// TestServeDebugPacketFilterRules_Success tests successful packet filter rules retrieval
func TestServeDebugPacketFilterRules_Success(t *testing.T) {
	testRules := []tailcfg.FilterRule{
		{SrcIPs: []string{"100.64.0.0/10"}},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			netMap: &netmap.NetworkMap{
				PacketFilterRules: testRules,
			},
		},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-packet-filter-rules", nil)
	w := httptest.NewRecorder()

	h.serveDebugPacketFilterRules(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}
}

// TestServeDebugPacketFilterRules_NoNetmap tests nil netmap
func TestServeDebugPacketFilterRules_NoNetmap(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b:           &mockBackendForDebug{},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-packet-filter-rules", nil)
	w := httptest.NewRecorder()

	h.serveDebugPacketFilterRules(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}

	body := w.Body.String()
	if !strings.Contains(body, "no netmap") {
		t.Errorf("body = %q, want no netmap error", body)
	}
}

// TestServeDebugPacketFilterRules_PermissionDenied tests permission check
func TestServeDebugPacketFilterRules_PermissionDenied(t *testing.T) {
	h := &Handler{
		PermitWrite: false,
		b:           &mockBackendForDebug{},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-packet-filter-rules", nil)
	w := httptest.NewRecorder()

	h.serveDebugPacketFilterRules(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// TestServeDebugPacketFilterMatches_Success tests successful packet filter matches retrieval
func TestServeDebugPacketFilterMatches_Success(t *testing.T) {
	testFilter := []tailcfg.FilterRule{
		{SrcIPs: []string{"*"}},
	}

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			netMap: &netmap.NetworkMap{
				PacketFilter: testFilter,
			},
		},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-packet-filter-matches", nil)
	w := httptest.NewRecorder()

	h.serveDebugPacketFilterMatches(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}
}

// TestServeDebugPacketFilterMatches_NoNetmap tests nil netmap
func TestServeDebugPacketFilterMatches_NoNetmap(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b:           &mockBackendForDebug{},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-packet-filter-matches", nil)
	w := httptest.NewRecorder()

	h.serveDebugPacketFilterMatches(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

// TestServeDebugPacketFilterMatches_PermissionDenied tests permission check
func TestServeDebugPacketFilterMatches_PermissionDenied(t *testing.T) {
	h := &Handler{
		PermitWrite: false,
		b:           &mockBackendForDebug{},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-packet-filter-matches", nil)
	w := httptest.NewRecorder()

	h.serveDebugPacketFilterMatches(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// TestServeDebugOptionalFeatures_Success tests optional features endpoint
func TestServeDebugOptionalFeatures_Success(t *testing.T) {
	h := &Handler{
		b: &mockBackendForDebug{},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-optional-features", nil)
	w := httptest.NewRecorder()

	h.serveDebugOptionalFeatures(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}

	// Response should be valid JSON with Features field
	var result struct {
		Features []string
	}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
}

// TestServeDebugLog_InvalidJSON tests invalid JSON body
func TestServeDebugLog_InvalidJSON(t *testing.T) {
	h := &Handler{
		PermitRead: true,
		b:          &mockBackendForDebug{},
		clock:      tstest.Clock{},
		logf:       t.Logf,
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-log", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()

	h.serveDebugLog(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	body := w.Body.String()
	if !strings.Contains(body, "invalid JSON") {
		t.Errorf("body = %q, want invalid JSON error", body)
	}
}

// TestServeDebugLog_Success tests successful log upload
func TestServeDebugLog_Success(t *testing.T) {
	h := &Handler{
		PermitRead: true,
		b:          &mockBackendForDebug{},
		clock:      tstest.Clock{},
		logf:       t.Logf,
	}

	logReq := struct {
		Lines  []string
		Prefix string
	}{
		Lines:  []string{"test log line 1", "test log line 2"},
		Prefix: "test-prefix",
	}

	body, _ := json.Marshal(logReq)
	req := httptest.NewRequest("POST", "/localapi/v0/debug-log", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.serveDebugLog(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNoContent)
	}
}

// TestServeDebugLog_PermissionDenied tests permission check
func TestServeDebugLog_PermissionDenied(t *testing.T) {
	h := &Handler{
		PermitRead: false,
		b:          &mockBackendForDebug{},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug-log", nil)
	w := httptest.NewRecorder()

	h.serveDebugLog(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// TestServeDebugLog_MethodNotAllowed tests POST requirement
func TestServeDebugLog_MethodNotAllowed(t *testing.T) {
	h := &Handler{
		PermitRead: true,
		b:          &mockBackendForDebug{},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-log", nil)
	w := httptest.NewRecorder()

	h.serveDebugLog(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// TestServeDebugLog_DefaultPrefix tests default prefix when not provided
func TestServeDebugLog_DefaultPrefix(t *testing.T) {
	h := &Handler{
		PermitRead: true,
		b:          &mockBackendForDebug{},
		clock:      tstest.Clock{},
		logf:       t.Logf,
	}

	logReq := struct {
		Lines  []string
		Prefix string
	}{
		Lines: []string{"test line"},
		// Prefix intentionally empty
	}

	body, _ := json.Marshal(logReq)
	req := httptest.NewRequest("POST", "/localapi/v0/debug-log", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.serveDebugLog(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNoContent)
	}
}

// TestServeDebugLog_EmptyLines tests empty lines array
func TestServeDebugLog_EmptyLines(t *testing.T) {
	h := &Handler{
		PermitRead: true,
		b:          &mockBackendForDebug{},
		clock:      tstest.Clock{},
		logf:       t.Logf,
	}

	logReq := struct {
		Lines  []string
		Prefix string
	}{
		Lines:  []string{},
		Prefix: "test",
	}

	body, _ := json.Marshal(logReq)
	req := httptest.NewRequest("POST", "/localapi/v0/debug-log", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.serveDebugLog(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNoContent)
	}
}

// TestServeDebug_MissingAction tests missing action parameter
func TestServeDebug_MissingAction(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b:           &mockBackendForDebug{},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug", nil)
	w := httptest.NewRecorder()

	h.serveDebug(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	body := w.Body.String()
	if !strings.Contains(body, "missing parameter 'action'") {
		t.Errorf("body = %q, want missing action error", body)
	}
}

// TestServeDebug_UnknownAction tests unknown action
func TestServeDebug_UnknownAction(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b:           &mockBackendForDebug{},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug?action=unknown-action", nil)
	w := httptest.NewRecorder()

	h.serveDebug(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	body := w.Body.String()
	if !strings.Contains(body, "unknown action") {
		t.Errorf("body = %q, want unknown action error", body)
	}
}

// TestServeDebug_PermissionDenied tests permission check
func TestServeDebug_PermissionDenied(t *testing.T) {
	h := &Handler{
		PermitWrite: false,
		b:           &mockBackendForDebug{},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug?action=rebind", nil)
	w := httptest.NewRecorder()

	h.serveDebug(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// TestServeDebug_MethodNotAllowed tests POST requirement
func TestServeDebug_MethodNotAllowed(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b:           &mockBackendForDebug{},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug", nil)
	w := httptest.NewRecorder()

	h.serveDebug(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// TestServeDebug_RebindAction tests rebind action
func TestServeDebug_RebindAction(t *testing.T) {
	rebindCalled := false

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			debugRebind: func() error {
				rebindCalled = true
				return nil
			},
		},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug?action=rebind", nil)
	w := httptest.NewRecorder()

	h.serveDebug(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if !rebindCalled {
		t.Error("DebugRebind was not called")
	}

	body := w.Body.String()
	if body != "done\n" {
		t.Errorf("body = %q, want 'done\\n'", body)
	}
}

// TestServeDebug_RestunAction tests restun action
func TestServeDebug_RestunAction(t *testing.T) {
	restunCalled := false

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			debugReSTUN: func() error {
				restunCalled = true
				return nil
			},
		},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug?action=restun", nil)
	w := httptest.NewRecorder()

	h.serveDebug(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if !restunCalled {
		t.Error("DebugReSTUN was not called")
	}
}

// TestServeDebug_NotifyAction tests notify action with JSON body
func TestServeDebug_NotifyAction(t *testing.T) {
	var notifySeen *ipn.Notify

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			debugNotify: func(n ipn.Notify) {
				notifySeen = &n
			},
		},
	}

	notify := ipn.Notify{
		State: ptr(ipn.Running),
	}
	body, _ := json.Marshal(notify)

	req := httptest.NewRequest("POST", "/localapi/v0/debug", bytes.NewReader(body))
	req.Header.Set("Debug-Action", "notify")
	w := httptest.NewRecorder()

	h.serveDebug(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if notifySeen == nil {
		t.Fatal("DebugNotify was not called")
	}

	if notifySeen.State == nil || *notifySeen.State != ipn.Running {
		t.Errorf("notify state = %v, want Running", notifySeen.State)
	}
}

// TestServeDebug_NotifyActionInvalidJSON tests notify with invalid JSON
func TestServeDebug_NotifyActionInvalidJSON(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b:           &mockBackendForDebug{},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug", bytes.NewReader([]byte("invalid")))
	req.Header.Set("Debug-Action", "notify")
	w := httptest.NewRecorder()

	h.serveDebug(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestServeDebug_RebindError tests rebind error handling
func TestServeDebug_RebindError(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			debugRebind: func() error {
				return fmt.Errorf("rebind failed")
			},
		},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug?action=rebind", nil)
	w := httptest.NewRecorder()

	h.serveDebug(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	body := w.Body.String()
	if !strings.Contains(body, "rebind failed") {
		t.Errorf("body = %q, want rebind error", body)
	}
}

// TestServeDebug_RotateDiscoKeyAction tests rotate-disco-key action
func TestServeDebug_RotateDiscoKeyAction(t *testing.T) {
	rotateCalled := false

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			debugRotateDiscoKey: func() error {
				rotateCalled = true
				return nil
			},
		},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug?action=rotate-disco-key", nil)
	w := httptest.NewRecorder()

	h.serveDebug(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if !rotateCalled {
		t.Error("DebugRotateDiscoKey was not called")
	}
}

// TestServeDebug_RotateDiscoKeyError tests rotate-disco-key error
func TestServeDebug_RotateDiscoKeyError(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			debugRotateDiscoKey: func() error {
				return fmt.Errorf("rotation error")
			},
		},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/debug?action=rotate-disco-key", nil)
	w := httptest.NewRecorder()

	h.serveDebug(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// ptr is a helper to create a pointer to a value
func ptr[T any](v T) *T {
	return &v
}

// TestDebugEventError_JSON tests debugEventError JSON encoding
func TestDebugEventError_JSON(t *testing.T) {
	err := debugEventError{Error: "test error"}

	data, jsonErr := json.Marshal(err)
	if jsonErr != nil {
		t.Fatalf("failed to marshal: %v", jsonErr)
	}

	var decoded debugEventError
	if jsonErr := json.Unmarshal(data, &decoded); jsonErr != nil {
		t.Fatalf("failed to unmarshal: %v", jsonErr)
	}

	if decoded.Error != "test error" {
		t.Errorf("error = %q, want 'test error'", decoded.Error)
	}
}

// TestServeDebugPeerEndpointChanges_IPv6 tests IPv6 address
func TestServeDebugPeerEndpointChanges_IPv6(t *testing.T) {
	testIP := netip.MustParseAddr("fd7a:115c::1")

	h := &Handler{
		PermitRead: true,
		b: &mockBackendForDebug{
			getEndpointChanges: func(ctx context.Context, ip netip.Addr) (any, error) {
				if ip != testIP {
					t.Errorf("ip = %v, want %v", ip, testIP)
				}
				return map[string]string{"status": "ok"}, nil
			},
		},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-peer-endpoint-changes?ip=fd7a:115c::1", nil)
	w := httptest.NewRecorder()

	h.serveDebugPeerEndpointChanges(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestServeComponentDebugLogging_ZeroSeconds tests zero seconds duration
func TestServeComponentDebugLogging_ZeroSeconds(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b:           &mockBackendForDebug{},
		clock:       tstest.Clock{},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/component-debug-logging?component=test&secs=0", nil)
	w := httptest.NewRecorder()

	h.serveComponentDebugLogging(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestServeComponentDebugLogging_InvalidSeconds tests invalid seconds value
func TestServeComponentDebugLogging_InvalidSeconds(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b:           &mockBackendForDebug{},
		clock:       tstest.Clock{},
	}

	// Invalid secs value should default to 0
	req := httptest.NewRequest("POST", "/localapi/v0/component-debug-logging?component=test&secs=invalid", nil)
	w := httptest.NewRecorder()

	h.serveComponentDebugLogging(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestServeDebugPacketFilterRules_EmptyRules tests empty packet filter rules
func TestServeDebugPacketFilterRules_EmptyRules(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			netMap: &netmap.NetworkMap{
				PacketFilterRules: []tailcfg.FilterRule{},
			},
		},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-packet-filter-rules", nil)
	w := httptest.NewRecorder()

	h.serveDebugPacketFilterRules(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	// Should return valid JSON even for empty rules
	var rules []tailcfg.FilterRule
	if err := json.NewDecoder(w.Body).Decode(&rules); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	if len(rules) != 0 {
		t.Errorf("len(rules) = %d, want 0", len(rules))
	}
}

// TestServeDebugPacketFilterMatches_EmptyFilter tests empty packet filter
func TestServeDebugPacketFilterMatches_EmptyFilter(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			netMap: &netmap.NetworkMap{
				PacketFilter: []tailcfg.FilterRule{},
			},
		},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-packet-filter-matches", nil)
	w := httptest.NewRecorder()

	h.serveDebugPacketFilterMatches(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestServeDebugLog_LargeLogRequest tests large number of log lines
func TestServeDebugLog_LargeLogRequest(t *testing.T) {
	h := &Handler{
		PermitRead: true,
		b:          &mockBackendForDebug{},
		clock:      tstest.Clock{},
		logf:       func(format string, args ...any) {}, // Discard logs
	}

	// Create 100 log lines
	lines := make([]string, 100)
	for i := range lines {
		lines[i] = fmt.Sprintf("log line %d", i)
	}

	logReq := struct {
		Lines  []string
		Prefix string
	}{
		Lines:  lines,
		Prefix: "large-test",
	}

	body, _ := json.Marshal(logReq)
	req := httptest.NewRequest("POST", "/localapi/v0/debug-log", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.serveDebugLog(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNoContent)
	}
}

// TestServeDebugOptionalFeatures_ResponseStructure tests response structure
func TestServeDebugOptionalFeatures_ResponseStructure(t *testing.T) {
	h := &Handler{
		b: &mockBackendForDebug{},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-optional-features", nil)
	w := httptest.NewRecorder()

	h.serveDebugOptionalFeatures(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	// Verify response can be decoded
	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Should have Features field
	if _, ok := response["Features"]; !ok {
		t.Error("response missing 'Features' field")
	}
}

// TestServeDevSetStateStore_EmptyValue tests empty value parameter
func TestServeDevSetStateStore_EmptyValue(t *testing.T) {
	keySeen := ""
	valueSeen := "not-empty"

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			setDevStateStore: func(key, value string) error {
				keySeen = key
				valueSeen = value
				return nil
			},
		},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/dev-set-state-store?key=testkey&value=", nil)
	w := httptest.NewRecorder()

	h.serveDevSetStateStore(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if keySeen != "testkey" {
		t.Errorf("key = %q, want testkey", keySeen)
	}

	if valueSeen != "" {
		t.Errorf("value = %q, want empty", valueSeen)
	}
}

// TestServeDebugPeerEndpointChanges_ContextCancellation tests context cancellation
func TestServeDebugPeerEndpointChanges_ContextCancellation(t *testing.T) {
	h := &Handler{
		PermitRead: true,
		b: &mockBackendForDebug{
			getEndpointChanges: func(ctx context.Context, ip netip.Addr) (any, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := httptest.NewRequest("GET", "/localapi/v0/debug-peer-endpoint-changes?ip=100.64.0.1", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.serveDebugPeerEndpointChanges(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d (context cancelled)", w.Code, http.StatusInternalServerError)
	}
}

// TestServeDebugLog_MultilineMessages tests log lines with newlines
func TestServeDebugLog_MultilineMessages(t *testing.T) {
	h := &Handler{
		PermitRead: true,
		b:          &mockBackendForDebug{},
		clock:      tstest.Clock{},
		logf:       t.Logf,
	}

	logReq := struct {
		Lines  []string
		Prefix string
	}{
		Lines: []string{
			"line 1\nwith newline",
			"line 2\twith tab",
			"line 3 normal",
		},
		Prefix: "multiline-test",
	}

	body, _ := json.Marshal(logReq)
	req := httptest.NewRequest("POST", "/localapi/v0/debug-log", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.serveDebugLog(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNoContent)
	}
}

// TestServeDebugRotateDiscoKey_MultipleRotations tests multiple sequential rotations
func TestServeDebugRotateDiscoKey_MultipleRotations(t *testing.T) {
	rotateCount := 0

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			debugRotateDiscoKey: func() error {
				rotateCount++
				return nil
			},
		},
	}

	// Rotate 3 times
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/localapi/v0/debug-rotate-disco-key", nil)
		w := httptest.NewRecorder()

		h.serveDebugRotateDiscoKey(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("rotation %d: status = %d, want %d", i, w.Code, http.StatusOK)
		}
	}

	if rotateCount != 3 {
		t.Errorf("rotateCount = %d, want 3", rotateCount)
	}
}

// TestServeComponentDebugLogging_EmptyComponent tests empty component name
func TestServeComponentDebugLogging_EmptyComponent(t *testing.T) {
	componentSeen := "not-empty"

	h := &Handler{
		PermitWrite: true,
		b: &mockBackendForDebug{
			setComponentDebugLogging: func(component string, until time.Time) error {
				componentSeen = component
				return nil
			},
		},
		clock: tstest.Clock{},
	}

	req := httptest.NewRequest("POST", "/localapi/v0/component-debug-logging?component=&secs=30", nil)
	w := httptest.NewRecorder()

	h.serveComponentDebugLogging(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if componentSeen != "" {
		t.Errorf("component = %q, want empty", componentSeen)
	}
}

// TestServeDebugPeerEndpointChanges_NilResult tests nil result from backend
func TestServeDebugPeerEndpointChanges_NilResult(t *testing.T) {
	h := &Handler{
		PermitRead: true,
		b: &mockBackendForDebug{
			getEndpointChanges: func(ctx context.Context, ip netip.Addr) (any, error) {
				return nil, nil
			},
		},
	}

	req := httptest.NewRequest("GET", "/localapi/v0/debug-peer-endpoint-changes?ip=100.64.0.1", nil)
	w := httptest.NewRecorder()

	h.serveDebugPeerEndpointChanges(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	// Should encode null in JSON
	body := w.Body.String()
	if !strings.Contains(body, "null") {
		t.Errorf("body = %q, want null", body)
	}
}
