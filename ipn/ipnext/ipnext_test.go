// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnext

import (
	"errors"
	"fmt"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tsd"
	"tailscale.com/tstime"
	"tailscale.com/types/logger"
)

// mockExtension implements Extension for testing
type mockExtension struct {
	name         string
	initErr      error
	shutdownErr  error
	initCalled   bool
	shutdownCalled bool
}

func (m *mockExtension) Name() string { return m.name }

func (m *mockExtension) Init(Host) error {
	m.initCalled = true
	return m.initErr
}

func (m *mockExtension) Shutdown() error {
	m.shutdownCalled = true
	return m.shutdownErr
}

// mockSafeBackend implements SafeBackend for testing
type mockSafeBackend struct{}

func (m *mockSafeBackend) Sys() *tsd.System              { return nil }
func (m *mockSafeBackend) Clock() tstime.Clock           { return nil }
func (m *mockSafeBackend) TailscaleVarRoot() string      { return "/tmp" }

// TestDefinition_Name tests Definition.Name()
func TestDefinition_Name(t *testing.T) {
	d := &Definition{name: "test-extension"}
	if got := d.Name(); got != "test-extension" {
		t.Errorf("Name() = %q, want %q", got, "test-extension")
	}
}

// TestDefinition_MakeExtension tests successful extension creation
func TestDefinition_MakeExtension(t *testing.T) {
	ext := &mockExtension{name: "test"}
	newFn := func(logger.Logf, SafeBackend) (Extension, error) {
		return ext, nil
	}

	d := &Definition{
		name:  "test",
		newFn: newFn,
	}

	logf := logger.Discard
	sb := &mockSafeBackend{}

	got, err := d.MakeExtension(logf, sb)
	if err != nil {
		t.Fatalf("MakeExtension() error = %v", err)
	}

	if got != ext {
		t.Error("MakeExtension() returned wrong extension")
	}
}

// TestDefinition_MakeExtension_NameMismatch tests name validation
func TestDefinition_MakeExtension_NameMismatch(t *testing.T) {
	ext := &mockExtension{name: "wrong-name"}
	newFn := func(logger.Logf, SafeBackend) (Extension, error) {
		return ext, nil
	}

	d := &Definition{
		name:  "expected-name",
		newFn: newFn,
	}

	logf := logger.Discard
	sb := &mockSafeBackend{}

	_, err := d.MakeExtension(logf, sb)
	if err == nil {
		t.Fatal("MakeExtension() should error on name mismatch")
	}

	wantErr := `extension name mismatch: registered "expected-name"; actual "wrong-name"`
	if err.Error() != wantErr {
		t.Errorf("error = %q, want %q", err.Error(), wantErr)
	}
}

// TestDefinition_MakeExtension_NewFnError tests error propagation
func TestDefinition_MakeExtension_NewFnError(t *testing.T) {
	expectedErr := errors.New("creation failed")
	newFn := func(logger.Logf, SafeBackend) (Extension, error) {
		return nil, expectedErr
	}

	d := &Definition{
		name:  "test",
		newFn: newFn,
	}

	logf := logger.Discard
	sb := &mockSafeBackend{}

	_, err := d.MakeExtension(logf, sb)
	if !errors.Is(err, expectedErr) {
		t.Errorf("MakeExtension() error = %v, want %v", err, expectedErr)
	}
}

// TestRegisterExtension_Panic_NilFunc tests nil function panic
func TestRegisterExtension_Panic_NilFunc(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("RegisterExtension() should panic with nil function")
		} else {
			got := fmt.Sprint(r)
			want := `ipnext: newExt is nil: "test"`
			if got != want {
				t.Errorf("panic message = %q, want %q", got, want)
			}
		}
		// Reset extensions map after test
		extensions = extensions[:0]
	}()

	RegisterExtension("test", nil)
}

// TestRegisterExtension_Panic_Duplicate tests duplicate name panic
func TestRegisterExtension_Panic_Duplicate(t *testing.T) {
	defer func() {
		// Reset extensions map after test
		extensions = extensions[:0]
	}()

	newFn := func(logger.Logf, SafeBackend) (Extension, error) {
		return &mockExtension{name: "test"}, nil
	}

	// First registration should succeed
	RegisterExtension("test", newFn)

	// Second registration should panic
	defer func() {
		if r := recover(); r == nil {
			t.Error("RegisterExtension() should panic on duplicate")
		} else {
			got := fmt.Sprint(r)
			want := `ipnext: duplicate extension name "test"`
			if got != want {
				t.Errorf("panic message = %q, want %q", got, want)
			}
		}
	}()

	RegisterExtension("test", newFn)
}

// TestRegisterExtension_Success tests successful registration
func TestRegisterExtension_Success(t *testing.T) {
	defer func() {
		extensions = extensions[:0]
	}()

	newFn := func(logger.Logf, SafeBackend) (Extension, error) {
		return &mockExtension{name: "test"}, nil
	}

	RegisterExtension("test", newFn)

	if !extensions.Contains("test") {
		t.Error("extension not registered")
	}

	def, ok := extensions.Get("test")
	if !ok {
		t.Fatal("failed to get registered extension")
	}

	if def.name != "test" {
		t.Errorf("registered name = %q, want %q", def.name, "test")
	}
}

// TestExtensions_Iterator tests Extensions() iteration
func TestExtensions_Iterator(t *testing.T) {
	defer func() {
		extensions = extensions[:0]
	}()

	newFn := func(name string) NewExtensionFn {
		return func(logger.Logf, SafeBackend) (Extension, error) {
			return &mockExtension{name: name}, nil
		}
	}

	RegisterExtension("ext1", newFn("ext1"))
	RegisterExtension("ext2", newFn("ext2"))
	RegisterExtension("ext3", newFn("ext3"))

	count := 0
	seen := make(map[string]bool)

	for def := range Extensions() {
		count++
		seen[def.name] = true
	}

	if count != 3 {
		t.Errorf("Extensions() count = %d, want 3", count)
	}

	for _, name := range []string{"ext1", "ext2", "ext3"} {
		if !seen[name] {
			t.Errorf("extension %q not seen in iteration", name)
		}
	}
}

// TestExtensions_Order tests iteration order preservation
func TestExtensions_Order(t *testing.T) {
	defer func() {
		extensions = extensions[:0]
	}()

	newFn := func(name string) NewExtensionFn {
		return func(logger.Logf, SafeBackend) (Extension, error) {
			return &mockExtension{name: name}, nil
		}
	}

	RegisterExtension("first", newFn("first"))
	RegisterExtension("second", newFn("second"))
	RegisterExtension("third", newFn("third"))

	var order []string
	for def := range Extensions() {
		order = append(order, def.name)
	}

	want := []string{"first", "second", "third"}
	if len(order) != len(want) {
		t.Fatalf("order length = %d, want %d", len(order), len(want))
	}

	for i, name := range want {
		if order[i] != name {
			t.Errorf("order[%d] = %q, want %q", i, order[i], name)
		}
	}
}

// TestDefinitionForTest tests test helper
func TestDefinitionForTest(t *testing.T) {
	ext := &mockExtension{name: "test-ext"}
	def := DefinitionForTest(ext)

	if def.name != "test-ext" {
		t.Errorf("name = %q, want %q", def.name, "test-ext")
	}

	logf := logger.Discard
	sb := &mockSafeBackend{}

	got, err := def.MakeExtension(logf, sb)
	if err != nil {
		t.Fatalf("MakeExtension() error = %v", err)
	}

	if got != ext {
		t.Error("MakeExtension() returned wrong extension")
	}
}

// TestDefinitionWithErrForTest tests error test helper
func TestDefinitionWithErrForTest(t *testing.T) {
	expectedErr := errors.New("test error")
	def := DefinitionWithErrForTest("error-ext", expectedErr)

	if def.name != "error-ext" {
		t.Errorf("name = %q, want %q", def.name, "error-ext")
	}

	logf := logger.Discard
	sb := &mockSafeBackend{}

	_, err := def.MakeExtension(logf, sb)
	if !errors.Is(err, expectedErr) {
		t.Errorf("MakeExtension() error = %v, want %v", err, expectedErr)
	}
}

// TestSkipExtension_Error tests SkipExtension error
func TestSkipExtension_Error(t *testing.T) {
	if SkipExtension == nil {
		t.Fatal("SkipExtension should not be nil")
	}

	want := "skipping extension"
	if SkipExtension.Error() != want {
		t.Errorf("SkipExtension.Error() = %q, want %q", SkipExtension.Error(), want)
	}
}

// TestSkipExtension_Wrapped tests wrapped SkipExtension
func TestSkipExtension_Wrapped(t *testing.T) {
	wrapped := fmt.Errorf("platform not supported: %w", SkipExtension)

	if !errors.Is(wrapped, SkipExtension) {
		t.Error("wrapped error should be SkipExtension")
	}
}

// TestMockExtension_Interface tests mock implements Extension
func TestMockExtension_Interface(t *testing.T) {
	var _ Extension = (*mockExtension)(nil)
}

// TestMockExtension_Init tests Init tracking
func TestMockExtension_Init(t *testing.T) {
	ext := &mockExtension{name: "test"}

	if ext.initCalled {
		t.Error("initCalled should be false initially")
	}

	err := ext.Init(nil)
	if err != nil {
		t.Errorf("Init() error = %v", err)
	}

	if !ext.initCalled {
		t.Error("initCalled should be true after Init()")
	}
}

// TestMockExtension_InitError tests Init error
func TestMockExtension_InitError(t *testing.T) {
	expectedErr := errors.New("init failed")
	ext := &mockExtension{
		name:    "test",
		initErr: expectedErr,
	}

	err := ext.Init(nil)
	if !errors.Is(err, expectedErr) {
		t.Errorf("Init() error = %v, want %v", err, expectedErr)
	}

	if !ext.initCalled {
		t.Error("initCalled should be true even on error")
	}
}

// TestMockExtension_Shutdown tests Shutdown tracking
func TestMockExtension_Shutdown(t *testing.T) {
	ext := &mockExtension{name: "test"}

	if ext.shutdownCalled {
		t.Error("shutdownCalled should be false initially")
	}

	err := ext.Shutdown()
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}

	if !ext.shutdownCalled {
		t.Error("shutdownCalled should be true after Shutdown()")
	}
}

// TestMockExtension_ShutdownError tests Shutdown error
func TestMockExtension_ShutdownError(t *testing.T) {
	expectedErr := errors.New("shutdown failed")
	ext := &mockExtension{
		name:        "test",
		shutdownErr: expectedErr,
	}

	err := ext.Shutdown()
	if !errors.Is(err, expectedErr) {
		t.Errorf("Shutdown() error = %v, want %v", err, expectedErr)
	}

	if !ext.shutdownCalled {
		t.Error("shutdownCalled should be true even on error")
	}
}

// TestMockSafeBackend_Interface tests mock implements SafeBackend
func TestMockSafeBackend_Interface(t *testing.T) {
	var _ SafeBackend = (*mockSafeBackend)(nil)
}

// TestMockSafeBackend_Methods tests SafeBackend methods
func TestMockSafeBackend_Methods(t *testing.T) {
	sb := &mockSafeBackend{}

	if sb.Sys() != nil {
		t.Error("Sys() should return nil")
	}

	if sb.Clock() != nil {
		t.Error("Clock() should return nil")
	}

	if sb.TailscaleVarRoot() != "/tmp" {
		t.Errorf("TailscaleVarRoot() = %q, want /tmp", sb.TailscaleVarRoot())
	}
}

// TestHooks_ZeroValue tests Hooks zero value
func TestHooks_ZeroValue(t *testing.T) {
	var h Hooks

	// Verify all hooks are zero-valued and usable
	_ = h.BackendStateChange
	_ = h.ProfileStateChange
	_ = h.BackgroundProfileResolvers
	_ = h.AuditLoggers
	_ = h.NewControlClient
	_ = h.OnSelfChange
	_ = h.MutateNotifyLocked
	_ = h.SetPeerStatus
	_ = h.ShouldUploadServices
}

// TestProfileStateChangeCallback_Type tests callback signature
func TestProfileStateChangeCallback_Type(t *testing.T) {
	var callback ProfileStateChangeCallback = func(p ipn.LoginProfileView, pr ipn.PrefsView, sameNode bool) {
		// Callback implementation
		_ = p
		_ = pr
		_ = sameNode
	}

	if callback == nil {
		t.Error("callback should not be nil")
	}

	// Test calling the callback
	callback(ipn.LoginProfileView{}, ipn.PrefsView{}, true)
}

// TestNewExtensionFn_Type tests function type
func TestNewExtensionFn_Type(t *testing.T) {
	var fn NewExtensionFn = func(logger.Logf, SafeBackend) (Extension, error) {
		return &mockExtension{name: "test"}, nil
	}

	if fn == nil {
		t.Error("fn should not be nil")
	}

	ext, err := fn(logger.Discard, &mockSafeBackend{})
	if err != nil {
		t.Fatalf("fn() error = %v", err)
	}

	if ext.Name() != "test" {
		t.Errorf("extension name = %q, want %q", ext.Name(), "test")
	}
}

// TestAuditLogProvider_Type tests provider type
func TestAuditLogProvider_Type(t *testing.T) {
	var provider AuditLogProvider = func() ipnauth.AuditLogFunc {
		return func(*ipnauth.AuditLogEntry) error {
			return nil
		}
	}

	if provider == nil {
		t.Error("provider should not be nil")
	}

	fn := provider()
	if fn == nil {
		t.Error("audit log func should not be nil")
	}

	err := fn(&ipnauth.AuditLogEntry{})
	if err != nil {
		t.Errorf("audit log func error = %v", err)
	}
}

// TestProfileResolver_Type tests resolver type
func TestProfileResolver_Type(t *testing.T) {
	var resolver ProfileResolver = func(ps ProfileStore) ipn.LoginProfileView {
		return ps.CurrentProfile()
	}

	if resolver == nil {
		t.Error("resolver should not be nil")
	}
}

// TestExtensions_EmptyMap tests empty extensions map
func TestExtensions_EmptyMap(t *testing.T) {
	defer func() {
		extensions = extensions[:0]
	}()

	// Reset to empty
	extensions = extensions[:0]

	count := 0
	for range Extensions() {
		count++
	}

	if count != 0 {
		t.Errorf("empty Extensions() should yield 0 items, got %d", count)
	}
}

// TestDefinition_NilNewFn tests nil newFn handling
func TestDefinition_NilNewFn(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			// MakeExtension might panic on nil newFn
			t.Logf("panic (expected): %v", r)
		}
	}()

	d := &Definition{
		name:  "test",
		newFn: nil,
	}

	// This should panic or error
	_, err := d.MakeExtension(logger.Discard, &mockSafeBackend{})
	if err == nil {
		t.Error("MakeExtension() with nil newFn should fail")
	}
}

// TestMultipleExtensions_Registration tests multiple extensions
func TestMultipleExtensions_Registration(t *testing.T) {
	defer func() {
		extensions = extensions[:0]
	}()

	names := []string{"ext-a", "ext-b", "ext-c", "ext-d", "ext-e"}

	for _, name := range names {
		n := name // capture
		newFn := func(logger.Logf, SafeBackend) (Extension, error) {
			return &mockExtension{name: n}, nil
		}
		RegisterExtension(n, newFn)
	}

	if extensions.Len() != 5 {
		t.Errorf("extensions count = %d, want 5", extensions.Len())
	}

	for _, name := range names {
		if !extensions.Contains(name) {
			t.Errorf("extension %q not registered", name)
		}
	}
}
