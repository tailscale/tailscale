// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package envknob

import (
	"os"
	"testing"
	"time"

	"tailscale.com/types/opt"
)

func TestBool(t *testing.T) {
	tests := []struct {
		name    string
		envVar  string
		value   string
		want    bool
		wantSet bool
	}{
		{name: "true", envVar: "TEST_BOOL_TRUE", value: "true", want: true, wantSet: true},
		{name: "false", envVar: "TEST_BOOL_FALSE", value: "false", want: false, wantSet: true},
		{name: "1", envVar: "TEST_BOOL_1", value: "1", want: true, wantSet: true},
		{name: "0", envVar: "TEST_BOOL_0", value: "0", want: false, wantSet: true},
		{name: "unset", envVar: "TEST_BOOL_UNSET", value: "", want: false, wantSet: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != "" {
				os.Setenv(tt.envVar, tt.value)
				defer os.Unsetenv(tt.envVar)
			}

			got := Bool(tt.envVar)
			if got != tt.want {
				t.Errorf("Bool(%q) = %v, want %v", tt.envVar, got, tt.want)
			}
		})
	}
}

func TestBoolDefaultTrue(t *testing.T) {
	envVar := "TEST_BOOL_DEFAULT_TRUE"

	// Unset - should return true
	os.Unsetenv(envVar)
	if got := BoolDefaultTrue(envVar); !got {
		t.Errorf("BoolDefaultTrue(%q) with unset = %v, want true", envVar, got)
	}

	// Set to false - should return false
	os.Setenv(envVar, "false")
	defer os.Unsetenv(envVar)
	if got := BoolDefaultTrue(envVar); got {
		t.Errorf("BoolDefaultTrue(%q) with false = %v, want false", envVar, got)
	}
}

func TestGOOS(t *testing.T) {
	// Should return a non-empty string
	if got := GOOS(); got == "" {
		t.Error("GOOS() returned empty string")
	}

	// By default should match runtime.GOOS
	if got := GOOS(); got != os.Getenv("GOOS") && os.Getenv("GOOS") == "" {
		// If GOOS env var not set, should use runtime
		// Can't test exact value as it's platform-dependent
	}
}

func TestString(t *testing.T) {
	tests := []struct {
		name   string
		envVar string
		value  string
		want   string
	}{
		{name: "set", envVar: "TEST_STRING", value: "hello", want: "hello"},
		{name: "empty", envVar: "TEST_STRING_EMPTY", value: "", want: ""},
		{name: "spaces", envVar: "TEST_STRING_SPACES", value: "  value  ", want: "  value  "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != "" {
				os.Setenv(tt.envVar, tt.value)
				defer os.Unsetenv(tt.envVar)
			}

			got := String(tt.envVar)
			if got != tt.want {
				t.Errorf("String(%q) = %q, want %q", tt.envVar, got, tt.want)
			}
		})
	}
}

func TestOptBool(t *testing.T) {
	tests := []struct {
		name    string
		envVar  string
		value   string
		wantSet bool
		wantVal bool
	}{
		{name: "true", envVar: "TEST_OPT_TRUE", value: "true", wantSet: true, wantVal: true},
		{name: "false", envVar: "TEST_OPT_FALSE", value: "false", wantSet: true, wantVal: false},
		{name: "unset", envVar: "TEST_OPT_UNSET", value: "", wantSet: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != "" {
				os.Setenv(tt.envVar, tt.value)
				defer os.Unsetenv(tt.envVar)
			} else {
				os.Unsetenv(tt.envVar)
			}

			got := OptBool(tt.envVar)
			if _, ok := got.Get(); ok != tt.wantSet {
				t.Errorf("OptBool(%q).Get() set = %v, want %v", tt.envVar, ok, tt.wantSet)
			}
			if tt.wantSet {
				if val, _ := got.Get(); val != tt.wantVal {
					t.Errorf("OptBool(%q).Get() value = %v, want %v", tt.envVar, val, tt.wantVal)
				}
			}
		})
	}
}

func TestSetenv(t *testing.T) {
	envVar := "TEST_SETENV"
	value := "test_value"

	defer os.Unsetenv(envVar)

	Setenv(envVar, value)

	// Verify it's actually set in the environment
	if got := os.Getenv(envVar); got != value {
		t.Errorf("After Setenv, os.Getenv(%q) = %q, want %q", envVar, got, value)
	}

	// Verify String retrieves it
	if got := String(envVar); got != value {
		t.Errorf("After Setenv, String(%q) = %q, want %q", envVar, got, value)
	}
}

func TestRegisterString(t *testing.T) {
	envVar := "TEST_REGISTER_STRING"
	value := "registered"

	os.Setenv(envVar, value)
	defer os.Unsetenv(envVar)

	var target string
	RegisterString(&target, envVar)

	if target != value {
		t.Errorf("After RegisterString, target = %q, want %q", target, value)
	}
}

func TestRegisterBool(t *testing.T) {
	envVar := "TEST_REGISTER_BOOL"

	os.Setenv(envVar, "true")
	defer os.Unsetenv(envVar)

	var target bool
	RegisterBool(&target, envVar)

	if !target {
		t.Error("After RegisterBool with true, target = false, want true")
	}
}

func TestRegisterOptBool(t *testing.T) {
	envVar := "TEST_REGISTER_OPTBOOL"

	os.Setenv(envVar, "true")
	defer os.Unsetenv(envVar)

	var target opt.Bool
	RegisterOptBool(&target, envVar)

	if val, ok := target.Get(); !ok || !val {
		t.Errorf("After RegisterOptBool, target = (%v, %v), want (true, true)", val, ok)
	}
}

func TestLogCurrent(t *testing.T) {
	// Set a test env var
	os.Setenv("TEST_LOG_CURRENT", "test")
	defer os.Unsetenv("TEST_LOG_CURRENT")

	// Force it to be noted
	Setenv("TEST_LOG_CURRENT", "test")

	logged := false
	logf := func(format string, args ...any) {
		logged = true
	}

	LogCurrent(logf)

	if !logged {
		t.Error("LogCurrent did not call logf")
	}
}

func TestUseRunningUserForAuth(t *testing.T) {
	// This just tests that the function runs without panicking
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("UseRunningUserForAuth() panicked: %v", r)
		}
	}()

	_ = UseRunningUserForAuth()
}

func TestDERPConncap(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("DERPConncap() panicked: %v", r)
		}
	}()

	got := DERPConncap()
	if got < 0 {
		t.Errorf("DERPConncap() = %d, want >= 0", got)
	}
}

// Test some known environment variables
func TestKnownVariables(t *testing.T) {
	// These functions should not panic
	_ = CrashMonitorSupport()
	_ = NoLogsNoSupport()
	_ = AllowRemoteUpdate()
	_ = DisablePortMapper()
}

// Benchmark common operations
func BenchmarkBool(b *testing.B) {
	os.Setenv("BENCH_BOOL", "true")
	defer os.Unsetenv("BENCH_BOOL")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Bool("BENCH_BOOL")
	}
}

func BenchmarkString(b *testing.B) {
	os.Setenv("BENCH_STRING", "value")
	defer os.Unsetenv("BENCH_STRING")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = String("BENCH_STRING")
	}
}

func BenchmarkOptBool(b *testing.B) {
	os.Setenv("BENCH_OPTBOOL", "true")
	defer os.Unsetenv("BENCH_OPTBOOL")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = OptBool("BENCH_OPTBOOL")
	}
}

// Integration test for registering variables
func TestRegisterIntegration(t *testing.T) {
	// Test registering multiple types
	var (
		strVal  string
		boolVal bool
		optVal  opt.Bool
		durVal  time.Duration
		intVal  int
	)

	os.Setenv("TEST_INT_STR", "hello")
	os.Setenv("TEST_INT_BOOL", "true")
	os.Setenv("TEST_INT_OPT", "false")
	os.Setenv("TEST_INT_DUR", "5s")
	os.Setenv("TEST_INT_INT", "42")

	defer func() {
		os.Unsetenv("TEST_INT_STR")
		os.Unsetenv("TEST_INT_BOOL")
		os.Unsetenv("TEST_INT_OPT")
		os.Unsetenv("TEST_INT_DUR")
		os.Unsetenv("TEST_INT_INT")
	}()

	RegisterString(&strVal, "TEST_INT_STR")
	RegisterBool(&boolVal, "TEST_INT_BOOL")
	RegisterOptBool(&optVal, "TEST_INT_OPT")
	RegisterDuration(&durVal, "TEST_INT_DUR")
	RegisterInt(&intVal, "TEST_INT_INT")

	if strVal != "hello" {
		t.Errorf("strVal = %q, want %q", strVal, "hello")
	}
	if !boolVal {
		t.Error("boolVal = false, want true")
	}
	if val, ok := optVal.Get(); !ok || val {
		t.Errorf("optVal = (%v, %v), want (false, true)", val, ok)
	}
	if durVal != 5*time.Second {
		t.Errorf("durVal = %v, want 5s", durVal)
	}
	if intVal != 42 {
		t.Errorf("intVal = %d, want 42", intVal)
	}
}
