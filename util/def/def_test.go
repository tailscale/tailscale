// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package def_test

import (
	"os"
	"strconv"
	"testing"
	"time"

	"tailscale.com/util/def"
)

func TestBool(t *testing.T) {
	tests := []struct {
		name string
		in   string
		def  bool
		want bool
	}{
		{name: "empty_true", in: "", def: true, want: true},
		{name: "empty_false", in: "", def: false, want: false},
		{name: "valid_1", in: "1", def: false, want: true},
		{name: "valid_t", in: "t", def: false, want: true},
		{name: "valid_T", in: "T", def: false, want: true},
		{name: "valid_TRUE", in: "TRUE", def: false, want: true},
		{name: "valid_true", in: "true", def: false, want: true},
		{name: "valid_True", in: "True", def: false, want: true},
		{name: "valid_true_default_true", in: "true", def: true, want: true},
		{name: "valid_0", in: "0", def: true, want: false},
		{name: "valid_f", in: "f", def: true, want: false},
		{name: "valid_F", in: "F", def: true, want: false},
		{name: "valid_FALSE", in: "FALSE", def: true, want: false},
		{name: "valid_false", in: "false", def: true, want: false},
		{name: "valid_False", in: "False", def: true, want: false},
		{name: "valid_false_default_false", in: "false", def: false, want: false},
		{name: "invalid_true", in: "sure", def: true, want: true},
		{name: "invalid_false", in: "sure", def: false, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := def.Bool(tt.in, tt.def); got != tt.want {
				t.Errorf("Bool(%q, %v) = %v; want %v", tt.in, tt.def, got, tt.want)
			}
		})
	}
}

func TestDuration(t *testing.T) {
	tests := []struct {
		name string
		in   string
		def  time.Duration
		want time.Duration
	}{
		{name: "empty_second", in: "", def: time.Second, want: time.Second},
		{name: "empty_zero", in: "", def: 0, want: 0},
		{name: "valid", in: "2m30s", def: time.Second, want: 2*time.Minute + 30*time.Second},
		{name: "valid_zero", in: "0s", def: time.Second, want: 0},
		{name: "invalid_second", in: "soon", def: time.Second, want: time.Second},
		{name: "invalid_minute", in: "soon", def: time.Minute, want: time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := def.Duration(tt.in, tt.def); got != tt.want {
				t.Errorf("Duration(%q, %v) = %v; want %v", tt.in, tt.def, got, tt.want)
			}
		})
	}
}

func TestEnv(t *testing.T) {
	const key = "TS_DEF_TEST_ENV"
	t.Run("unset", func(t *testing.T) {
		os.Unsetenv(key)
		if got := def.Env(key, "fallback"); got != "fallback" {
			t.Errorf("Env(unset) = %q; want %q", got, "fallback")
		}
	})
	t.Run("set", func(t *testing.T) {
		t.Setenv(key, "value")
		if got := def.Env(key, "fallback"); got != "value" {
			t.Errorf("Env(set) = %q; want %q", got, "value")
		}
	})
	t.Run("set_empty", func(t *testing.T) {
		t.Setenv(key, "")
		if got := def.Env(key, "fallback"); got != "" {
			t.Errorf("Env(set empty) = %q; want %q", got, "")
		}
	})
}

func TestEnvs(t *testing.T) {
	const k1, k2 = "TS_DEF_TEST_ENVS_1", "TS_DEF_TEST_ENVS_2"
	t.Run("none_set", func(t *testing.T) {
		os.Unsetenv(k1)
		os.Unsetenv(k2)
		if got := def.Envs([]string{k1, k2}, "fallback"); got != "fallback" {
			t.Errorf("Envs(none set) = %q; want %q", got, "fallback")
		}
	})
	t.Run("first_set_wins", func(t *testing.T) {
		t.Setenv(k1, "first")
		t.Setenv(k2, "second")
		if got := def.Envs([]string{k1, k2}, "fallback"); got != "first" {
			t.Errorf("Envs(both set) = %q; want %q", got, "first")
		}
	})
	t.Run("second_set", func(t *testing.T) {
		os.Unsetenv(k1)
		t.Setenv(k2, "second")
		if got := def.Envs([]string{k1, k2}, "fallback"); got != "second" {
			t.Errorf("Envs(second set) = %q; want %q", got, "second")
		}
	})
}

func TestEnvBool(t *testing.T) {
	const key = "TS_DEF_TEST_ENV_BOOL"
	tests := []struct {
		name string
		set  bool
		val  string
		def  bool
		want bool
	}{
		{name: "unset_true", set: false, def: true, want: true},
		{name: "unset_false", set: false, def: false, want: false},
		{name: "empty_true", set: true, val: "", def: true, want: true},
		{name: "valid_true", set: true, val: "true", def: false, want: true},
		{name: "valid_false", set: true, val: "false", def: true, want: false},
		{name: "invalid_true", set: true, val: "sure", def: true, want: true},
		{name: "invalid_false", set: true, val: "sure", def: false, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set {
				t.Setenv(key, tt.val)
			} else {
				os.Unsetenv(key)
			}
			if got := def.EnvBool(key, tt.def); got != tt.want {
				t.Errorf("EnvBool(%q=%q, %v) = %v; want %v", key, tt.val, tt.def, got, tt.want)
			}
		})
	}
}

func TestEnvStringPointer(t *testing.T) {
	const key = "TS_DEF_TEST_ENV_STR_PTR"
	t.Run("unset", func(t *testing.T) {
		os.Unsetenv(key)
		if got := def.EnvStringPointer(key); got != nil {
			t.Errorf("EnvStringPointer(unset) = %v; want nil", *got)
		}
	})
	t.Run("set", func(t *testing.T) {
		t.Setenv(key, "value")
		got := def.EnvStringPointer(key)
		if got == nil || *got != "value" {
			t.Errorf("EnvStringPointer(set) = %v; want pointer to %q", got, "value")
		}
	})
	t.Run("set_empty", func(t *testing.T) {
		t.Setenv(key, "")
		got := def.EnvStringPointer(key)
		if got == nil || *got != "" {
			t.Errorf("EnvStringPointer(set empty) = %v; want pointer to %q", got, "")
		}
	})
}

func TestEnvBoolPointer(t *testing.T) {
	const key = "TS_DEF_TEST_ENV_BOOL_PTR"
	t.Run("unset", func(t *testing.T) {
		os.Unsetenv(key)
		if got := def.EnvBoolPointer(key); got != nil {
			t.Errorf("EnvBoolPointer(unset) = %v; want nil", *got)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		t.Setenv(key, "sure")
		if got := def.EnvBoolPointer(key); got != nil {
			t.Errorf("EnvBoolPointer(invalid) = %v; want nil", *got)
		}
	})
	t.Run("valid_true", func(t *testing.T) {
		t.Setenv(key, "true")
		got := def.EnvBoolPointer(key)
		if got == nil || *got != true {
			t.Errorf("EnvBoolPointer(true) = %v; want pointer to true", got)
		}
	})
	t.Run("valid_false", func(t *testing.T) {
		t.Setenv(key, "false")
		got := def.EnvBoolPointer(key)
		if got == nil || *got != false {
			t.Errorf("EnvBoolPointer(false) = %v; want pointer to false", got)
		}
	})
}

func FuzzBool(f *testing.F) {
	for _, tc := range []struct {
		in  string
		def bool
	}{
		{in: "", def: true},
		{in: "", def: false},
		{in: "true", def: false},
		{in: "false", def: true},
		{in: "sure", def: true},
		{in: "sure", def: false},
	} {
		f.Add(tc.in, tc.def)
	}
	f.Fuzz(func(t *testing.T, in string, fallback bool) {
		got := def.Bool(in, fallback)
		want, err := strconv.ParseBool(in)
		if in == "" || err != nil {
			want = fallback
		}
		if got != want {
			t.Fatalf("Bool(%q, %v) = %v; want %v", in, fallback, got, want)
		}
	})
}

func FuzzDuration(f *testing.F) {
	for _, tc := range []struct {
		in  string
		def time.Duration
	}{
		{in: "", def: time.Second},
		{in: "", def: 0},
		{in: "2m30s", def: time.Second},
		{in: "soon", def: time.Second},
	} {
		f.Add(tc.in, int64(tc.def))
	}
	f.Fuzz(func(t *testing.T, in string, fallbackN int64) {
		fallback := time.Duration(fallbackN)
		got := def.Duration(in, fallback)
		want, err := time.ParseDuration(in)
		if in == "" || err != nil {
			want = fallback
		}
		if got != want {
			t.Fatalf("Duration(%q, %v) = %v; want %v", in, fallback, got, want)
		}
	})
}
