// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package def_test

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"tailscale.com/types/opt"
	"tailscale.com/util/def"
)

func FuzzGetenv(f *testing.F) {
	// Extracted from cmd/k8s-operator.defaultEnv:
	defaultEnv := func(envName, defVal string) string {
		v := os.Getenv(envName)
		if v == "" {
			return defVal
		}
		return v
	}

	f.Setenv("TAILSCALE_DEF_TEST", "1")
	for _, tc := range []string{
		"",
		"invalid",
		"PATH",
		"TAILSCALE_DEF_TEST",
	} {
		f.Add(tc, "")
		f.Add(tc, "default")
	}
	for _, kv := range os.Environ() {
		bits := strings.SplitN(kv, "=", 2)
		f.Add(bits[0], "")
		f.Add(bits[0], "default")
		f.Add(bits[0], bits[1])
	}
	f.Fuzz(func(t *testing.T, key string, d string) {
		want := defaultEnv(key, d)
		got := def.Getenv(key, d)
		if got != want {
			t.Errorf("def.Getenv(%q, %q): got %q, want %q", key, d, got, want)
		}
	})
}

func FuzzGetenvBool(f *testing.F) {
	// Extracted from cmd/containerboot.defaultBool:
	defaultBool := func(name string, defVal bool) bool {
		v := os.Getenv(name)
		ret, err := strconv.ParseBool(v)
		if err != nil {
			return defVal
		}
		return ret
	}

	f.Setenv("TAILSCALE_DEF_TEST", "1")
	for _, tc := range []string{
		"",
		"invalid",
		"PATH",
		"TAILSCALE_DEF_TEST",
	} {
		f.Add(tc, true)
		f.Add(tc, false)
	}
	for _, kv := range os.Environ() {
		bits := strings.SplitN(kv, "=", 2)
		f.Add(bits[0], true)
		f.Add(bits[0], false)
	}
	f.Fuzz(func(t *testing.T, key string, d bool) {
		want := defaultBool(key, d)
		got := def.GetenvBool(key, d)
		if got != want {
			t.Errorf("def.GetenvBool(%q, %t): got %t, want %t", key, d, got, want)
		}
	})
}

func FuzzGetenvOptBool(f *testing.F) {
	// Extracted from cmd/k8s-operator.defaultBool:
	defaultBool := func(envName string, defVal bool) bool {
		vs := os.Getenv(envName)
		if vs == "" {
			return defVal
		}
		v, _ := opt.Bool(vs).Get()
		return v
	}

	f.Setenv("TAILSCALE_DEF_TEST", "")
	f.Setenv("TAILSCALE_DEF_TEST_9", "0")
	f.Setenv("TAILSCALE_DEF_TEST_1", "1")
	f.Setenv("TAILSCALE_DEF_TEST_TRUE", "true")
	f.Setenv("TAILSCALE_DEF_TEST_FALSE", "false")
	f.Setenv("TAILSCALE_DEF_TEST_UNSET", "unset")
	for _, tc := range []string{
		"",
		"invalid",
		"PATH",
		"TAILSCALE_DEF_TEST_UNSET",
	} {
		f.Add(tc, true)
		f.Add(tc, false)
	}
	for _, kv := range os.Environ() {
		bits := strings.SplitN(kv, "=", 2)
		f.Add(bits[0], true)
		f.Add(bits[0], false)
	}
	f.Fuzz(func(t *testing.T, key string, d bool) {
		want := defaultBool(key, d)
		got := def.GetenvOptBool(key, d)
		if got != want {
			t.Errorf("def.GetenvOptBool(%q, %t): got %t, want %t", key, d, got, want)
		}
	})
}

func FuzzGetenvResolve(f *testing.F) {
	// Extracted from cmd/containerboot.defaultEnvs:
	defaultEnvs := func(names []string, defVal string) string {
		for _, name := range names {
			if v, ok := os.LookupEnv(name); ok {
				return v
			}
		}
		return defVal
	}

	f.Setenv("TAILSCALE_DEF_TEST", "unset")
	for _, tc := range []string{
		"",
		"invalid",
		"invalid PATH",
		"invalid TAILSCALE_DEF_TEST",
		"PATH",
		"TAILSCALE_DEF_TEST",
	} {
		f.Add(tc, "")
		f.Add(tc, "default")
	}
	for _, kv := range os.Environ() {
		bits := strings.SplitN(kv, "=", 2)
		f.Add(bits[0], "")
		f.Add(bits[0], "default")
		f.Add("invalid "+bits[0], "")
		f.Add("invalid "+bits[0], "default")
	}
	f.Fuzz(func(t *testing.T, keys string, d string) {
		ks := strings.Fields(keys)
		want := defaultEnvs(ks, d)
		got := def.GetenvResolve(ks, d)
		if got != want {
			t.Errorf("def.GetenvResolve(%q, %q): got %q, want %q", ks, d, got, want)
		}
	})
}

func FuzzLookupEnv(f *testing.F) {
	// Extracted from cmd/containerboot.defaultEnv:
	defaultEnv := func(name, defVal string) string {
		if v, ok := os.LookupEnv(name); ok {
			return v
		}
		return defVal
	}

	f.Setenv("TAILSCALE_DEF_TEST", "1")
	for _, tc := range []string{
		"",
		"invalid",
		"PATH",
		"TAILSCALE_DEF_TEST",
	} {
		f.Add(tc, "")
		f.Add(tc, "default")
	}
	for _, kv := range os.Environ() {
		bits := strings.SplitN(kv, "=", 2)
		f.Add(bits[0], "")
		f.Add(bits[0], "default")
		f.Add(bits[0], bits[1])
	}
	f.Fuzz(func(t *testing.T, key string, d string) {
		want := defaultEnv(key, d)
		got := def.LookupEnv(key, d)
		if got != want {
			t.Errorf("def.LookupEnv(%q, %q): got %q, want %q", key, d, got, want)
		}
	})
}
