// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package build

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestImageRepo(t *testing.T) {
	for _, tc := range []struct {
		registry, name, want string
	}{
		{"", "tailscale", "local/tailscale"},
		{"example.com", "tailscale", "example.com/tailscale"},
		{"example.com/", "tailscale", "example.com/tailscale"},
		{"localhost:5000", "k8s-operator", "localhost:5000/k8s-operator"},
	} {
		if got := ImageRepo(tc.registry, tc.name); got != tc.want {
			t.Errorf("ImageRepo(%q, %q) = %q, want %q", tc.registry, tc.name, got, tc.want)
		}
	}
}

func TestExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/manifests/present"):
			// remote.Head requires Content-Length and Docker-Content-Digest.
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			w.Header().Set("Docker-Content-Digest", "sha256:d1e8ab55c882e9587ee6ea474d305eea86ad50f4fcd1a2fdc4e08bea44c76507")
			w.Header().Set("Content-Length", "2")
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/manifests/missing"):
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	registry := strings.TrimPrefix(srv.URL, "http://")

	ctx := t.Context()
	if ok, err := Exists(ctx, registry+"/img:present"); err != nil || !ok {
		t.Errorf("Exists(present) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := Exists(ctx, registry+"/img:missing"); err != nil || ok {
		t.Errorf("Exists(missing) = %v, %v; want false, nil", ok, err)
	}
	// Server errors must propagate, not read as "missing"; a false negative
	// would trigger a push that an immutable registry rejects.
	if _, err := Exists(ctx, registry+"/img:error"); err == nil {
		t.Error("Exists(error) = nil error; want error")
	}
}
