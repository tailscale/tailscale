// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"testing"
)

// Test_statefulSetNameBase tests that parent name portion in a StatefulSet name
// base will be truncated if the parent name is longer than 43 chars to ensure
// that the total does not exceed 52 chars.
// How many chars need to be cut off parent name depends on an internal var in
// kube name generation code that can change at which point this test will break
// and need to be changed. This is okay as we do not rely on that value in
// code whilst being aware when it changes might still be useful.
// https://github.com/kubernetes/kubernetes/blob/v1.28.4/staging/src/k8s.io/apiserver/pkg/storage/names/generate.go#L45.
// https://github.com/kubernetes/kubernetes/pull/116430
func Test_statefulSetNameBase(t *testing.T) {
	tests := []struct {
		name string
		in   string
		out  string
	}{
		{
			name: "43 chars",
			in:   "oidhexl9o832hcbhyg4uz6o0s7u9uae54h5k8ofs9xb",
			out:  "ts-oidhexl9o832hcbhyg4uz6o0s7u9uae54h5k8ofs9xb-",
		},
		{
			name: "44 chars",
			in:   "oidhexl9o832hcbhyg4uz6o0s7u9uae54h5k8ofs9xbo",
			out:  "ts-oidhexl9o832hcbhyg4uz6o0s7u9uae54h5k8ofs9xb-",
		},
		{
			name: "42 chars",
			in:   "oidhexl9o832hcbhyg4uz6o0s7u9uae54h5k8ofs9x",
			out:  "ts-oidhexl9o832hcbhyg4uz6o0s7u9uae54h5k8ofs9x-",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := statefulSetNameBase(tt.in); got != tt.out {
				t.Errorf("stsNamePrefix(%s) = %q, want %s", tt.in, got, tt.out)
			}
		})
	}
}
