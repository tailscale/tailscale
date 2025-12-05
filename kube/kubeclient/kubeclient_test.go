// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package kubeclient

import "testing"

func TestIsNotFoundErr(t *testing.T) {
	if IsNotFoundErr(nil) {
		t.Error("IsNotFoundErr(nil) = true, want false")
	}
}

func TestNamespaceFile(t *testing.T) {
	_ = namespaceFile
	// Constant should be defined
}
