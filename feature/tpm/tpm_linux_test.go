// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tpm

import (
	"os"
	"strings"
	"testing"
)

func TestOpenNoTPM(t *testing.T) {
	paths := []string{"/dev/tpmrm0", "/dev/tpm0"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			t.Skipf("%s exists", p)
		}
	}
	tpm, err := open()
	if err == nil {
		tpm.Close()
		t.Fatal("open succeeded with no TPM device")
	}
	if !isNoTPM(err) {
		t.Errorf("isNoTPM(%v) = false, want true", err)
	}
	for _, p := range paths {
		if !strings.Contains(err.Error(), p+":") {
			t.Errorf("open error %q does not name %s", err, p)
		}
	}
}
