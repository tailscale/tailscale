// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package chonktest

import (
	"testing"

	"tailscale.com/tka"
)

func TestImplementsChonk(t *testing.T) {
	for _, tt := range []struct {
		name     string
		newChonk func(t *testing.T) tka.Chonk
	}{
		{
			name:     "Mem",
			newChonk: func(t *testing.T) tka.Chonk { return &tka.Mem{} },
		},
		{
			name:     "FS",
			newChonk: func(t *testing.T) tka.Chonk { return &tka.FS{Base: t.TempDir()} },
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			RunChonkTests(t, tt.newChonk)
		})
	}
}

func TestImplementsCompactableChonk(t *testing.T) {
	for _, tt := range []struct {
		name     string
		newChonk func(t *testing.T) tka.CompactableChonk
	}{
		{
			name:     "FS",
			newChonk: func(t *testing.T) tka.CompactableChonk { return &tka.FS{Base: t.TempDir()} },
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			RunCompactableChonkTests(t, tt.newChonk)
		})
	}
}
