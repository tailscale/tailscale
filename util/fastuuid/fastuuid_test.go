// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package fastuuid

import (
	"testing"

	"github.com/google/uuid"
)

func TestNewUUID(t *testing.T) {
	g := pool.Get().(*generator)
	defer pool.Put(g)
	u := g.newUUID()
	if u[6] != (u[6]&0x0f)|0x40 {
		t.Errorf("version bits are incorrect")
	}
	if u[8] != (u[8]&0x3f)|0x80 {
		t.Errorf("variant bits are incorrect")
	}
}

func BenchmarkBasic(b *testing.B) {
	b.Run("NewUUID", func(b *testing.B) {
		for range b.N {
			NewUUID()
		}
	})

	b.Run("uuid.New-unpooled", func(b *testing.B) {
		uuid.DisableRandPool()
		for range b.N {
			uuid.New()
		}
	})

	b.Run("uuid.New-pooled", func(b *testing.B) {
		uuid.EnableRandPool()
		for range b.N {
			uuid.New()
		}
	})
}

func BenchmarkParallel(b *testing.B) {
	b.Run("NewUUID", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				NewUUID()
			}
		})
	})

	b.Run("uuid.New-unpooled", func(b *testing.B) {
		uuid.DisableRandPool()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				uuid.New()
			}
		})
	})

	b.Run("uuid.New-pooled", func(b *testing.B) {
		uuid.EnableRandPool()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				uuid.New()
			}
		})
	})
}
