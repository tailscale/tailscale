package derp

import (
	"testing"
	"unique"

	"go4.org/mem"
	"tailscale.com/types/key"
)

func BenchmarkUnique(b *testing.B) {
	var keys [100]key.NodePublic
	for i := range keys {
		keys[i] = key.NodePublicFromRaw32(mem.B([]byte{31: byte(i)}))
	}
	b.Run("raw", func(b *testing.B) {
		m := map[flowKey]bool{}
		for range b.N {
			for _, k := range keys {
				key := flowKey{k, k}
				if _, ok := m[key]; !ok {
					m[key] = true
				}
			}
		}
	})
	b.Run("unique-tightmake", func(b *testing.B) {
		m := map[unique.Handle[flowKey]]bool{}
		for range b.N {
			for _, k := range keys {
				key := unique.Make(flowKey{k, k})
				if _, ok := m[key]; !ok {
					m[key] = true
				}
			}
		}
	})
	b.Run("unique-makeonce", func(b *testing.B) {
		m := map[unique.Handle[flowKey]]bool{}
		ukeys := make([]unique.Handle[flowKey], len(keys))
		for i, k := range keys {
			ukeys[i] = unique.Make(flowKey{k, k})
		}
		for range b.N {
			for _, key := range ukeys {
				if _, ok := m[key]; !ok {
					m[key] = true
				}
			}
		}
	})
}
