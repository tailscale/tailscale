// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package set

import (
	"fmt"
	"iter"
	"maps"
	"reflect"
	"slices"
	"testing"
)

func TestSmallSet(t *testing.T) {
	t.Parallel()

	wantSize := reflect.TypeFor[int64]().Size() + reflect.TypeFor[map[int]struct{}]().Size()
	if wantSize > 16 {
		t.Errorf("wantSize should be no more than 16") // it might be smaller on 32-bit systems
	}
	if size := reflect.TypeFor[SmallSet[int64]]().Size(); size != wantSize {
		t.Errorf("SmallSet[int64] size is %d, want %v", size, wantSize)
	}

	type op struct {
		add bool
		v   int
	}
	ops := iter.Seq[op](func(yield func(op) bool) {
		for _, add := range []bool{false, true} {
			for v := range 4 {
				if !yield(op{add: add, v: v}) {
					return
				}
			}
		}
	})
	type setLike interface {
		Add(int)
		Delete(int)
	}
	apply := func(s setLike, o op) {
		if o.add {
			s.Add(o.v)
		} else {
			s.Delete(o.v)
		}
	}

	// For all combinations of 4 operations,
	// apply them to both a regular map and SmallSet
	// and make sure all the invariants hold.

	for op1 := range ops {
		for op2 := range ops {
			for op3 := range ops {
				for op4 := range ops {

					normal := Set[int]{}
					small := &SmallSet[int]{}
					for _, op := range []op{op1, op2, op3, op4} {
						apply(normal, op)
						apply(small, op)
					}

					name := func() string {
						return fmt.Sprintf("op1=%v, op2=%v, op3=%v, op4=%v", op1, op2, op3, op4)
					}
					if normal.Len() != small.Len() {
						t.Errorf("len mismatch after ops %s: normal=%d, small=%d", name(), normal.Len(), small.Len())
					}
					if got := small.Clone().Len(); normal.Len() != got {
						t.Errorf("len mismatch after ops %s: normal=%d, clone=%d", name(), normal.Len(), got)
					}

					normalEle := slices.Sorted(maps.Keys(normal))
					smallEle := slices.Sorted(small.Values())
					if !slices.Equal(normalEle, smallEle) {
						t.Errorf("elements mismatch after ops %s: normal=%v, small=%v", name(), normalEle, smallEle)
					}
					for e := range 5 {
						if normal.Contains(e) != small.Contains(e) {
							t.Errorf("contains(%v) mismatch after ops %s: normal=%v, small=%v", e, name(), normal.Contains(e), small.Contains(e))
						}
					}
				}
			}
		}
	}
}
