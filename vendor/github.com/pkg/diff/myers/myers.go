// Package myers implements the Myers diff algorithm.
package myers

import (
	"context"
	"fmt"

	"github.com/pkg/diff/edit"
)

// A Pair is two things that can be diffed using the Myers diff algorithm.
// A is the initial state; B is the final state.
type Pair interface {
	// LenA returns the number of initial elements.
	LenA() int
	// LenB returns the number of final elements.
	LenB() int
	// Equal reports whether the aᵢ'th element of A is equal to the bᵢ'th element of B.
	Equal(ai, bi int) bool
}

// Diff calculates an edit.Script for ab using the Myers diff algorithm.
// This implementation uses the algorithm described in the first half
// of Myers' paper, which requires quadratric space.
// (An implementation of the linear space version is forthcoming.)
//
// Because diff calculation can be expensive, Myers supports cancellation via ctx.
func Diff(ctx context.Context, ab Pair) edit.Script {
	aLen := ab.LenA()
	bLen := ab.LenB()
	if aLen == 0 {
		return edit.NewScript(edit.Range{HighB: bLen})
	}
	if bLen == 0 {
		return edit.NewScript(edit.Range{HighA: aLen})
	}

	max := aLen + bLen
	if max < 0 {
		panic("overflow in myers.Diff")
	}
	// v has indices -max .. 0 .. max
	// access to elements of v have the form max + actual offset
	v := make([]int, 2*max+1)

	var trace [][]int
search:
	for d := 0; d < max; d++ {
		// Only check context every 16th iteration to reduce overhead.
		if ctx != nil && uint(d)%16 == 0 && ctx.Err() != nil {
			return edit.Script{}
		}

		// append the middle (populated) elements of v to trace
		middle := v[max-d : max+d+1]
		vcopy := make([]int, len(middle))
		copy(vcopy, middle)
		trace = append(trace, vcopy)

		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[max+k-1] < v[max+k+1]) {
				x = v[max+k+1]
			} else {
				x = v[max+k-1] + 1
			}

			y := x - k
			for x < aLen && y < bLen && ab.Equal(x, y) {
				x++
				y++
			}
			v[max+k] = x

			if x == aLen && y == bLen {
				break search
			}
		}
	}

	if len(trace) == max {
		// No commonality at all, delete everything and then insert everything.
		// This is handled as a special case to avoid complicating the logic below.
		return edit.NewScript(edit.Range{HighA: aLen}, edit.Range{HighB: bLen})
	}

	// Create reversed edit script.
	x := aLen
	y := bLen
	var e edit.Script
	for d := len(trace) - 1; d >= 0; d-- {
		// v has indices -d .. 0 .. d
		// access to elements of v have the form d + actual offset
		v := trace[d]
		k := x - y
		var prevk int
		if k == -d || (k != d && v[d+k-1] < v[d+k+1]) {
			prevk = k + 1
		} else {
			prevk = k - 1
		}
		var prevx int
		if idx := d + prevk; 0 <= idx && idx < len(v) {
			prevx = v[idx]
		}
		prevy := prevx - prevk
		for x > prevx && y > prevy {
			appendToReversed(&e, edit.Range{LowA: x - 1, LowB: y - 1, HighA: x, HighB: y})
			x--
			y--
		}
		if d > 0 {
			appendToReversed(&e, edit.Range{LowA: prevx, LowB: prevy, HighA: x, HighB: y})
		}
		x, y = prevx, prevy
	}

	// Reverse reversed edit script, to return to natural order.
	reverse(e)

	// Sanity check
	for i := 1; i < len(e.Ranges); i++ {
		prevop := e.Ranges[i-1].Op()
		currop := e.Ranges[i].Op()
		if (prevop == currop) || (prevop == edit.Ins && currop != edit.Eq) || (currop == edit.Del && prevop != edit.Eq) {
			panic(fmt.Errorf("bad script: %v -> %v", prevop, currop))
		}
	}

	return e
}

func reverse(e edit.Script) {
	for i := 0; i < len(e.Ranges)/2; i++ {
		j := len(e.Ranges) - i - 1
		e.Ranges[i], e.Ranges[j] = e.Ranges[j], e.Ranges[i]
	}
}

func appendToReversed(e *edit.Script, seg edit.Range) {
	if len(e.Ranges) == 0 {
		e.Ranges = append(e.Ranges, seg)
		return
	}
	u, ok := combineRanges(seg, e.Ranges[len(e.Ranges)-1])
	if !ok {
		e.Ranges = append(e.Ranges, seg)
		return
	}
	e.Ranges[len(e.Ranges)-1] = u
	return
}

// combineRanges combines s and t into a single edit.Range if possible
// and reports whether it succeeded.
func combineRanges(s, t edit.Range) (u edit.Range, ok bool) {
	if t.Len() == 0 {
		return s, true
	}
	if s.Len() == 0 {
		return t, true
	}
	if s.Op() != t.Op() {
		return edit.Range{LowA: -1, HighA: -1, LowB: -1, HighB: -1}, false
	}
	switch s.Op() {
	case edit.Ins:
		s.HighB = t.HighB
	case edit.Del:
		s.HighA = t.HighA
	case edit.Eq:
		s.HighA = t.HighA
		s.HighB = t.HighB
	default:
		panic("bad op")
	}
	return s, true
}

func rangeString(r edit.Range) string {
	// This output is helpful when hacking on a Myers diff.
	// In other contexts it is usually more natural to group LowA, HighA and LowB, HighB.
	return fmt.Sprintf("(%d, %d) -- %s %d --> (%d, %d)", r.LowA, r.LowB, r.Op(), r.Len(), r.HighA, r.HighB)
}
