// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package set

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestSliceSet(t *testing.T) {
	c := qt.New(t)

	var ss Slice[int]
	c.Check(len(ss.slice), qt.Equals, 0)
	ss.Add(1)
	c.Check(len(ss.slice), qt.Equals, 1)
	c.Check(len(ss.set), qt.Equals, 0)
	c.Check(ss.Contains(1), qt.Equals, true)
	c.Check(ss.Contains(2), qt.Equals, false)

	ss.Add(1)
	c.Check(len(ss.slice), qt.Equals, 1)
	c.Check(len(ss.set), qt.Equals, 0)

	ss.Add(2)
	ss.Add(3)
	ss.Add(4)
	ss.Add(5)
	ss.Add(6)
	ss.Add(7)
	ss.Add(8)
	c.Check(len(ss.slice), qt.Equals, 8)
	c.Check(len(ss.set), qt.Equals, 0)

	ss.Add(9)
	c.Check(len(ss.slice), qt.Equals, 9)
	c.Check(len(ss.set), qt.Equals, 9)

	ss.Remove(4)
	c.Check(len(ss.slice), qt.Equals, 8)
	c.Check(len(ss.set), qt.Equals, 8)
	c.Assert(ss.Contains(4), qt.IsFalse)

	// Ensure that the order of insertion is maintained
	c.Assert(ss.Slice().AsSlice(), qt.DeepEquals, []int{1, 2, 3, 5, 6, 7, 8, 9})
	ss.Add(4)
	c.Check(len(ss.slice), qt.Equals, 9)
	c.Check(len(ss.set), qt.Equals, 9)
	c.Assert(ss.Contains(4), qt.IsTrue)
	c.Assert(ss.Slice().AsSlice(), qt.DeepEquals, []int{1, 2, 3, 5, 6, 7, 8, 9, 4})

	ss.Add(1, 234, 556)
	c.Assert(ss.Slice().AsSlice(), qt.DeepEquals, []int{1, 2, 3, 5, 6, 7, 8, 9, 4, 234, 556})
}
