// Package edit provides edit scripts.
// Edit scripts are a core notion for diffs.
// They represent a way to go from A to B by a sequence
// of insertions, deletions, and equal elements.
package edit

import (
	"fmt"
	"strings"
)

// A Script is an edit script to alter A into B.
type Script struct {
	Ranges []Range
}

// NewScript returns a Script containing the ranges r.
// It is only a convenience wrapper used to reduce line noise.
func NewScript(r ...Range) Script {
	return Script{Ranges: r}
}

// IsIdentity reports whether s is the identity edit script,
// that is, whether A and B are identical.
func (s *Script) IsIdentity() bool {
	for _, r := range s.Ranges {
		if !r.IsEqual() {
			return false
		}
	}
	return true
}

// Stat reports the total number of insertions and deletions in s.
func (s *Script) Stat() (ins, del int) {
	for _, r := range s.Ranges {
		switch {
		case r.IsDelete():
			del += r.HighA - r.LowA
		case r.IsInsert():
			ins += r.HighB - r.LowB
		}
	}
	return ins, del
}

// dump formats s for debugging.
func (s *Script) dump() string {
	buf := new(strings.Builder)
	for _, r := range s.Ranges {
		fmt.Fprintln(buf, r)
	}
	return buf.String()
}

// A Range is a pair of clopen index ranges.
// It represents the elements A[LowA:HighA] and B[LowB:HighB].
type Range struct {
	LowA, HighA int
	LowB, HighB int
}

// IsInsert reports whether r represents an insertion in a Script.
// If so, the inserted elements are B[LowB:HighB].
func (r *Range) IsInsert() bool {
	return r.LowA == r.HighA
}

// IsDelete reports whether r represents a deletion in a Script.
// If so, the deleted elements are A[LowA:HighA].
func (r *Range) IsDelete() bool {
	return r.LowB == r.HighB
}

// IsEqual reports whether r represents a series of equal elements in a Script.
// If so, the elements A[LowA:HighA] are equal to the elements B[LowB:HighB].
func (r *Range) IsEqual() bool {
	return r.HighB-r.LowB == r.HighA-r.LowA
}

// An Op is a edit operation in a Script.
type Op int8

//go:generate stringer -type Op

const (
	Del Op = -1 // delete
	Eq  Op = 0  // equal
	Ins Op = 1  // insert
)

// Op reports what kind of operation r represents.
// This can also be determined by calling r.IsInsert,
// r.IsDelete, and r.IsEqual,
// but this form is sometimes more convenient to use.
func (r *Range) Op() Op {
	if r.IsInsert() {
		return Ins
	}
	if r.IsDelete() {
		return Del
	}
	if r.IsEqual() {
		return Eq
	}
	panic("malformed Range")
}

// Len reports the number of elements in r.
// In a deletion, it is the number of deleted elements.
// In an insertion, it is the number of inserted elements.
// For equal elements, it is the number of equal elements.
func (r *Range) Len() int {
	if r.LowA == r.HighA {
		return r.HighB - r.LowB
	}
	return r.HighA - r.LowA
}
