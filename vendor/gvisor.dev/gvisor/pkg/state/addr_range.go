package state

// A Range represents a contiguous range of T.
//
// +stateify savable
type addrRange struct {
	// Start is the inclusive start of the range.
	Start uintptr

	// End is the exclusive end of the range.
	End uintptr
}

// WellFormed returns true if r.Start <= r.End. All other methods on a Range
// require that the Range is well-formed.
//
//go:nosplit
func (r addrRange) WellFormed() bool {
	return r.Start <= r.End
}

// Length returns the length of the range.
//
//go:nosplit
func (r addrRange) Length() uintptr {
	return r.End - r.Start
}

// Contains returns true if r contains x.
//
//go:nosplit
func (r addrRange) Contains(x uintptr) bool {
	return r.Start <= x && x < r.End
}

// Overlaps returns true if r and r2 overlap.
//
//go:nosplit
func (r addrRange) Overlaps(r2 addrRange) bool {
	return r.Start < r2.End && r2.Start < r.End
}

// IsSupersetOf returns true if r is a superset of r2; that is, the range r2 is
// contained within r.
//
//go:nosplit
func (r addrRange) IsSupersetOf(r2 addrRange) bool {
	return r.Start <= r2.Start && r.End >= r2.End
}

// Intersect returns a range consisting of the intersection between r and r2.
// If r and r2 do not overlap, Intersect returns a range with unspecified
// bounds, but for which Length() == 0.
//
//go:nosplit
func (r addrRange) Intersect(r2 addrRange) addrRange {
	if r.Start < r2.Start {
		r.Start = r2.Start
	}
	if r.End > r2.End {
		r.End = r2.End
	}
	if r.End < r.Start {
		r.End = r.Start
	}
	return r
}

// CanSplitAt returns true if it is legal to split a segment spanning the range
// r at x; that is, splitting at x would produce two ranges, both of which have
// non-zero length.
//
//go:nosplit
func (r addrRange) CanSplitAt(x uintptr) bool {
	return r.Contains(x) && r.Start < x
}
