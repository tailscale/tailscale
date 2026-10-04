package pktbuf

import "slices"

// Arena is an arena-based memory allocator for byte slices.
type Arena struct {
	mem  []byte
	high int // high water mark for previous arena cycles
	avg  float32
}

const initialArenaChunkSize = 4096

// Get allocates and returns a byte slice of the given size.
//
// The allocation remains valid until the next call to UnsafelyReset.
func (a *Arena) Get(sz int) []byte {
	a.mem = slices.Grow(a.mem, sz)
	ln := len(a.mem)
	a.mem = a.mem[:ln+sz]
	ret := a.mem[ln : ln+sz : ln+sz]
	// compiler should turn this into an efficient memset.
	for i := range ret {
		ret[i] = 0
	}
	return ret
}

const shrinkHysteresis = 1024

// Reset clears the arena for reuse. Past allocations are unaffected.
func (a *Arena) Reset() {
	a.mem = nil
}

// UnsafelyReset clears the arena for reuse. Unlike Reset,
// UnsafelyReset reuses the arena's existing storage for future
// allocations, so callers MUST cease all use of previously allocated
// slices prior to reset.
func (a *Arena) UnsafelyReset() {
	a.high = max(a.high, len(a.mem))
	a.avg = 0.9*a.avg + 0.1*float32(len(a.mem))
	if avgInt := int(a.avg); avgInt < a.high-shrinkHysteresis {
		a.mem = make([]byte, 0, avgInt)
	}
	a.mem = a.mem[:0]
}
