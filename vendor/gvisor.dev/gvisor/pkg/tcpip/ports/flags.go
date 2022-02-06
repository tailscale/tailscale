// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ports

// Flags represents the type of port reservation.
//
// +stateify savable
type Flags struct {
	// MostRecent represents UDP SO_REUSEADDR.
	MostRecent bool

	// LoadBalanced indicates SO_REUSEPORT.
	//
	// LoadBalanced takes precidence over MostRecent.
	LoadBalanced bool

	// TupleOnly represents TCP SO_REUSEADDR.
	TupleOnly bool
}

// Bits converts the Flags to their bitset form.
func (f Flags) Bits() BitFlags {
	var rf BitFlags
	if f.MostRecent {
		rf |= MostRecentFlag
	}
	if f.LoadBalanced {
		rf |= LoadBalancedFlag
	}
	if f.TupleOnly {
		rf |= TupleOnlyFlag
	}
	return rf
}

// Effective returns the effective behavior of a flag config.
func (f Flags) Effective() Flags {
	e := f
	if e.LoadBalanced && e.MostRecent {
		e.MostRecent = false
	}
	return e
}

// BitFlags is a bitset representation of Flags.
type BitFlags uint32

const (
	// MostRecentFlag represents Flags.MostRecent.
	MostRecentFlag BitFlags = 1 << iota

	// LoadBalancedFlag represents Flags.LoadBalanced.
	LoadBalancedFlag

	// TupleOnlyFlag represents Flags.TupleOnly.
	TupleOnlyFlag

	// nextFlag is the value that the next added flag will have.
	//
	// It is used to calculate FlagMask below. It is also the number of
	// valid flag states.
	nextFlag

	// FlagMask is a bit mask for BitFlags.
	FlagMask = nextFlag - 1

	// MultiBindFlagMask contains the flags that allow binding the same
	// tuple multiple times.
	MultiBindFlagMask = MostRecentFlag | LoadBalancedFlag
)

// ToFlags converts the bitset into a Flags struct.
func (f BitFlags) ToFlags() Flags {
	return Flags{
		MostRecent:   f&MostRecentFlag != 0,
		LoadBalanced: f&LoadBalancedFlag != 0,
		TupleOnly:    f&TupleOnlyFlag != 0,
	}
}

// FlagCounter counts how many references each flag combination has.
type FlagCounter struct {
	// refs stores the count for each possible flag combination, (0 though
	// FlagMask).
	refs [nextFlag]int
}

// AddRef increases the reference count for a specific flag combination.
func (c *FlagCounter) AddRef(flags BitFlags) {
	c.refs[flags]++
}

// DropRef decreases the reference count for a specific flag combination.
func (c *FlagCounter) DropRef(flags BitFlags) {
	c.refs[flags]--
}

// TotalRefs calculates the total number of references for all flag
// combinations.
func (c FlagCounter) TotalRefs() int {
	var total int
	for _, r := range c.refs {
		total += r
	}
	return total
}

// FlagRefs returns the number of references with all specified flags.
func (c FlagCounter) FlagRefs(flags BitFlags) int {
	var total int
	for i, r := range c.refs {
		if BitFlags(i)&flags == flags {
			total += r
		}
	}
	return total
}

// AllRefsHave returns if all references have all specified flags.
func (c FlagCounter) AllRefsHave(flags BitFlags) bool {
	for i, r := range c.refs {
		if BitFlags(i)&flags != flags && r > 0 {
			return false
		}
	}
	return true
}

// SharedFlags returns the set of flags shared by all references.
func (c FlagCounter) SharedFlags() BitFlags {
	intersection := FlagMask
	for i, r := range c.refs {
		if r > 0 {
			intersection &= BitFlags(i)
		}
	}
	return intersection
}
