// Package intern provides string interning.
//
// Unlike much string interning, the routines in this package
// return *string instead of string. This enables extremely
// cheap (compare only a pointer) comparisons of any strings
// interned by this package. Since diff algorithms involve
// many string comparisons, this often ends up paying for the
// cost of the interning. Also, in the typical case,
// diffs involve lots of repeated lines (most of the file
// contents are typically unchanged, so any give line
// appears at least twice), so string interning saves memory.
package intern

type Strings map[string]*string

func (m Strings) FromBytes(b []byte) *string {
	p, ok := m[string(b)]
	if ok {
		return p
	}
	s := string(b)
	p = &s
	m[s] = p
	return p
}
