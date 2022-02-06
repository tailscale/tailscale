package diff

// TODO: add a package for diffing gigantic files.
// Instead of reading the entire thing into memory, we could
// scan through the file once, storing the location of all newlines in each file.
// Then Seek/ReadAt to read each line lazily as needed,
// relying on the OS page cache for performance.
// This will allow diffing giant files with low memory use,
// albeit at a some time cost.
// An alternative is to mmap the files,
// although this is OS-specific and can be fiddly.

// TODO: add a package providing a StringIntern type, something like:
//
// type StringIntern struct {
// 	s map[string]*string
// }
//
// func (i *StringIntern) Bytes(b []byte) *string
// func (i *StringIntern) String(s string) *string
//
// And document what it is and why to use it.
// And consider adding helper functions to Strings and Bytes to use it.
// The reason to use it is that a lot of the execution time in diffing
// (which is an expensive operation) is taken up doing string comparisons.
// If you have paid the O(n) cost to intern all strings involved in both A and B,
// then string comparisons are reduced to cheap pointer comparisons.

// TODO: consider adding an "it just works" test helper that accepts two slices (via interface{}),
// diffs them using Strings or Bytes or Slices (using reflect.DeepEqual) as appropriate,
// and calls t.Errorf with a generated diff if they're not equal.

// TODO: add support for hunk/section/function headers.
// This will probably take the form of a write option
// providing access to the necessary data,
// and a package that helps calculate the necessary data.
// There are several ways to do that calculation...

// TODO: add copyright headers at top of all files

// TODO: hook up some CI

// TODO: add more badges? see github.com/pkg/errors for some likely candidates.
