// Package diff contains high level routines that generate a textual diff.
//
// It is implemented in terms of the other packages in this module.
// If you want fine-grained control,
// want to inspect a diff programmatically,
// want to provide a context for cancellation,
// need to diff gigantic files that don't fit in memory,
// or want to diff unusual things,
// use the lower level packages.
package diff

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"github.com/pkg/diff/ctxt"
	"github.com/pkg/diff/intern"
	"github.com/pkg/diff/myers"
	"github.com/pkg/diff/write"
)

// lines returns the lines contained in text/filename.
// text and filename are interpreted as described in the docs for Text.
func lines(m intern.Strings, filename string, text interface{}) ([]*string, error) {
	var r io.Reader
	switch text := text.(type) {
	case nil:
		f, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	case string:
		r = strings.NewReader(text)
	case []byte:
		r = bytes.NewReader(text)
	case io.Reader:
		r = text
	default:
		return nil, fmt.Errorf("unexpected type %T, want string, []byte, io.Reader, or nil", text)
	}
	var x []*string
	scan := bufio.NewScanner(r)
	for scan.Scan() {
		x = append(x, m.FromBytes(scan.Bytes()))
	}
	return x, scan.Err()
}

// addNames adds a Names write.Option using aName and bName,
// taking care to put it at the end,
// so as not to overwrite any competing option.
func addNames(aName, bName string, options []write.Option) []write.Option {
	opts := make([]write.Option, len(options)+1)
	opts[0] = write.Names(aName, bName)
	copy(opts[1:], options)
	return opts
}

// Text diffs a and b and writes the result to w.
// It treats a and b as text, and splits their contents
// into lines using bufio.ScanLines.
// aFile and bFile are filenames to use in the output.
//
// a and b each may be nil or may have type string, []byte, or io.Reader.
// If nil, the text is read from the filename.
func Text(aFile, bFile string, a, b interface{}, w io.Writer, options ...write.Option) error {
	m := make(intern.Strings)
	aLines, err := lines(m, aFile, a)
	if err != nil {
		return err
	}
	bLines, err := lines(m, bFile, b)
	if err != nil {
		return err
	}
	ab := &diffStrings{a: aLines, b: bLines}
	s := myers.Diff(context.Background(), ab)
	s = ctxt.Size(s, 3)
	opts := addNames(aFile, bFile, options)
	err = write.Unified(s, w, ab, opts...)
	return err
}

type diffStrings struct {
	a, b []*string
}

func (ab *diffStrings) LenA() int                                { return len(ab.a) }
func (ab *diffStrings) LenB() int                                { return len(ab.b) }
func (ab *diffStrings) Equal(ai, bi int) bool                    { return ab.a[ai] == ab.b[bi] }
func (ab *diffStrings) WriteATo(w io.Writer, i int) (int, error) { return io.WriteString(w, *ab.a[i]) }
func (ab *diffStrings) WriteBTo(w io.Writer, i int) (int, error) { return io.WriteString(w, *ab.b[i]) }

// Slices diffs slices a and b and writes the result to w.
// It uses fmt.Print to print the elements of a and b.
// It uses reflect.DeepEqual to compare elements of a and b.
// It uses aName and bName as the names of a and b in the output.
func Slices(aName, bName string, a, b interface{}, w io.Writer, options ...write.Option) error {
	ab := &diffSlices{a: reflect.ValueOf(a), b: reflect.ValueOf(b)}
	if err := ab.validateTypes(); err != nil {
		return err
	}
	s := myers.Diff(context.Background(), ab)
	s = ctxt.Size(s, 3)
	opts := addNames(aName, bName, options)
	err := write.Unified(s, w, ab, opts...)
	return err
}

type diffSlices struct {
	a, b reflect.Value
}

func (ab *diffSlices) LenA() int                                { return ab.a.Len() }
func (ab *diffSlices) LenB() int                                { return ab.b.Len() }
func (ab *diffSlices) atA(i int) interface{}                    { return ab.a.Index(i).Interface() }
func (ab *diffSlices) atB(i int) interface{}                    { return ab.b.Index(i).Interface() }
func (ab *diffSlices) Equal(ai, bi int) bool                    { return reflect.DeepEqual(ab.atA(ai), ab.atB(bi)) }
func (ab *diffSlices) WriteATo(w io.Writer, i int) (int, error) { return fmt.Fprint(w, ab.atA(i)) }
func (ab *diffSlices) WriteBTo(w io.Writer, i int) (int, error) { return fmt.Fprint(w, ab.atB(i)) }

func (ab *diffSlices) validateTypes() error {
	if t := ab.a.Type(); t.Kind() != reflect.Slice {
		return fmt.Errorf("a has type %v, must be a slice", t)
	}
	if t := ab.b.Type(); t.Kind() != reflect.Slice {
		return fmt.Errorf("b has type %v, must be a slice", t)
	}
	return nil
}
