// Package jen is a code generator for Go
package jen

import (
	"bytes"
	"fmt"
	"go/format"
	"io"
	"io/ioutil"
	"sort"
	"strconv"
)

// Code represents an item of code that can be rendered.
type Code interface {
	render(f *File, w io.Writer, s *Statement) error
	isNull(f *File) bool
}

// Save renders the file and saves to the filename provided.
func (f *File) Save(filename string) error {
	// notest
	buf := &bytes.Buffer{}
	if err := f.Render(buf); err != nil {
		return err
	}
	if err := ioutil.WriteFile(filename, buf.Bytes(), 0644); err != nil {
		return err
	}
	return nil
}

// Render renders the file to the provided writer.
func (f *File) Render(w io.Writer) error {
	body := &bytes.Buffer{}
	if err := f.render(f, body, nil); err != nil {
		return err
	}
	source := &bytes.Buffer{}
	if len(f.headers) > 0 {
		for _, c := range f.headers {
			if err := Comment(c).render(f, source, nil); err != nil {
				return err
			}
			if _, err := fmt.Fprint(source, "\n"); err != nil {
				return err
			}
		}
		// Append an extra newline so that header comments don't get lumped in
		// with package comments.
		if _, err := fmt.Fprint(source, "\n"); err != nil {
			return err
		}
	}
	for _, c := range f.comments {
		if err := Comment(c).render(f, source, nil); err != nil {
			return err
		}
		if _, err := fmt.Fprint(source, "\n"); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(source, "package %s", f.name); err != nil {
		return err
	}
	if f.CanonicalPath != "" {
		if _, err := fmt.Fprintf(source, " // import %q", f.CanonicalPath); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprint(source, "\n\n"); err != nil {
		return err
	}
	if err := f.renderImports(source); err != nil {
		return err
	}
	if _, err := source.Write(body.Bytes()); err != nil {
		return err
	}
	formatted, err := format.Source(source.Bytes())
	if err != nil {
		return fmt.Errorf("Error %s while formatting source:\n%s", err, source.String())
	}
	if _, err := w.Write(formatted); err != nil {
		return err
	}
	return nil
}

func (f *File) renderImports(source io.Writer) error {

	// Render the "C" import if it's been used in a `Qual`, `Anon` or if there's a preamble comment
	hasCgo := f.imports["C"].name != "" || len(f.cgoPreamble) > 0

	// Only separate the import from the main imports block if there's a preamble
	separateCgo := hasCgo && len(f.cgoPreamble) > 0

	filtered := map[string]importdef{}
	for path, def := range f.imports {
		// filter out the "C" pseudo-package so it's not rendered in a block with the other
		// imports, but only if it is accompanied by a preamble comment
		if path == "C" && separateCgo {
			continue
		}
		filtered[path] = def
	}

	if len(filtered) == 1 {
		for path, def := range filtered {
			if def.alias && path != "C" {
				// "C" package should be rendered without alias even when used as an anonymous import
				// (e.g. should never have an underscore).
				if _, err := fmt.Fprintf(source, "import %s %s\n\n", def.name, strconv.Quote(path)); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprintf(source, "import %s\n\n", strconv.Quote(path)); err != nil {
					return err
				}
			}
		}
	} else if len(filtered) > 1 {
		if _, err := fmt.Fprint(source, "import (\n"); err != nil {
			return err
		}
		// We must sort the imports to ensure repeatable
		// source.
		paths := []string{}
		for path := range filtered {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		for _, path := range paths {
			def := filtered[path]
			if def.alias && path != "C" {
				// "C" package should be rendered without alias even when used as an anonymous import
				// (e.g. should never have an underscore).
				if _, err := fmt.Fprintf(source, "%s %s\n", def.name, strconv.Quote(path)); err != nil {
					return err
				}

			} else {
				if _, err := fmt.Fprintf(source, "%s\n", strconv.Quote(path)); err != nil {
					return err
				}
			}
		}
		if _, err := fmt.Fprint(source, ")\n\n"); err != nil {
			return err
		}
	}

	if separateCgo {
		for _, c := range f.cgoPreamble {
			if err := Comment(c).render(f, source, nil); err != nil {
				return err
			}
			if _, err := fmt.Fprint(source, "\n"); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(source, "import \"C\"\n\n"); err != nil {
			return err
		}
	}

	return nil
}
