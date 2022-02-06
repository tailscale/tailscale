package jen

import (
	"bytes"
	"io"
	"sort"
)

// Dict renders as key/value pairs. Use with Values for map or composite
// literals.
type Dict map[Code]Code

// DictFunc executes a func(Dict) to generate the value. Use with Values for
// map or composite literals.
func DictFunc(f func(Dict)) Dict {
	d := Dict{}
	f(d)
	return d
}

func (d Dict) render(f *File, w io.Writer, s *Statement) error {
	first := true
	// must order keys to ensure repeatable source
	type kv struct {
		k Code
		v Code
	}
	lookup := map[string]kv{}
	keys := []string{}
	for k, v := range d {
		if k.isNull(f) || v.isNull(f) {
			continue
		}
		buf := &bytes.Buffer{}
		if err := k.render(f, buf, nil); err != nil {
			return err
		}
		keys = append(keys, buf.String())
		lookup[buf.String()] = kv{k: k, v: v}
	}
	sort.Strings(keys)
	for _, key := range keys {
		k := lookup[key].k
		v := lookup[key].v
		if first && len(keys) > 1 {
			if _, err := w.Write([]byte("\n")); err != nil {
				return err
			}
			first = false
		}
		if err := k.render(f, w, nil); err != nil {
			return err
		}
		if _, err := w.Write([]byte(":")); err != nil {
			return err
		}
		if err := v.render(f, w, nil); err != nil {
			return err
		}
		if len(keys) > 1 {
			if _, err := w.Write([]byte(",\n")); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d Dict) isNull(f *File) bool {
	if d == nil || len(d) == 0 {
		return true
	}
	for k, v := range d {
		if !k.isNull(f) && !v.isNull(f) {
			// if any of the key/value pairs are both not null, the Dict is not
			// null
			return false
		}
	}
	return true
}
