package jen

import (
	"fmt"
	"io"
	"sort"
	"strconv"
)

// Tag renders a struct tag
func Tag(items map[string]string) *Statement {
	return newStatement().Tag(items)
}

// Tag renders a struct tag
func (g *Group) Tag(items map[string]string) *Statement {
	// notest
	// don't think this can ever be used in valid code?
	s := Tag(items)
	g.items = append(g.items, s)
	return s
}

// Tag renders a struct tag
func (s *Statement) Tag(items map[string]string) *Statement {
	c := tag{
		items: items,
	}
	*s = append(*s, c)
	return s
}

type tag struct {
	items map[string]string
}

func (t tag) isNull(f *File) bool {
	return len(t.items) == 0
}

func (t tag) render(f *File, w io.Writer, s *Statement) error {

	if t.isNull(f) {
		// notest
		// render won't be called if t is null
		return nil
	}

	var str string

	var sorted []string
	for k := range t.items {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	for _, k := range sorted {
		v := t.items[k]
		if len(str) > 0 {
			str += " "
		}
		str += fmt.Sprintf(`%s:"%s"`, k, v)
	}

	if strconv.CanBackquote(str) {
		str = "`" + str + "`"
	} else {
		str = strconv.Quote(str)
	}

	if _, err := w.Write([]byte(str)); err != nil {
		return err
	}

	return nil
}
