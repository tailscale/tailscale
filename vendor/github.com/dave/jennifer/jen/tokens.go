package jen

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

type tokenType string

const (
	packageToken     tokenType = "package"
	identifierToken  tokenType = "identifier"
	qualifiedToken   tokenType = "qualified"
	keywordToken     tokenType = "keyword"
	operatorToken    tokenType = "operator"
	delimiterToken   tokenType = "delimiter"
	literalToken     tokenType = "literal"
	literalRuneToken tokenType = "literal_rune"
	literalByteToken tokenType = "literal_byte"
	nullToken        tokenType = "null"
	layoutToken      tokenType = "layout"
)

type token struct {
	typ     tokenType
	content interface{}
}

func (t token) isNull(f *File) bool {
	if t.typ == packageToken {
		// package token is null if the path is a dot-import or the local package path
		return f.isDotImport(t.content.(string)) || f.isLocal(t.content.(string))
	}
	return t.typ == nullToken
}

func (t token) render(f *File, w io.Writer, s *Statement) error {
	switch t.typ {
	case literalToken:
		var out string
		switch t.content.(type) {
		case bool, string, int, complex128:
			// default constant types can be left bare
			out = fmt.Sprintf("%#v", t.content)
		case float64:
			out = fmt.Sprintf("%#v", t.content)
			if !strings.Contains(out, ".") && !strings.Contains(out, "e") {
				// If the formatted value is not in scientific notation, and does not have a dot, then
				// we add ".0". Otherwise it will be interpreted as an int.
				// See:
				// https://github.com/dave/jennifer/issues/39
				// https://github.com/golang/go/issues/26363
				out += ".0"
			}
		case float32, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, uintptr:
			// other built-in types need specific type info
			out = fmt.Sprintf("%T(%#v)", t.content, t.content)
		case complex64:
			// fmt package already renders parenthesis for complex64
			out = fmt.Sprintf("%T%#v", t.content, t.content)
		default:
			panic(fmt.Sprintf("unsupported type for literal: %T", t.content))
		}
		if _, err := w.Write([]byte(out)); err != nil {
			return err
		}
	case literalRuneToken:
		if _, err := w.Write([]byte(strconv.QuoteRune(t.content.(rune)))); err != nil {
			return err
		}
	case literalByteToken:
		if _, err := w.Write([]byte(fmt.Sprintf("byte(%#v)", t.content))); err != nil {
			return err
		}
	case keywordToken, operatorToken, layoutToken, delimiterToken:
		if _, err := w.Write([]byte(fmt.Sprintf("%s", t.content))); err != nil {
			return err
		}
		if t.content.(string) == "default" {
			// Special case for Default, which must always be followed by a colon
			if _, err := w.Write([]byte(":")); err != nil {
				return err
			}
		}
	case packageToken:
		path := t.content.(string)
		alias := f.register(path)
		if _, err := w.Write([]byte(alias)); err != nil {
			return err
		}
	case identifierToken:
		if _, err := w.Write([]byte(t.content.(string))); err != nil {
			return err
		}
	case nullToken: // notest
		// do nothing (should never render a null token)
	}
	return nil
}

// Null adds a null item. Null items render nothing and are not followed by a
// separator in lists.
func Null() *Statement {
	return newStatement().Null()
}

// Null adds a null item. Null items render nothing and are not followed by a
// separator in lists.
func (g *Group) Null() *Statement {
	s := Null()
	g.items = append(g.items, s)
	return s
}

// Null adds a null item. Null items render nothing and are not followed by a
// separator in lists.
func (s *Statement) Null() *Statement {
	t := token{
		typ: nullToken,
	}
	*s = append(*s, t)
	return s
}

// Empty adds an empty item. Empty items render nothing but are followed by a
// separator in lists.
func Empty() *Statement {
	return newStatement().Empty()
}

// Empty adds an empty item. Empty items render nothing but are followed by a
// separator in lists.
func (g *Group) Empty() *Statement {
	s := Empty()
	g.items = append(g.items, s)
	return s
}

// Empty adds an empty item. Empty items render nothing but are followed by a
// separator in lists.
func (s *Statement) Empty() *Statement {
	t := token{
		typ:     operatorToken,
		content: "",
	}
	*s = append(*s, t)
	return s
}

// Op renders the provided operator / token.
func Op(op string) *Statement {
	return newStatement().Op(op)
}

// Op renders the provided operator / token.
func (g *Group) Op(op string) *Statement {
	s := Op(op)
	g.items = append(g.items, s)
	return s
}

// Op renders the provided operator / token.
func (s *Statement) Op(op string) *Statement {
	t := token{
		typ:     operatorToken,
		content: op,
	}
	*s = append(*s, t)
	return s
}

// Dot renders a period followed by an identifier. Use for fields and selectors.
func Dot(name string) *Statement {
	// notest
	// don't think this can be used in valid code?
	return newStatement().Dot(name)
}

// Dot renders a period followed by an identifier. Use for fields and selectors.
func (g *Group) Dot(name string) *Statement {
	// notest
	// don't think this can be used in valid code?
	s := Dot(name)
	g.items = append(g.items, s)
	return s
}

// Dot renders a period followed by an identifier. Use for fields and selectors.
func (s *Statement) Dot(name string) *Statement {
	d := token{
		typ:     delimiterToken,
		content: ".",
	}
	t := token{
		typ:     identifierToken,
		content: name,
	}
	*s = append(*s, d, t)
	return s
}

// Id renders an identifier.
func Id(name string) *Statement {
	return newStatement().Id(name)
}

// Id renders an identifier.
func (g *Group) Id(name string) *Statement {
	s := Id(name)
	g.items = append(g.items, s)
	return s
}

// Id renders an identifier.
func (s *Statement) Id(name string) *Statement {
	t := token{
		typ:     identifierToken,
		content: name,
	}
	*s = append(*s, t)
	return s
}

// Qual renders a qualified identifier. Imports are automatically added when
// used with a File. If the path matches the local path, the package name is
// omitted. If package names conflict they are automatically renamed. Note that
// it is not possible to reliably determine the package name given an arbitrary
// package path, so a sensible name is guessed from the path and added as an
// alias. The names of all standard library packages are known so these do not
// need to be aliased. If more control is needed of the aliases, see
// [File.ImportName](#importname) or [File.ImportAlias](#importalias).
func Qual(path, name string) *Statement {
	return newStatement().Qual(path, name)
}

// Qual renders a qualified identifier. Imports are automatically added when
// used with a File. If the path matches the local path, the package name is
// omitted. If package names conflict they are automatically renamed. Note that
// it is not possible to reliably determine the package name given an arbitrary
// package path, so a sensible name is guessed from the path and added as an
// alias. The names of all standard library packages are known so these do not
// need to be aliased. If more control is needed of the aliases, see
// [File.ImportName](#importname) or [File.ImportAlias](#importalias).
func (g *Group) Qual(path, name string) *Statement {
	s := Qual(path, name)
	g.items = append(g.items, s)
	return s
}

// Qual renders a qualified identifier. Imports are automatically added when
// used with a File. If the path matches the local path, the package name is
// omitted. If package names conflict they are automatically renamed. Note that
// it is not possible to reliably determine the package name given an arbitrary
// package path, so a sensible name is guessed from the path and added as an
// alias. The names of all standard library packages are known so these do not
// need to be aliased. If more control is needed of the aliases, see
// [File.ImportName](#importname) or [File.ImportAlias](#importalias).
func (s *Statement) Qual(path, name string) *Statement {
	g := &Group{
		close: "",
		items: []Code{
			token{
				typ:     packageToken,
				content: path,
			},
			token{
				typ:     identifierToken,
				content: name,
			},
		},
		name:      "qual",
		open:      "",
		separator: ".",
	}
	*s = append(*s, g)
	return s
}

// Line inserts a blank line.
func Line() *Statement {
	return newStatement().Line()
}

// Line inserts a blank line.
func (g *Group) Line() *Statement {
	s := Line()
	g.items = append(g.items, s)
	return s
}

// Line inserts a blank line.
func (s *Statement) Line() *Statement {
	t := token{
		typ:     layoutToken,
		content: "\n",
	}
	*s = append(*s, t)
	return s
}
