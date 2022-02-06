package fileglob

import (
	"fmt"
	"strings"

	"github.com/gobwas/glob/syntax/ast"
	"github.com/gobwas/glob/syntax/lexer"
)

// ValidPattern determines whether a pattern is valid. It returns the parser
// error if the pattern is invalid and nil otherwise.
func ValidPattern(pattern string) error {
	_, err := ast.Parse(lexer.NewLexer(pattern))
	return err // nolint:wrapcheck
}

// ContainsMatchers determines whether the pattern contains any type of glob
// matcher. It will also return false if the pattern is an invalid expression.
func ContainsMatchers(pattern string) bool {
	rootNode, err := ast.Parse(lexer.NewLexer(pattern))
	if err != nil {
		return false
	}

	_, isStatic := staticText(rootNode)
	return !isStatic
}

// staticText returns the static string matcher represented by the AST unless
// it contains dynamic matchers (wildcards, etc.). In this case the ok return
// value is false.
func staticText(node *ast.Node) (text string, ok bool) {
	// nolint:exhaustive
	switch node.Kind {
	case ast.KindPattern:
		text := ""

		for _, child := range node.Children {
			childText, ok := staticText(child)
			if !ok {
				return "", false
			}

			text += childText
		}

		return text, true
	case ast.KindText:
		return node.Value.(ast.Text).Text, true
	case ast.KindNothing:
		return "", true
	default:
		return "", false
	}
}

// staticPrefix returns the file path inside the pattern up
// to the first path element that contains a wildcard.
func staticPrefix(pattern string) (string, error) {
	parts := strings.Split(pattern, stringSeparator)

	// nolint:prealloc
	var prefixPath []string
	for _, part := range parts {
		if part == "" {
			continue
		}

		rootNode, err := ast.Parse(lexer.NewLexer(part))
		if err != nil {
			return "", fmt.Errorf("parse glob pattern: %w", err)
		}

		staticPart, ok := staticText(rootNode)
		if !ok {
			break
		}

		prefixPath = append(prefixPath, staticPart)
	}
	prefix := strings.Join(prefixPath, stringSeparator)
	if len(pattern) > 0 && rune(pattern[0]) == runeSeparator && !strings.HasPrefix(prefix, stringSeparator) {
		prefix = stringSeparator + prefix
	}

	if prefix == "" {
		prefix = "."
	}

	return prefix, nil
}
