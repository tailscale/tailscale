package checkers

import (
	"go/ast"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-critic/go-critic/checkers/internal/astwalk"
	"github.com/go-critic/go-critic/framework/linter"
)

func init() {
	var info linter.CheckerInfo
	info.Name = "commentFormatting"
	info.Tags = []string{"style"}
	info.Summary = "Detects comments with non-idiomatic formatting"
	info.Before = `//This is a comment`
	info.After = `// This is a comment`

	collection.AddChecker(&info, func(ctx *linter.CheckerContext) (linter.FileWalker, error) {
		parts := []string{
			`^//go:generate .*$`, // e.g.: go:generate value
			`^//[\w-]+:.*$`,      // e.g.: key: value
			`^//nolint\b`,        // e.g.: nolint
			`^//line /.*:\d+`,    // e.g.: line /path/to/file:123
			`^//export \w+$`,     // e.g.: export Foo
			`^//[/+#-]+.*$`,      // e.g.: vertical breaker /////////////
		}
		pat := "(?m)" + strings.Join(parts, "|")
		pragmaRE := regexp.MustCompile(pat)
		return astwalk.WalkerForComment(&commentFormattingChecker{
			ctx:      ctx,
			pragmaRE: pragmaRE,
		}), nil
	})
}

type commentFormattingChecker struct {
	astwalk.WalkHandler
	ctx *linter.CheckerContext

	pragmaRE *regexp.Regexp
}

func (c *commentFormattingChecker) VisitComment(cg *ast.CommentGroup) {
	if strings.HasPrefix(cg.List[0].Text, "/*") {
		return
	}
	for _, comment := range cg.List {
		if len(comment.Text) <= len("// ") {
			continue
		}
		if c.pragmaRE.MatchString(comment.Text) {
			continue
		}

		// Make a decision based on a first comment text rune.
		r, _ := utf8.DecodeRuneInString(comment.Text[len("//"):])
		if !c.specialChar(r) && !unicode.IsSpace(r) {
			c.warn(comment)
			return
		}
	}
}

func (c *commentFormattingChecker) specialChar(r rune) bool {
	// Permitted list to avoid false-positives.
	switch r {
	case '+', '-', '#', '!':
		return true
	default:
		return false
	}
}

func (c *commentFormattingChecker) warn(comment *ast.Comment) {
	c.ctx.Warn(comment, "put a space between `//` and comment text")
}
