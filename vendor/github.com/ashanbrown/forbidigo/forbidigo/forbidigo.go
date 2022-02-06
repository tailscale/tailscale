// forbidigo provides a linter for forbidding the use of specific identifiers
package forbidigo

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"log"
	"regexp"
	"strings"

	"github.com/pkg/errors"
)

type Issue interface {
	Details() string
	Position() token.Position
	String() string
}

type UsedIssue struct {
	identifier string
	pattern    string
	position   token.Position
}

func (a UsedIssue) Details() string {
	return fmt.Sprintf("use of `%s` forbidden by pattern `%s`", a.identifier, a.pattern)
}

func (a UsedIssue) Position() token.Position {
	return a.position
}

func (a UsedIssue) String() string { return toString(a) }

func toString(i Issue) string {
	return fmt.Sprintf("%s at %s", i.Details(), i.Position())
}

type Linter struct {
	cfg      config
	patterns []*regexp.Regexp
}

func DefaultPatterns() []string {
	return []string{`^(fmt\.Print(|f|ln)|print|println)$`}
}

//go:generate go-options config
type config struct {
	// don't check inside Godoc examples (see https://blog.golang.org/examples)
	ExcludeGodocExamples   bool `options:",true"`
	IgnorePermitDirectives bool // don't check for `permit` directives(for example, in favor of `nolint`)
}

func NewLinter(patterns []string, options ...Option) (*Linter, error) {
	cfg, err := newConfig(options...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to process options")
	}

	if len(patterns) == 0 {
		patterns = DefaultPatterns()
	}
	compiledPatterns := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("unable to compile pattern `%s`: %s", p, err)
		}
		compiledPatterns = append(compiledPatterns, re)
	}
	return &Linter{
		cfg:      cfg,
		patterns: compiledPatterns,
	}, nil
}

type visitor struct {
	cfg        config
	isTestFile bool // godoc only runs on test files

	linter   *Linter
	comments []*ast.CommentGroup

	fset   *token.FileSet
	issues []Issue
}

func (l *Linter) Run(fset *token.FileSet, nodes ...ast.Node) ([]Issue, error) {
	var issues []Issue //nolint:prealloc // we don't know how many there will be
	for _, node := range nodes {
		var comments []*ast.CommentGroup
		isTestFile := false
		isWholeFileExample := false
		if file, ok := node.(*ast.File); ok {
			comments = file.Comments
			fileName := fset.Position(file.Pos()).Filename
			isTestFile = strings.HasSuffix(fileName, "_test.go")

			// From https://blog.golang.org/examples, a "whole file example" is:
			// a file that ends in _test.go and contains exactly one example function,
			// no test or benchmark functions, and at least one other package-level declaration.
			if l.cfg.ExcludeGodocExamples && isTestFile && len(file.Decls) > 1 {
				numExamples := 0
				numTestsAndBenchmarks := 0
				for _, decl := range file.Decls {
					funcDecl, isFuncDecl := decl.(*ast.FuncDecl)
					// consider only functions, not methods
					if !isFuncDecl || funcDecl.Recv != nil || funcDecl.Name == nil {
						continue
					}
					funcName := funcDecl.Name.Name
					if strings.HasPrefix(funcName, "Test") || strings.HasPrefix(funcName, "Benchmark") {
						numTestsAndBenchmarks++
						break // not a whole file example
					}
					if strings.HasPrefix(funcName, "Example") {
						numExamples++
					}
				}

				// if this is a whole file example, skip this node
				isWholeFileExample = numExamples == 1 && numTestsAndBenchmarks == 0
			}
		}
		if isWholeFileExample {
			continue
		}
		visitor := visitor{
			cfg:        l.cfg,
			isTestFile: isTestFile,
			linter:     l,
			fset:       fset,
			comments:   comments,
		}
		ast.Walk(&visitor, node)
		issues = append(issues, visitor.issues...)
	}
	return issues, nil
}

func (v *visitor) Visit(node ast.Node) ast.Visitor {
	switch node := node.(type) {
	case *ast.FuncDecl:
		// don't descend into godoc examples if we are ignoring them
		isGodocExample := v.isTestFile && node.Recv == nil && node.Name != nil && strings.HasPrefix(node.Name.Name, "Example")
		if isGodocExample && v.cfg.ExcludeGodocExamples {
			return nil
		}
		return v
	case *ast.SelectorExpr:
	case *ast.Ident:
	default:
		return v
	}
	for _, p := range v.linter.patterns {
		if p.MatchString(v.textFor(node)) && !v.permit(node) {
			v.issues = append(v.issues, UsedIssue{
				identifier: v.textFor(node),
				pattern:    p.String(),
				position:   v.fset.Position(node.Pos()),
			})
		}
	}
	return nil
}

func (v *visitor) textFor(node ast.Node) string {
	buf := new(bytes.Buffer)
	if err := printer.Fprint(buf, v.fset, node); err != nil {
		log.Fatalf("ERROR: unable to print node at %s: %s", v.fset.Position(node.Pos()), err)
	}
	return buf.String()
}

func (v *visitor) permit(node ast.Node) bool {
	if v.cfg.IgnorePermitDirectives {
		return false
	}
	nodePos := v.fset.Position(node.Pos())
	var nolint = regexp.MustCompile(fmt.Sprintf(`^//\s?permit:%s\b`, regexp.QuoteMeta(v.textFor(node))))
	for _, c := range v.comments {
		commentPos := v.fset.Position(c.Pos())
		if commentPos.Line == nodePos.Line && len(c.List) > 0 && nolint.MatchString(c.List[0].Text) {
			return true
		}
	}
	return false
}
