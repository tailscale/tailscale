package ruleguard

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/build"
	"go/printer"
	"io/ioutil"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/quasilyte/go-ruleguard/internal/gogrep"
	"github.com/quasilyte/go-ruleguard/nodetag"
	"github.com/quasilyte/go-ruleguard/ruleguard/goutil"
)

type rulesRunner struct {
	state *engineState

	ctx   *RunContext
	rules *goRuleSet

	gogrepState gogrep.MatcherState

	importer *goImporter

	filename string
	src      []byte

	// nodePath is a stack of ast.Nodes we visited to this point.
	// When we enter a new node, it's placed on the top of the stack.
	// When we leave that node, it's popped.
	// The stack is a slice that is allocated only once and reused
	// for the lifetime of the runner.
	// The only overhead it has is a slice append and pop operations
	// that are quire cheap.
	//
	// Note: we need this path to get a Node.Parent() for `$$` matches.
	// So it's used to climb up the tree there.
	// For named submatches we can't use it as the node can be located
	// deeper into the tree than the current node.
	// In those cases we need a more complicated algorithm.
	nodePath nodePath

	filterParams filterParams
}

func newRulesRunner(ctx *RunContext, buildContext *build.Context, state *engineState, rules *goRuleSet) *rulesRunner {
	importer := newGoImporter(state, goImporterConfig{
		fset:         ctx.Fset,
		debugImports: ctx.DebugImports,
		debugPrint:   ctx.DebugPrint,
		buildContext: buildContext,
	})
	gogrepState := gogrep.NewMatcherState()
	gogrepState.Types = ctx.Types
	rr := &rulesRunner{
		ctx:         ctx,
		importer:    importer,
		rules:       rules,
		gogrepState: gogrepState,
		nodePath:    newNodePath(),
		filterParams: filterParams{
			env:      state.env.GetEvalEnv(),
			importer: importer,
			ctx:      ctx,
		},
	}
	rr.filterParams.nodeText = rr.nodeText
	rr.filterParams.nodePath = &rr.nodePath
	return rr
}

func (rr *rulesRunner) nodeText(n ast.Node) []byte {
	if gogrep.IsEmptyNodeSlice(n) {
		return nil
	}

	from := rr.ctx.Fset.Position(n.Pos()).Offset
	to := rr.ctx.Fset.Position(n.End()).Offset
	src := rr.fileBytes()
	if (from >= 0 && from < len(src)) && (to >= 0 && to < len(src)) {
		return src[from:to]
	}

	// Go printer would panic on comments.
	if n, ok := n.(*ast.Comment); ok {
		return []byte(n.Text)
	}

	// Fallback to the printer.
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, rr.ctx.Fset, n); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func (rr *rulesRunner) fileBytes() []byte {
	if rr.src != nil {
		return rr.src
	}

	// TODO(quasilyte): re-use src slice?
	src, err := ioutil.ReadFile(rr.filename)
	if err != nil || src == nil {
		// Assign a zero-length slice so rr.src
		// is never nil during the second fileBytes call.
		rr.src = make([]byte, 0)
	} else {
		rr.src = src
	}
	return rr.src
}

func (rr *rulesRunner) run(f *ast.File) error {
	// If it's not empty then we're leaking memory.
	// For every Push() there should be a Pop() call.
	if rr.nodePath.Len() != 0 {
		panic("internal error: node path is not empty")
	}

	rr.filename = rr.ctx.Fset.Position(f.Pos()).Filename
	rr.filterParams.filename = rr.filename
	rr.collectImports(f)

	if rr.rules.universal.categorizedNum != 0 {
		var inspector astWalker
		inspector.nodePath = &rr.nodePath
		inspector.filterParams = &rr.filterParams
		inspector.Walk(f, func(n ast.Node) {
			rr.runRules(n)
		})
	}

	if len(rr.rules.universal.commentRules) != 0 {
		for _, commentGroup := range f.Comments {
			for _, comment := range commentGroup.List {
				rr.runCommentRules(comment)
			}
		}
	}

	return nil
}

func (rr *rulesRunner) runCommentRules(comment *ast.Comment) {
	// We'll need that file to create a token.Pos from the artificial offset.
	file := rr.ctx.Fset.File(comment.Pos())

	for _, rule := range rr.rules.universal.commentRules {
		var m commentMatchData
		if rule.captureGroups {
			result := rule.pat.FindStringSubmatchIndex(comment.Text)
			if result == nil {
				continue
			}
			for i, name := range rule.pat.SubexpNames() {
				if i == 0 || name == "" {
					continue
				}
				resultIndex := i * 2
				beginPos := result[resultIndex+0]
				endPos := result[resultIndex+1]
				// Negative index a special case when named group captured nothing.
				// Consider this pattern: `(?P<x>foo)|(bar)`.
				// If we have `bar` input string, <x> will remain empty.
				if beginPos < 0 || endPos < 0 {
					m.capture = append(m.capture, gogrep.CapturedNode{
						Name: name,
						Node: &ast.Comment{Slash: comment.Pos()},
					})
					continue
				}
				m.capture = append(m.capture, gogrep.CapturedNode{
					Name: name,
					Node: &ast.Comment{
						Slash: file.Pos(beginPos + file.Offset(comment.Pos())),
						Text:  comment.Text[beginPos:endPos],
					},
				})
			}
			m.node = &ast.Comment{
				Slash: file.Pos(result[0] + file.Offset(comment.Pos())),
				Text:  comment.Text[result[0]:result[1]],
			}
		} else {
			// Fast path: no need to save any submatches.
			result := rule.pat.FindStringIndex(comment.Text)
			if result == nil {
				continue
			}
			m.node = &ast.Comment{
				Slash: file.Pos(result[0] + file.Offset(comment.Pos())),
				Text:  comment.Text[result[0]:result[1]],
			}
		}

		accept := rr.handleCommentMatch(rule, m)
		if accept {
			break
		}
	}
}

func (rr *rulesRunner) runRules(n ast.Node) {
	tag := nodetag.FromNode(n)
	for _, rule := range rr.rules.universal.rulesByTag[tag] {
		matched := false
		rule.pat.MatchNode(&rr.gogrepState, n, func(m gogrep.MatchData) {
			matched = rr.handleMatch(rule, m)
		})
		if matched {
			break
		}
	}
}

func (rr *rulesRunner) reject(rule goRule, reason string, m matchData) {
	if rule.group.Name != rr.ctx.Debug {
		return // This rule is not being debugged
	}

	pos := rr.ctx.Fset.Position(m.Node().Pos())
	rr.ctx.DebugPrint(fmt.Sprintf("%s:%d: [%s:%d] rejected by %s",
		pos.Filename, pos.Line, filepath.Base(rule.group.Filename), rule.line, reason))

	values := make([]gogrep.CapturedNode, len(m.CaptureList()))
	copy(values, m.CaptureList())
	sort.Slice(values, func(i, j int) bool {
		return values[i].Name < values[j].Name
	})

	for _, v := range values {
		name := v.Name
		node := v.Node

		if comment, ok := node.(*ast.Comment); ok {
			s := strings.ReplaceAll(comment.Text, "\n", `\n`)
			rr.ctx.DebugPrint(fmt.Sprintf("  $%s: %s", name, s))
			continue
		}

		var expr ast.Expr
		switch node := node.(type) {
		case ast.Expr:
			expr = node
		case *ast.ExprStmt:
			expr = node.X
		default:
			continue
		}

		typ := rr.ctx.Types.TypeOf(expr)
		typeString := "<unknown>"
		if typ != nil {
			typeString = typ.String()
		}
		s := strings.ReplaceAll(goutil.SprintNode(rr.ctx.Fset, expr), "\n", `\n`)
		rr.ctx.DebugPrint(fmt.Sprintf("  $%s %s: %s", name, typeString, s))
	}
}

func (rr *rulesRunner) handleCommentMatch(rule goCommentRule, m commentMatchData) bool {
	if rule.base.filter.fn != nil {
		rr.filterParams.match = m
		filterResult := rule.base.filter.fn(&rr.filterParams)
		if !filterResult.Matched() {
			rr.reject(rule.base, filterResult.RejectReason(), m)
			return false
		}
	}

	message := rr.renderMessage(rule.base.msg, m, true)
	node := m.Node()
	if rule.base.location != "" {
		node, _ = m.CapturedByName(rule.base.location)
	}
	var suggestion *Suggestion
	if rule.base.suggestion != "" {
		suggestion = &Suggestion{
			Replacement: []byte(rr.renderMessage(rule.base.suggestion, m, false)),
			From:        node.Pos(),
			To:          node.End(),
		}
	}
	info := GoRuleInfo{
		Group: rule.base.group,
		Line:  rule.base.line,
	}
	rr.ctx.Report(info, node, message, suggestion)
	return true
}

func (rr *rulesRunner) handleMatch(rule goRule, m gogrep.MatchData) bool {
	if rule.filter.fn != nil {
		rr.filterParams.match = astMatchData{match: m}
		filterResult := rule.filter.fn(&rr.filterParams)
		if !filterResult.Matched() {
			rr.reject(rule, filterResult.RejectReason(), astMatchData{match: m})
			return false
		}
	}

	message := rr.renderMessage(rule.msg, astMatchData{match: m}, true)
	node := m.Node
	if rule.location != "" {
		node, _ = m.CapturedByName(rule.location)
	}
	var suggestion *Suggestion
	if rule.suggestion != "" {
		suggestion = &Suggestion{
			Replacement: []byte(rr.renderMessage(rule.suggestion, astMatchData{match: m}, false)),
			From:        node.Pos(),
			To:          node.End(),
		}
	}
	info := GoRuleInfo{
		Group: rule.group,
		Line:  rule.line,
	}
	rr.ctx.Report(info, node, message, suggestion)
	return true
}

func (rr *rulesRunner) collectImports(f *ast.File) {
	rr.filterParams.imports = make(map[string]struct{}, len(f.Imports))
	for _, spec := range f.Imports {
		s, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		rr.filterParams.imports[s] = struct{}{}
	}
}

func (rr *rulesRunner) renderMessage(msg string, m matchData, truncate bool) string {
	var buf strings.Builder
	if strings.Contains(msg, "$$") {
		buf.Write(rr.nodeText(m.Node()))
		msg = strings.ReplaceAll(msg, "$$", buf.String())
	}
	if len(m.CaptureList()) == 0 {
		return msg
	}

	capture := make([]gogrep.CapturedNode, len(m.CaptureList()))
	copy(capture, m.CaptureList())
	sort.Slice(capture, func(i, j int) bool {
		return len(capture[i].Name) > len(capture[j].Name)
	})

	for _, c := range capture {
		n := c.Node
		key := "$" + c.Name
		if !strings.Contains(msg, key) {
			continue
		}
		buf.Reset()
		buf.Write(rr.nodeText(n))
		// Don't interpolate strings that are too long.
		var replacement string
		if truncate && buf.Len() > 60 {
			replacement = key
		} else {
			replacement = buf.String()
		}
		msg = strings.ReplaceAll(msg, key, replacement)
	}
	return msg
}
