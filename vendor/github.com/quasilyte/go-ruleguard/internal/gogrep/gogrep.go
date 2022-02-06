package gogrep

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/quasilyte/go-ruleguard/nodetag"
)

func IsEmptyNodeSlice(n ast.Node) bool {
	if list, ok := n.(NodeSlice); ok {
		return list.Len() == 0
	}
	return false
}

// MatchData describes a successful pattern match.
type MatchData struct {
	Node    ast.Node
	Capture []CapturedNode
}

type CapturedNode struct {
	Name string
	Node ast.Node
}

func (data MatchData) CapturedByName(name string) (ast.Node, bool) {
	if name == "$$" {
		return data.Node, true
	}
	return findNamed(data.Capture, name)
}

type MatcherState struct {
	Types *types.Info

	// node values recorded by name, excluding "_" (used only by the
	// actual matching phase)
	capture []CapturedNode

	pc int
}

func NewMatcherState() MatcherState {
	return MatcherState{
		capture: make([]CapturedNode, 0, 8),
	}
}

type Pattern struct {
	m *matcher
}

type PatternInfo struct {
	Vars map[string]struct{}
}

func (p *Pattern) NodeTag() nodetag.Value {
	return operationInfoTable[p.m.prog.insts[0].op].Tag
}

// MatchNode calls cb if n matches a pattern.
func (p *Pattern) MatchNode(state *MatcherState, n ast.Node, cb func(MatchData)) {
	p.m.MatchNode(state, n, cb)
}

// Clone creates a pattern copy.
func (p *Pattern) Clone() *Pattern {
	clone := *p
	clone.m = &matcher{}
	*clone.m = *p.m
	return &clone
}

func Compile(fset *token.FileSet, src string, strict bool) (*Pattern, PatternInfo, error) {
	info := newPatternInfo()
	n, err := parseExpr(fset, src)
	if err != nil {
		return nil, info, err
	}
	var c compiler
	prog, err := c.Compile(fset, n, &info, strict)
	if err != nil {
		return nil, info, err
	}
	m := newMatcher(prog)
	return &Pattern{m: m}, info, nil
}

func newPatternInfo() PatternInfo {
	return PatternInfo{
		Vars: map[string]struct{}{},
	}
}
