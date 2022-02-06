package analyzer

import (
	"flag"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/gostaticanalysis/analysisutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const (
	doc       = "thelper detects tests helpers which is not start with t.Helper() method."
	checksDoc = `coma separated list of enabled checks

Available checks

` + checkTBegin + ` - check t.Helper() begins helper function
` + checkTFirst + ` - check *testing.T is first param of helper function
` + checkTName + `  - check *testing.T param has t name

Also available similar checks for benchmark and TB helpers: ` +
		checkBBegin + `, ` + checkBFirst + `, ` + checkBName + `,` +
		checkTBBegin + `, ` + checkTBFirst + `, ` + checkTBName + `

`
)

type enabledChecksValue map[string]struct{}

func (m enabledChecksValue) Enabled(c string) bool {
	_, ok := m[c]
	return ok
}

func (m enabledChecksValue) String() string {
	ss := make([]string, 0, len(m))
	for s := range m {
		ss = append(ss, s)
	}
	sort.Strings(ss)
	return strings.Join(ss, ",")
}

func (m enabledChecksValue) Set(s string) error {
	ss := strings.FieldsFunc(s, func(c rune) bool { return c == ',' })
	if len(ss) == 0 {
		return nil
	}

	for k := range m {
		delete(m, k)
	}
	for _, v := range ss {
		switch v {
		case checkTBegin, checkTFirst, checkTName,
			checkBBegin, checkBFirst, checkBName,
			checkTBBegin, checkTBFirst, checkTBName:
			m[v] = struct{}{}
		default:
			return fmt.Errorf("unknown check name %q (see help for full list)", v)
		}
	}
	return nil
}

const (
	checkTBegin  = "t_begin"
	checkTFirst  = "t_first"
	checkTName   = "t_name"
	checkBBegin  = "b_begin"
	checkBFirst  = "b_first"
	checkBName   = "b_name"
	checkTBBegin = "tb_begin"
	checkTBFirst = "tb_first"
	checkTBName  = "tb_name"
)

type thelper struct {
	enabledChecks enabledChecksValue
}

// NewAnalyzer return a new thelper analyzer.
// thelper analyzes Go test codes how they use t.Helper() method.
func NewAnalyzer() *analysis.Analyzer {
	thelper := thelper{}
	thelper.enabledChecks = enabledChecksValue{
		checkTBegin:  struct{}{},
		checkTFirst:  struct{}{},
		checkTName:   struct{}{},
		checkBBegin:  struct{}{},
		checkBFirst:  struct{}{},
		checkBName:   struct{}{},
		checkTBBegin: struct{}{},
		checkTBFirst: struct{}{},
		checkTBName:  struct{}{},
	}

	a := &analysis.Analyzer{
		Name: "thelper",
		Doc:  doc,
		Run:  thelper.run,
		Requires: []*analysis.Analyzer{
			inspect.Analyzer,
		},
	}

	a.Flags.Init("thelper", flag.ExitOnError)
	a.Flags.Var(&thelper.enabledChecks, "checks", checksDoc)

	return a
}

func (t thelper) run(pass *analysis.Pass) (interface{}, error) {
	tCheckOpts, bCheckOpts, tbCheckOpts, ok := t.buildCheckFuncOpts(pass)
	if !ok {
		return nil, nil
	}

	var reports reports
	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	nodeFilter := []ast.Node{
		(*ast.FuncDecl)(nil),
		(*ast.FuncLit)(nil),
		(*ast.CallExpr)(nil),
	}
	inspect.Preorder(nodeFilter, func(node ast.Node) {
		var fd funcDecl
		switch n := node.(type) {
		case *ast.FuncLit:
			fd.Pos = n.Pos()
			fd.Type = n.Type
			fd.Body = n.Body
			fd.Name = ast.NewIdent("")
		case *ast.FuncDecl:
			fd.Pos = n.Name.NamePos
			fd.Type = n.Type
			fd.Body = n.Body
			fd.Name = n.Name
		case *ast.CallExpr:
			tbRunSubtestExpr := extractSubtestExp(pass, n, tCheckOpts.tbRun)
			if tbRunSubtestExpr == nil {
				tbRunSubtestExpr = extractSubtestExp(pass, n, bCheckOpts.tbRun)
			}

			if tbRunSubtestExpr != nil {
				reports.Filter(funcDefPosition(pass, tbRunSubtestExpr))
			} else {
				reports.NoFilter(funcDefPosition(pass, n.Fun))
			}
			return
		default:
			return
		}

		checkFunc(pass, &reports, fd, tCheckOpts)
		checkFunc(pass, &reports, fd, bCheckOpts)
		checkFunc(pass, &reports, fd, tbCheckOpts)
	})

	reports.Flush(pass)

	return nil, nil
}

type checkFuncOpts struct {
	skipPrefix string
	varName    string
	tbHelper   types.Object
	tbRun      types.Object
	tbType     types.Type
	ctxType    types.Type
	checkBegin bool
	checkFirst bool
	checkName  bool
}

func (t thelper) buildCheckFuncOpts(pass *analysis.Pass) (checkFuncOpts, checkFuncOpts, checkFuncOpts, bool) {
	var ctxType types.Type
	ctxObj := analysisutil.ObjectOf(pass, "context", "Context")
	if ctxObj != nil {
		ctxType = ctxObj.Type()
	}

	tCheckOpts, ok := t.buildTestCheckFuncOpts(pass, ctxType)
	if !ok {
		return checkFuncOpts{}, checkFuncOpts{}, checkFuncOpts{}, false
	}

	bCheckOpts, ok := t.buildBenchmarkCheckFuncOpts(pass, ctxType)
	if !ok {
		return checkFuncOpts{}, checkFuncOpts{}, checkFuncOpts{}, false
	}

	tbCheckOpts, ok := t.buildTBCheckFuncOpts(pass, ctxType)
	if !ok {
		return checkFuncOpts{}, checkFuncOpts{}, checkFuncOpts{}, false
	}

	return tCheckOpts, bCheckOpts, tbCheckOpts, true
}

func (t thelper) buildTestCheckFuncOpts(pass *analysis.Pass, ctxType types.Type) (checkFuncOpts, bool) {
	tObj := analysisutil.ObjectOf(pass, "testing", "T")
	if tObj == nil {
		return checkFuncOpts{}, false
	}

	tHelper, _, _ := types.LookupFieldOrMethod(tObj.Type(), true, tObj.Pkg(), "Helper")
	if tHelper == nil {
		return checkFuncOpts{}, false
	}

	tRun, _, _ := types.LookupFieldOrMethod(tObj.Type(), true, tObj.Pkg(), "Run")
	if tRun == nil {
		return checkFuncOpts{}, false
	}

	return checkFuncOpts{
		skipPrefix: "Test",
		varName:    "t",
		tbHelper:   tHelper,
		tbRun:      tRun,
		tbType:     types.NewPointer(tObj.Type()),
		ctxType:    ctxType,
		checkBegin: t.enabledChecks.Enabled(checkTBegin),
		checkFirst: t.enabledChecks.Enabled(checkTFirst),
		checkName:  t.enabledChecks.Enabled(checkTName),
	}, true
}

func (t thelper) buildBenchmarkCheckFuncOpts(pass *analysis.Pass, ctxType types.Type) (checkFuncOpts, bool) {
	bObj := analysisutil.ObjectOf(pass, "testing", "B")
	if bObj == nil {
		return checkFuncOpts{}, false
	}

	bHelper, _, _ := types.LookupFieldOrMethod(bObj.Type(), true, bObj.Pkg(), "Helper")
	if bHelper == nil {
		return checkFuncOpts{}, false
	}

	bRun, _, _ := types.LookupFieldOrMethod(bObj.Type(), true, bObj.Pkg(), "Run")
	if bRun == nil {
		return checkFuncOpts{}, false
	}

	return checkFuncOpts{
		skipPrefix: "Benchmark",
		varName:    "b",
		tbHelper:   bHelper,
		tbRun:      bRun,
		tbType:     types.NewPointer(bObj.Type()),
		ctxType:    ctxType,
		checkBegin: t.enabledChecks.Enabled(checkBBegin),
		checkFirst: t.enabledChecks.Enabled(checkBFirst),
		checkName:  t.enabledChecks.Enabled(checkBName),
	}, true
}

func (t thelper) buildTBCheckFuncOpts(pass *analysis.Pass, ctxType types.Type) (checkFuncOpts, bool) {
	tbObj := analysisutil.ObjectOf(pass, "testing", "TB")
	if tbObj == nil {
		return checkFuncOpts{}, false
	}

	tbHelper, _, _ := types.LookupFieldOrMethod(tbObj.Type(), true, tbObj.Pkg(), "Helper")
	if tbHelper == nil {
		return checkFuncOpts{}, false
	}

	return checkFuncOpts{
		skipPrefix: "",
		varName:    "tb",
		tbHelper:   tbHelper,
		tbType:     tbObj.Type(),
		ctxType:    ctxType,
		checkBegin: t.enabledChecks.Enabled(checkTBBegin),
		checkFirst: t.enabledChecks.Enabled(checkTBFirst),
		checkName:  t.enabledChecks.Enabled(checkTBName),
	}, true
}

type funcDecl struct {
	Pos  token.Pos
	Name *ast.Ident
	Type *ast.FuncType
	Body *ast.BlockStmt
}

func checkFunc(pass *analysis.Pass, reports *reports, funcDecl funcDecl, opts checkFuncOpts) {
	if opts.skipPrefix != "" && strings.HasPrefix(funcDecl.Name.Name, opts.skipPrefix) {
		return
	}

	p, pos, ok := searchFuncParam(pass, funcDecl, opts.tbType)
	if !ok {
		return
	}

	if opts.checkFirst {
		if pos != 0 {
			checkFirstPassed := false
			if pos == 1 && opts.ctxType != nil {
				_, pos, ok := searchFuncParam(pass, funcDecl, opts.ctxType)
				checkFirstPassed = ok && (pos == 0)
			}

			if !checkFirstPassed {
				reports.Reportf(funcDecl.Pos, "parameter %s should be the first or after context.Context", opts.tbType)
			}
		}
	}

	if len(p.Names) > 0 && p.Names[0].Name != "_" {
		if opts.checkName {
			if p.Names[0].Name != opts.varName {
				reports.Reportf(funcDecl.Pos, "parameter %s should have name %s", opts.tbType, opts.varName)
			}
		}

		if opts.checkBegin {
			if len(funcDecl.Body.List) == 0 || !isTHelperCall(pass, funcDecl.Body.List[0], opts.tbHelper) {
				reports.Reportf(funcDecl.Pos, "test helper function should start from %s.Helper()", opts.varName)
			}
		}
	}
}

func searchFuncParam(pass *analysis.Pass, f funcDecl, p types.Type) (*ast.Field, int, bool) {
	for i, f := range f.Type.Params.List {
		typeInfo, ok := pass.TypesInfo.Types[f.Type]
		if !ok {
			continue
		}

		if types.Identical(typeInfo.Type, p) {
			return f, i, true
		}
	}
	return nil, 0, false
}

func isTHelperCall(pass *analysis.Pass, s ast.Stmt, tHelper types.Object) bool {
	exprStmt, ok := s.(*ast.ExprStmt)
	if !ok {
		return false
	}

	callExpr, ok := exprStmt.X.(*ast.CallExpr)
	if !ok {
		return false
	}

	selExpr, ok := callExpr.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	return isSelectorCall(pass, selExpr, tHelper)
}

func extractSubtestExp(pass *analysis.Pass, e *ast.CallExpr, tbRun types.Object) ast.Expr {
	selExpr, ok := e.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}

	if !isSelectorCall(pass, selExpr, tbRun) {
		return nil
	}

	if len(e.Args) != 2 {
		return nil
	}

	return e.Args[1]
}

func funcDefPosition(pass *analysis.Pass, e ast.Expr) token.Pos {
	anonFunLit, ok := e.(*ast.FuncLit)
	if ok {
		return anonFunLit.Pos()
	}

	funIdent, ok := e.(*ast.Ident)
	if !ok {
		selExpr, ok := e.(*ast.SelectorExpr)
		if !ok {
			return token.NoPos
		}
		funIdent = selExpr.Sel
	}

	funDef, ok := pass.TypesInfo.Uses[funIdent]
	if !ok {
		return token.NoPos
	}

	return funDef.Pos()
}

func isSelectorCall(pass *analysis.Pass, selExpr *ast.SelectorExpr, callObj types.Object) bool {
	sel, ok := pass.TypesInfo.Selections[selExpr]
	if !ok {
		return false
	}

	return sel.Obj() == callObj
}
