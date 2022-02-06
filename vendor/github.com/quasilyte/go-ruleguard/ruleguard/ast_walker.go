package ruleguard

import (
	"go/ast"
	"go/constant"
)

type astWalker struct {
	nodePath *nodePath

	filterParams *filterParams

	visit func(ast.Node)
}

func (w *astWalker) Walk(root ast.Node, visit func(ast.Node)) {
	w.visit = visit
	w.walk(root)
}

func (w *astWalker) walkIdentList(list []*ast.Ident) {
	for _, x := range list {
		w.walk(x)
	}
}

func (w *astWalker) walkExprList(list []ast.Expr) {
	for _, x := range list {
		w.walk(x)
	}
}

func (w *astWalker) walkStmtList(list []ast.Stmt) {
	for _, x := range list {
		w.walk(x)
	}
}

func (w *astWalker) walkDeclList(list []ast.Decl) {
	for _, x := range list {
		w.walk(x)
	}
}

func (w *astWalker) walk(n ast.Node) {
	w.nodePath.Push(n)
	defer w.nodePath.Pop()

	w.visit(n)

	switch n := n.(type) {
	case *ast.Field:
		// TODO: handle field types.
		// See #252
		w.walkIdentList(n.Names)
		w.walk(n.Type)

	case *ast.FieldList:
		for _, f := range n.List {
			w.walk(f)
		}

	case *ast.Ellipsis:
		if n.Elt != nil {
			w.walk(n.Elt)
		}

	case *ast.FuncLit:
		w.walk(n.Type)
		w.walk(n.Body)

	case *ast.CompositeLit:
		if n.Type != nil {
			w.walk(n.Type)
		}
		w.walkExprList(n.Elts)

	case *ast.ParenExpr:
		w.walk(n.X)

	case *ast.SelectorExpr:
		w.walk(n.X)
		w.walk(n.Sel)

	case *ast.IndexExpr:
		w.walk(n.X)
		w.walk(n.Index)

	case *ast.SliceExpr:
		w.walk(n.X)
		if n.Low != nil {
			w.walk(n.Low)
		}
		if n.High != nil {
			w.walk(n.High)
		}
		if n.Max != nil {
			w.walk(n.Max)
		}

	case *ast.TypeAssertExpr:
		w.walk(n.X)
		if n.Type != nil {
			w.walk(n.Type)
		}

	case *ast.CallExpr:
		w.walk(n.Fun)
		w.walkExprList(n.Args)

	case *ast.StarExpr:
		w.walk(n.X)

	case *ast.UnaryExpr:
		w.walk(n.X)

	case *ast.BinaryExpr:
		w.walk(n.X)
		w.walk(n.Y)

	case *ast.KeyValueExpr:
		w.walk(n.Key)
		w.walk(n.Value)

	case *ast.ArrayType:
		if n.Len != nil {
			w.walk(n.Len)
		}
		w.walk(n.Elt)

	case *ast.StructType:
		w.walk(n.Fields)

	case *ast.FuncType:
		if n.Params != nil {
			w.walk(n.Params)
		}
		if n.Results != nil {
			w.walk(n.Results)
		}

	case *ast.InterfaceType:
		w.walk(n.Methods)

	case *ast.MapType:
		w.walk(n.Key)
		w.walk(n.Value)

	case *ast.ChanType:
		w.walk(n.Value)

	case *ast.DeclStmt:
		w.walk(n.Decl)

	case *ast.LabeledStmt:
		w.walk(n.Label)
		w.walk(n.Stmt)

	case *ast.ExprStmt:
		w.walk(n.X)

	case *ast.SendStmt:
		w.walk(n.Chan)
		w.walk(n.Value)

	case *ast.IncDecStmt:
		w.walk(n.X)

	case *ast.AssignStmt:
		w.walkExprList(n.Lhs)
		w.walkExprList(n.Rhs)

	case *ast.GoStmt:
		w.walk(n.Call)

	case *ast.DeferStmt:
		w.walk(n.Call)

	case *ast.ReturnStmt:
		w.walkExprList(n.Results)

	case *ast.BranchStmt:
		if n.Label != nil {
			w.walk(n.Label)
		}

	case *ast.BlockStmt:
		w.walkStmtList(n.List)

	case *ast.IfStmt:
		if n.Init != nil {
			w.walk(n.Init)
		}
		w.walk(n.Cond)
		deadcode := w.filterParams.deadcode
		if !deadcode {
			cv := w.filterParams.ctx.Types.Types[n.Cond].Value
			if cv != nil {
				w.filterParams.deadcode = !deadcode && !constant.BoolVal(cv)
				w.walk(n.Body)
				w.filterParams.deadcode = !w.filterParams.deadcode
				if n.Else != nil {
					w.walk(n.Else)
				}
				w.filterParams.deadcode = deadcode
				return
			}
		}
		w.walk(n.Body)
		if n.Else != nil {
			w.walk(n.Else)
		}

	case *ast.CaseClause:
		w.walkExprList(n.List)
		w.walkStmtList(n.Body)

	case *ast.SwitchStmt:
		if n.Init != nil {
			w.walk(n.Init)
		}
		if n.Tag != nil {
			w.walk(n.Tag)
		}
		w.walk(n.Body)

	case *ast.TypeSwitchStmt:
		if n.Init != nil {
			w.walk(n.Init)
		}
		w.walk(n.Assign)
		w.walk(n.Body)

	case *ast.CommClause:
		if n.Comm != nil {
			w.walk(n.Comm)
		}
		w.walkStmtList(n.Body)

	case *ast.SelectStmt:
		w.walk(n.Body)

	case *ast.ForStmt:
		if n.Init != nil {
			w.walk(n.Init)
		}
		if n.Cond != nil {
			w.walk(n.Cond)
		}
		if n.Post != nil {
			w.walk(n.Post)
		}
		w.walk(n.Body)

	case *ast.RangeStmt:
		if n.Key != nil {
			w.walk(n.Key)
		}
		if n.Value != nil {
			w.walk(n.Value)
		}
		w.walk(n.X)
		w.walk(n.Body)

	case *ast.ImportSpec:
		if n.Name != nil {
			w.walk(n.Name)
		}
		w.walk(n.Path)
		if n.Comment != nil {
			w.walk(n.Comment)
		}

	case *ast.ValueSpec:
		if n.Doc != nil {
			w.walk(n.Doc)
		}
		w.walkIdentList(n.Names)
		if n.Type != nil {
			w.walk(n.Type)
		}
		w.walkExprList(n.Values)
		if n.Comment != nil {
			w.walk(n.Comment)
		}

	case *ast.TypeSpec:
		if n.Doc != nil {
			w.walk(n.Doc)
		}
		w.walk(n.Name)
		w.walk(n.Type)
		if n.Comment != nil {
			w.walk(n.Comment)
		}

	case *ast.GenDecl:
		if n.Doc != nil {
			w.walk(n.Doc)
		}
		for _, s := range n.Specs {
			w.walk(s)
		}

	case *ast.FuncDecl:
		if n.Doc != nil {
			w.walk(n.Doc)
		}
		if n.Recv != nil {
			w.walk(n.Recv)
		}
		w.walk(n.Name)
		w.walk(n.Type)
		if n.Body != nil {
			w.walk(n.Body)
		}

	case *ast.File:
		w.walk(n.Name)
		w.walkDeclList(n.Decls)
	}
}
