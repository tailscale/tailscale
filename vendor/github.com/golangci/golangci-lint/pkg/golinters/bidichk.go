package golinters

import (
	"github.com/breml/bidichk/pkg/bidichk"
	"golang.org/x/tools/go/analysis"

	"github.com/golangci/golangci-lint/pkg/golinters/goanalysis"
)

func NewBiDiChkFuncName() *goanalysis.Linter {
	return goanalysis.NewLinter(
		"bidichk",
		"Checks for dangerous unicode character sequences",
		[]*analysis.Analyzer{bidichk.Analyzer},
		nil,
	).WithLoadMode(goanalysis.LoadModeSyntax)
}
