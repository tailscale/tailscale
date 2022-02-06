package golinters

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/daixiang0/gci/pkg/gci"
	"github.com/pkg/errors"
	"github.com/shazow/go-diff/difflib"
	"golang.org/x/tools/go/analysis"

	"github.com/golangci/golangci-lint/pkg/golinters/goanalysis"
	"github.com/golangci/golangci-lint/pkg/lint/linter"
)

const gciName = "gci"

func NewGci() *goanalysis.Linter {
	var mu sync.Mutex
	var resIssues []goanalysis.Issue
	differ := difflib.New()

	analyzer := &analysis.Analyzer{
		Name: gciName,
		Doc:  goanalysis.TheOnlyanalyzerDoc,
	}
	return goanalysis.NewLinter(
		gciName,
		"Gci control golang package import order and make it always deterministic.",
		[]*analysis.Analyzer{analyzer},
		nil,
	).WithContextSetter(func(lintCtx *linter.Context) {
		localFlag := lintCtx.Settings().Gci.LocalPrefixes
		goimportsFlag := lintCtx.Settings().Goimports.LocalPrefixes
		if localFlag == "" && goimportsFlag != "" {
			localFlag = goimportsFlag
		}

		analyzer.Run = func(pass *analysis.Pass) (interface{}, error) {
			var fileNames []string
			for _, f := range pass.Files {
				pos := pass.Fset.PositionFor(f.Pos(), false)
				fileNames = append(fileNames, pos.Filename)
			}

			var issues []goanalysis.Issue

			flagSet := gci.FlagSet{
				LocalFlag: gci.ParseLocalFlag(localFlag),
			}

			for _, f := range fileNames {
				source, result, err := gci.Run(f, &flagSet)
				if err != nil {
					return nil, err
				}
				if result == nil {
					continue
				}

				diff := bytes.Buffer{}
				_, err = diff.WriteString(fmt.Sprintf("--- %[1]s\n+++ %[1]s\n", f))
				if err != nil {
					return nil, fmt.Errorf("can't write diff header: %v", err)
				}

				err = differ.Diff(&diff, bytes.NewReader(source), bytes.NewReader(result))
				if err != nil {
					return nil, fmt.Errorf("can't get gci diff output: %v", err)
				}

				is, err := extractIssuesFromPatch(diff.String(), lintCtx.Log, lintCtx, gciName)
				if err != nil {
					return nil, errors.Wrapf(err, "can't extract issues from gci diff output %q", diff.String())
				}

				for i := range is {
					issues = append(issues, goanalysis.NewIssue(&is[i], pass))
				}
			}

			if len(issues) == 0 {
				return nil, nil
			}

			mu.Lock()
			resIssues = append(resIssues, issues...)
			mu.Unlock()

			return nil, nil
		}
	}).WithIssuesReporter(func(*linter.Context) []goanalysis.Issue {
		return resIssues
	}).WithLoadMode(goanalysis.LoadModeSyntax)
}
