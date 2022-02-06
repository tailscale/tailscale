package golinters

import (
	"strings"

	"github.com/golangci/golangci-lint/pkg/config"
	"github.com/golangci/golangci-lint/pkg/golinters/goanalysis"

	"github.com/butuzov/ireturn/analyzer"
	"golang.org/x/tools/go/analysis"
)

func NewIreturn(settings *config.IreturnSettings) *goanalysis.Linter {
	a := analyzer.NewAnalyzer()

	cfg := map[string]map[string]interface{}{}
	if settings != nil {
		cfg[a.Name] = map[string]interface{}{
			"allow":  strings.Join(settings.Allow, ","),
			"reject": strings.Join(settings.Reject, ","),
		}
	}

	return goanalysis.NewLinter(
		a.Name,
		a.Doc,
		[]*analysis.Analyzer{a},
		cfg,
	).WithLoadMode(goanalysis.LoadModeTypesInfo)
}
