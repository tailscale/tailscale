package golinters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/token"
	"os"
	"reflect"

	"github.com/BurntSushi/toml"
	"github.com/mgechev/dots"
	reviveConfig "github.com/mgechev/revive/config"
	"github.com/mgechev/revive/lint"
	"github.com/mgechev/revive/rule"
	"github.com/pkg/errors"
	"golang.org/x/tools/go/analysis"

	"github.com/golangci/golangci-lint/pkg/config"
	"github.com/golangci/golangci-lint/pkg/golinters/goanalysis"
	"github.com/golangci/golangci-lint/pkg/lint/linter"
	"github.com/golangci/golangci-lint/pkg/logutils"
	"github.com/golangci/golangci-lint/pkg/result"
)

const reviveName = "revive"

var reviveDebugf = logutils.Debug("revive")

// jsonObject defines a JSON object of a failure
type jsonObject struct {
	Severity     lint.Severity
	lint.Failure `json:",inline"`
}

// NewRevive returns a new Revive linter.
func NewRevive(cfg *config.ReviveSettings) *goanalysis.Linter {
	var issues []goanalysis.Issue

	analyzer := &analysis.Analyzer{
		Name: goanalysis.TheOnlyAnalyzerName,
		Doc:  goanalysis.TheOnlyanalyzerDoc,
	}

	return goanalysis.NewLinter(
		reviveName,
		"Fast, configurable, extensible, flexible, and beautiful linter for Go. Drop-in replacement of golint.",
		[]*analysis.Analyzer{analyzer},
		nil,
	).WithContextSetter(func(lintCtx *linter.Context) {
		analyzer.Run = func(pass *analysis.Pass) (interface{}, error) {
			var files []string

			for _, file := range pass.Files {
				files = append(files, pass.Fset.PositionFor(file.Pos(), false).Filename)
			}

			conf, err := getReviveConfig(cfg)
			if err != nil {
				return nil, err
			}

			formatter, err := reviveConfig.GetFormatter("json")
			if err != nil {
				return nil, err
			}

			revive := lint.New(os.ReadFile)

			lintingRules, err := reviveConfig.GetLintingRules(conf)
			if err != nil {
				return nil, err
			}

			packages, err := dots.ResolvePackages(files, []string{})
			if err != nil {
				return nil, err
			}

			failures, err := revive.Lint(packages, lintingRules, *conf)
			if err != nil {
				return nil, err
			}

			formatChan := make(chan lint.Failure)
			exitChan := make(chan bool)

			var output string
			go func() {
				output, err = formatter.Format(formatChan, *conf)
				if err != nil {
					lintCtx.Log.Errorf("Format error: %v", err)
				}
				exitChan <- true
			}()

			for f := range failures {
				if f.Confidence < conf.Confidence {
					continue
				}

				formatChan <- f
			}

			close(formatChan)
			<-exitChan

			var results []jsonObject
			err = json.Unmarshal([]byte(output), &results)
			if err != nil {
				return nil, err
			}

			for i := range results {
				issues = append(issues, reviveToIssue(pass, &results[i]))
			}

			return nil, nil
		}
	}).WithIssuesReporter(func(*linter.Context) []goanalysis.Issue {
		return issues
	}).WithLoadMode(goanalysis.LoadModeSyntax)
}

func reviveToIssue(pass *analysis.Pass, object *jsonObject) goanalysis.Issue {
	lineRangeTo := object.Position.End.Line
	if object.RuleName == (&rule.ExportedRule{}).Name() {
		lineRangeTo = object.Position.Start.Line
	}

	return goanalysis.NewIssue(&result.Issue{
		Severity: string(object.Severity),
		Text:     fmt.Sprintf("%s: %s", object.RuleName, object.Failure.Failure),
		Pos: token.Position{
			Filename: object.Position.Start.Filename,
			Line:     object.Position.Start.Line,
			Offset:   object.Position.Start.Offset,
			Column:   object.Position.Start.Column,
		},
		LineRange: &result.Range{
			From: object.Position.Start.Line,
			To:   lineRangeTo,
		},
		FromLinter: reviveName,
	}, pass)
}

// This function mimics the GetConfig function of revive.
// This allow to get default values and right types.
// https://github.com/golangci/golangci-lint/issues/1745
// https://github.com/mgechev/revive/blob/389ba853b0b3587f0c3b71b5f0c61ea4e23928ec/config/config.go#L155
func getReviveConfig(cfg *config.ReviveSettings) (*lint.Config, error) {
	conf := defaultConfig()

	if !reflect.DeepEqual(cfg, &config.ReviveSettings{}) {
		rawRoot := createConfigMap(cfg)
		buf := bytes.NewBuffer(nil)

		err := toml.NewEncoder(buf).Encode(rawRoot)
		if err != nil {
			return nil, errors.Wrap(err, "failed to encode configuration")
		}

		conf = &lint.Config{}
		_, err = toml.DecodeReader(buf, conf)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode configuration")
		}
	}

	normalizeConfig(conf)

	reviveDebugf("revive configuration: %#v", conf)

	return conf, nil
}

func createConfigMap(cfg *config.ReviveSettings) map[string]interface{} {
	rawRoot := map[string]interface{}{
		"ignoreGeneratedHeader": cfg.IgnoreGeneratedHeader,
		"confidence":            cfg.Confidence,
		"severity":              cfg.Severity,
		"errorCode":             cfg.ErrorCode,
		"warningCode":           cfg.WarningCode,
		"enableAllRules":        cfg.EnableAllRules,
	}

	rawDirectives := map[string]map[string]interface{}{}
	for _, directive := range cfg.Directives {
		rawDirectives[directive.Name] = map[string]interface{}{
			"severity": directive.Severity,
		}
	}

	if len(rawDirectives) > 0 {
		rawRoot["directive"] = rawDirectives
	}

	rawRules := map[string]map[string]interface{}{}
	for _, s := range cfg.Rules {
		rawRules[s.Name] = map[string]interface{}{
			"severity":  s.Severity,
			"arguments": safeTomlSlice(s.Arguments),
			"disabled":  s.Disabled,
		}
	}

	if len(rawRules) > 0 {
		rawRoot["rule"] = rawRules
	}

	return rawRoot
}

func safeTomlSlice(r []interface{}) []interface{} {
	if len(r) == 0 {
		return nil
	}

	if _, ok := r[0].(map[interface{}]interface{}); !ok {
		return r
	}

	var typed []interface{}
	for _, elt := range r {
		item := map[string]interface{}{}
		for k, v := range elt.(map[interface{}]interface{}) {
			item[k.(string)] = v
		}

		typed = append(typed, item)
	}

	return typed
}

// This element is not exported by revive, so we need copy the code.
// Extracted from https://github.com/mgechev/revive/blob/389ba853b0b3587f0c3b71b5f0c61ea4e23928ec/config/config.go#L15
var defaultRules = []lint.Rule{
	&rule.VarDeclarationsRule{},
	&rule.PackageCommentsRule{},
	&rule.DotImportsRule{},
	&rule.BlankImportsRule{},
	&rule.ExportedRule{},
	&rule.VarNamingRule{},
	&rule.IndentErrorFlowRule{},
	&rule.RangeRule{},
	&rule.ErrorfRule{},
	&rule.ErrorNamingRule{},
	&rule.ErrorStringsRule{},
	&rule.ReceiverNamingRule{},
	&rule.IncrementDecrementRule{},
	&rule.ErrorReturnRule{},
	&rule.UnexportedReturnRule{},
	&rule.TimeNamingRule{},
	&rule.ContextKeysType{},
	&rule.ContextAsArgumentRule{},
}

// This element is not exported by revive, so we need copy the code.
// Extracted from https://github.com/mgechev/revive/blob/389ba853b0b3587f0c3b71b5f0c61ea4e23928ec/config/config.go#L133
func normalizeConfig(cfg *lint.Config) {
	if cfg.Confidence == 0 {
		cfg.Confidence = 0.8
	}
	severity := cfg.Severity
	if severity != "" {
		for k, v := range cfg.Rules {
			if v.Severity == "" {
				v.Severity = severity
			}
			cfg.Rules[k] = v
		}
		for k, v := range cfg.Directives {
			if v.Severity == "" {
				v.Severity = severity
			}
			cfg.Directives[k] = v
		}
	}
}

// This element is not exported by revive, so we need copy the code.
// Extracted from https://github.com/mgechev/revive/blob/389ba853b0b3587f0c3b71b5f0c61ea4e23928ec/config/config.go#L182
func defaultConfig() *lint.Config {
	defaultConfig := lint.Config{
		Confidence: 0.0,
		Severity:   lint.SeverityWarning,
		Rules:      map[string]lint.RuleConfig{},
	}
	for _, r := range defaultRules {
		defaultConfig.Rules[r.Name()] = lint.RuleConfig{}
	}
	return &defaultConfig
}
