// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package jsontags

import (
	"fmt"
	"go/types"
	"os"
	"strings"

	_ "embed"

	"golang.org/x/tools/go/analysis"
	"tailscale.com/util/set"
)

var jsontagsAllowlist map[ReportKind]set.Set[string]

// ParseAllowlist parses an allowlist of reports to ignore,
// which is a newline-delimited list of tuples separated by a tab,
// where each tuple is a [ReportKind] and a fully-qualified field name.
//
// For example:
//
//	OmitEmptyUnsupportedInV1	tailscale.com/path/to/package.StructType.FieldName
//	OmitEmptyUnsupportedInV1	tailscale.com/path/to/package.*.FieldName
//
// The struct type name may be "*" for anonymous struct types such
// as those declared within a function or as a type literal in a variable.
func ParseAllowlist(s string) map[ReportKind]set.Set[string] {
	var allowlist map[ReportKind]set.Set[string]
	for line := range strings.SplitSeq(s, "\n") {
		kind, field, _ := strings.Cut(strings.TrimSpace(line), "\t")
		if allowlist == nil {
			allowlist = make(map[ReportKind]set.Set[string])
		}
		fields := allowlist[ReportKind(kind)]
		if fields == nil {
			fields = make(set.Set[string])
		}
		fields.Add(field)
		allowlist[ReportKind(kind)] = fields
	}
	return allowlist
}

// RegisterAllowlist registers an allowlist of reports to ignore,
// which is represented by a set of fully-qualified field names
// for each [ReportKind].
//
// For example:
//
//	{
//		"OmitEmptyUnsupportedInV1": set.Of(
//			"tailscale.com/path/to/package.StructType.FieldName",
//			"tailscale.com/path/to/package.*.FieldName",
//		),
//	}
//
// The struct type name may be "*" for anonymous struct types such
// as those declared within a function or as a type literal in a variable.
//
// This must be called at init and the input must not be mutated.
func RegisterAllowlist(allowlist map[ReportKind]set.Set[string]) {
	jsontagsAllowlist = allowlist
}

type ReportKind string

const (
	OmitEmptyUnsupportedInV1              ReportKind = "OmitEmptyUnsupportedInV1"
	OmitEmptyUnsupportedInV2              ReportKind = "OmitEmptyUnsupportedInV2"
	OmitEmptyShouldBeOmitZero             ReportKind = "OmitEmptyShouldBeOmitZero"
	OmitEmptyShouldBeOmitZeroButHasIsZero ReportKind = "OmitEmptyShouldBeOmitZeroButHasIsZero"
	StringOnNonNumericKind                ReportKind = "StringOnNonNumericKind"
	FormatMissingOnTimeDuration           ReportKind = "FormatMissingOnTimeDuration"
)

func (k ReportKind) message() string {
	switch k {
	case OmitEmptyUnsupportedInV1:
		return "uses `omitempty` on an unsupported type in json/v1; should probably use `omitzero` instead"
	case OmitEmptyUnsupportedInV2:
		return "uses `omitempty` on an unsupported type in json/v2; should probably use `omitzero` instead"
	case OmitEmptyShouldBeOmitZero:
		return "should use `omitzero` instead of `omitempty`"
	case OmitEmptyShouldBeOmitZeroButHasIsZero:
		return "should probably use `omitzero` instead of `omitempty`"
	case StringOnNonNumericKind:
		return "must not use `string` on non-numeric types"
	case FormatMissingOnTimeDuration:
		return "must use an explicit `format` tag (e.g., `format:nano`) on a time.Duration type; see https://go.dev/issue/71631"
	default:
		return string(k)
	}
}

func report(pass *analysis.Pass, structType *types.Struct, fieldVar *types.Var, k ReportKind) {
	// Lookup the full name of the struct type.
	var fullName string
	for _, name := range pass.Pkg.Scope().Names() {
		if obj := pass.Pkg.Scope().Lookup(name); obj != nil {
			if named, ok := obj.(*types.TypeName); ok {
				if types.Identical(named.Type().Underlying(), structType) {
					fullName = fmt.Sprintf("%v.%v.%v", named.Pkg().Path(), named.Name(), fieldVar.Name())
					break
				}
			}
		}
	}
	if fullName == "" {
		// Full name could not be found since this is probably an anonymous type
		// or locally declared within a function scope.
		// Use just the package path and field name instead.
		// This is imprecise, but better than nothing.
		fullName = fmt.Sprintf("%s.*.%s", fieldVar.Pkg().Path(), fieldVar.Name())
	}
	if jsontagsAllowlist[k].Contains(fullName) {
		return
	}

	const appendAllowlist = ""
	if appendAllowlist != "" {
		if f, err := os.OpenFile(appendAllowlist, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0664); err == nil {
			fmt.Fprintf(f, "%v\t%v\n", k, fullName)
			f.Close()
		}
	}

	pass.Report(analysis.Diagnostic{
		Pos:     fieldVar.Pos(),
		Message: fmt.Sprintf("field %q %s", fieldVar.Name(), k.message()),
	})
}
