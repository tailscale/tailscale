package chglog

import (
	"bytes"
	"fmt"
	"text/template"
)

// FormatChangelog format pkgLogs from a text/template.
func FormatChangelog(pkgLogs *PackageChangeLog, tpl *template.Template) (string, error) {
	var data bytes.Buffer
	if err := tpl.Execute(&data, pkgLogs); err != nil {
		return data.String(), fmt.Errorf("error formatting: %w", err)
	}

	return data.String(), nil
}
