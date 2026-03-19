// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package freedesktop provides helpers for freedesktop systems.
package freedesktop

import "strings"

const needsEscape = " \t\n\"'\\><~|&;$*?#()`"

var escaper = strings.NewReplacer(`"`, `\"`, "`", "\\`", `$`, `\$`, `\`, `\\`)

// Quote quotes according to the Desktop Entry Specification, as below:
//
// Arguments may be quoted in whole. If an argument contains a reserved
// character the argument must be quoted. The rules for quoting of arguments is
// also applicable to the executable name or path of the executable program as
// provided.
//
// Quoting must be done by enclosing the argument between double quotes and
// escaping the double quote character, backtick character ("`"), dollar sign
// ("$") and backslash character ("\") by preceding it with an additional
// backslash character. Implementations must undo quoting before expanding field
// codes and before passing the argument to the executable program. Reserved
// characters are space (" "), tab, newline, double quote, single quote ("'"),
// backslash character ("\"), greater-than sign (">"), less-than sign ("<"),
// tilde ("~"), vertical bar ("|"), ampersand ("&"), semicolon (";"), dollar
// sign ("$"), asterisk ("*"), question mark ("?"), hash mark ("#"), parenthesis
// ("(") and (")") and backtick character ("`").
func Quote(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, needsEscape) {
		return s
	}

	var b strings.Builder
	b.WriteString(`"`)
	escaper.WriteString(&b, s)
	b.WriteString(`"`)
	return b.String()
}
