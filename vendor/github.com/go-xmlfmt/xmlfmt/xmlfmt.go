////////////////////////////////////////////////////////////////////////////
// Porgram: xmlfmt.go
// Purpose: Go XML Beautify from XML string using pure string manipulation
// Authors: Antonio Sun (c) 2016-2021, All rights reserved
////////////////////////////////////////////////////////////////////////////

package xmlfmt

import (
	"html"
	"regexp"
	"strings"
)

var (
	reg = regexp.MustCompile(`<([/!]?)([^>]+?)(/?)>`)
	// NL is the newline string used in XML output, define for DOS-convenient.
	NL = "\r\n"
)

// FormatXML will (purly) reformat the XML string in a readable way, without any rewriting/altering the structure.
// If your XML Comments have nested tags in them, or you're not 100% sure otherwise, pass `true` as the third parameter to this function. But don't turn it on blindly, as the code has become ten times more complicated because of it.
func FormatXML(xmls, prefix, indent string, nestedTagsInComments ...bool) string {
	nestedTagsInComment := false
	if len(nestedTagsInComments) > 0 {
		nestedTagsInComment = nestedTagsInComments[0]
	}
	reXmlComments := regexp.MustCompile(`(?s)(<!--)(.*?)(-->)`)
	src := regexp.MustCompile(`(?s)>\s+<`).ReplaceAllString(xmls, "><")
	if nestedTagsInComment {
		src = reXmlComments.ReplaceAllStringFunc(src, func(m string) string {
			parts := reXmlComments.FindStringSubmatch(m)
			p2 := regexp.MustCompile(`\r*\n`).ReplaceAllString(parts[2], " ")
			return parts[1] + html.EscapeString(p2) + parts[3]
		})
	}
	rf := replaceTag(prefix, indent)
	r := prefix + reg.ReplaceAllStringFunc(src, rf)
	if nestedTagsInComment {
		r = reXmlComments.ReplaceAllStringFunc(r, func(m string) string {
			parts := reXmlComments.FindStringSubmatch(m)
			return parts[1] + html.UnescapeString(parts[2]) + parts[3]
		})
	}

	return r
}

// replaceTag returns a closure function to do 's/(?<=>)\s+(?=<)//g; s(<(/?)([^>]+?)(/?)>)($indent+=$3?0:$1?-1:1;"<$1$2$3>"."\n".("  "x$indent))ge' as in Perl
// and deal with comments as well
func replaceTag(prefix, indent string) func(string) string {
	indentLevel := 0
	return func(m string) string {
		// head elem
		if strings.HasPrefix(m, "<?xml") {
			return NL + prefix + strings.Repeat(indent, indentLevel) + m
		}
		// empty elem
		if strings.HasSuffix(m, "/>") {
			return NL + prefix + strings.Repeat(indent, indentLevel) + m
		}
		// comment elem
		if strings.HasPrefix(m, "<!") {
			return NL + prefix + strings.Repeat(indent, indentLevel) + m
		}
		// end elem
		if strings.HasPrefix(m, "</") {
			indentLevel--
			return NL + prefix + strings.Repeat(indent, indentLevel) + m
		}
		defer func() {
			indentLevel++
		}()

		return NL + prefix + strings.Repeat(indent, indentLevel) + m
	}
}
