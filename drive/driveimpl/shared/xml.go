// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package shared

import (
	"bytes"
	"encoding/xml"
)

// EscapeForXML escapes the given string for use in XML text.
func EscapeForXML(s string) string {
	result := bytes.NewBuffer(nil)
	xml.Escape(result, []byte(s))
	return result.String()
}
