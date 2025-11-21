package cli

import (
	"fmt"
	"strconv"
	"strings"
	"tailscale.com/tailcfg"
)

// parseDeviceAttrs parses a comma-separated list of key=value pairs into an AttrUpdate.
// Supported value types:
// - booleans: true/false (case-insensitive)
// - numbers: integers or floats parsed into float64
// - strings: any other token (used as-is)
// - deletion: key= (empty value) encodes as nil
func parseDeviceAttrs(s string) (tailcfg.AttrUpdate, error) {
	attrs := make(tailcfg.AttrUpdate)
	s = strings.TrimSpace(s)
	if s == "" {
		return attrs, nil
	}
	parts := strings.Split(s, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		key, val, ok := strings.Cut(p, "=")
		if !ok {
			return nil, fmt.Errorf("missing '=' in %q", p)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("empty key in %q", p)
		}
		val = strings.TrimSpace(val)
		if val == "" {
			attrs[key] = nil // delete
			continue
		}
		switch strings.ToLower(val) {
		case "true":
			attrs[key] = true
			continue
		case "false":
			attrs[key] = false
			continue
		}
		if i, err := strconv.ParseInt(val, 10, 64); err == nil {
			attrs[key] = float64(i)
			continue
		}
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			attrs[key] = f
			continue
		}
		attrs[key] = val
	}
	return attrs, nil
}
