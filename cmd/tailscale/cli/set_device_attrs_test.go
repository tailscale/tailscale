package cli

import (
	"reflect"
	"strings"
	"tailscale.com/tailcfg"
	"testing"
)

func TestParseDeviceAttrs(t *testing.T) {
	tests := []struct {
		in   string
		want tailcfg.AttrUpdate
		err  string
	}{
		{"", tailcfg.AttrUpdate{}, ""},
		{"env=prod", tailcfg.AttrUpdate{"env": "prod"}, ""},
		{"secure=true", tailcfg.AttrUpdate{"secure": true}, ""},
		{"secure=false", tailcfg.AttrUpdate{"secure": false}, ""},
		{"maxAge=3600", tailcfg.AttrUpdate{"maxAge": float64(3600)}, ""},
		{"ratio=0.25", tailcfg.AttrUpdate{"ratio": 0.25}, ""},
		{"deprecated=", tailcfg.AttrUpdate{"deprecated": nil}, ""},
		{"a=1,b=true,c=hi,d=", tailcfg.AttrUpdate{"a": float64(1), "b": true, "c": "hi", "d": nil}, ""},
		{"noval", nil, "missing '='"},
		{"=x", nil, "empty key"},
	}
	for _, tt := range tests {
		got, err := parseDeviceAttrs(tt.in)
		if tt.err != "" {
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Fatalf("parseDeviceAttrs(%q) error=%v; want substring %q", tt.in, err, tt.err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseDeviceAttrs(%q) unexpected error: %v", tt.in, err)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("parseDeviceAttrs(%q)\n got=%v\nwant=%v", tt.in, got, tt.want)
		}
	}
}
