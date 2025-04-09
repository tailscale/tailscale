// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package logpolicy

import (
	"net/http"
	"os"
	"reflect"
	"testing"

	"tailscale.com/logtail"
)

func resetLogTarget() {
	os.Unsetenv("TS_LOG_TARGET")
	v := reflect.ValueOf(&getLogTargetOnce).Elem()
	v.Set(reflect.Zero(v.Type()))
}

func TestLogHost(t *testing.T) {
	defer resetLogTarget()

	tests := []struct {
		env  string
		want string
	}{
		{"", logtail.DefaultHost},
		{"http://foo.com", "foo.com"},
		{"https://foo.com", "foo.com"},
		{"https://foo.com/", "foo.com"},
		{"https://foo.com:123/", "foo.com"},
	}
	for _, tt := range tests {
		resetLogTarget()
		os.Setenv("TS_LOG_TARGET", tt.env)
		if got := LogHost(); got != tt.want {
			t.Errorf("for env %q, got %q, want %q", tt.env, got, tt.want)
		}
	}
}
func TestOptions(t *testing.T) {
	defer resetLogTarget()

	tests := []struct {
		name        string
		opts        func() Options
		wantBaseURL string
	}{
		{
			name:        "default",
			opts:        func() Options { return Options{} },
			wantBaseURL: "",
		},
		{
			name: "custom_baseurl",
			opts: func() Options {
				os.Setenv("TS_LOG_TARGET", "http://localhost:1234")
				return Options{}
			},
			wantBaseURL: "http://localhost:1234",
		},
		{
			name: "custom_httpc_and_baseurl",
			opts: func() Options {
				os.Setenv("TS_LOG_TARGET", "http://localhost:12345")
				return Options{HTTPC: &http.Client{Transport: noopPretendSuccessTransport{}}}
			},
			wantBaseURL: "http://localhost:12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetLogTarget()
			config, policy := tt.opts().init(false)
			if policy == nil {
				t.Fatal("unexpected nil policy")
			}
			if config.BaseURL != tt.wantBaseURL {
				t.Errorf("got %q, want %q", config.BaseURL, tt.wantBaseURL)
			}
			policy.Close()
		})
	}
}
