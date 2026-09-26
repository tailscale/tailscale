// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package localapi

import (
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"testing"
)

func TestShouldDenyServeConfigForGOOSAndUserContext(t *testing.T) {
	newHandler := func(connIsLocalAdmin bool) *Handler {
		return handlerForTest(t, &Handler{
			Actor: &ipnauth.TestActor{LocalAdmin: connIsLocalAdmin},
			b:     newTestLocalBackend(t),
		})
	}
	tests := []struct {
		name     string
		configIn *ipn.ServeConfig
		h        *Handler
		wantErr  bool
	}{
		{
			name: "not-path-or-unix-handler",
			configIn: &ipn.ServeConfig{
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/": {Proxy: "http://127.0.0.1:3000"},
					}},
				},
			},
			h:       newHandler(false),
			wantErr: false,
		},
		{
			name: "path-handler-admin",
			configIn: &ipn.ServeConfig{
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/": {Path: "/tmp"},
					}},
				},
			},
			h:       newHandler(true),
			wantErr: false,
		},
		{
			name: "path-handler-not-admin",
			configIn: &ipn.ServeConfig{
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/": {Path: "/tmp"},
					}},
				},
			},
			h:       newHandler(false),
			wantErr: true,
		},
		{
			name: "unix-handler-admin",
			configIn: &ipn.ServeConfig{
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/": {Proxy: "unix:/var/run/foo.sock"},
					}},
				},
			},
			h:       newHandler(true),
			wantErr: false,
		},
		{
			name: "unix-handler-not-admin",
			configIn: &ipn.ServeConfig{
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/": {Proxy: "unix:/var/run/foo.sock"},
					}},
				},
			},
			h:       newHandler(false),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		for _, goos := range []string{"linux", "windows", "darwin", "illumos", "solaris"} {
			t.Run(goos+"-"+tt.name, func(t *testing.T) {
				err := authorizeServeConfigForGOOSAndUserContext(goos, tt.configIn, tt.h)
				gotErr := err != nil
				if gotErr != tt.wantErr {
					t.Errorf("authorizeServeConfigForGOOSAndUserContext() got error = %v, want error %v", err, tt.wantErr)
				}
			})
		}
	}
	t.Run("other-goos", func(t *testing.T) {
		configIn := &ipn.ServeConfig{
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Path: "/tmp"},
				}},
			},
		}
		h := newHandler(false)
		err := authorizeServeConfigForGOOSAndUserContext("dos", configIn, h)
		if err != nil {
			t.Errorf("authorizeServeConfigForGOOSAndUserContext() got error = %v, want nil", err)
		}
	})
}
