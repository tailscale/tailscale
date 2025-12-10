// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package conffile

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/tailcfg"
	"tailscale.com/util/must"
)

func mustParseProtoPortRange(s string) *tailcfg.ProtoPortRange {
	return &must.Get(tailcfg.ParseProtoPortRanges([]string{s}))[0]
}

func TestLoadConfigV0(t *testing.T) {
	tests := []struct {
		name       string
		config     string
		forService string
		want       *ServicesConfigFile
		wantErr    bool
	}{
		{
			name:   "empty-config",
			config: "{}",
			want:   &ServicesConfigFile{},
		},
		{
			name: "deserialize-endpoints",
			config: `{
				"services": {
					"svc:test": {
						"endpoints": {
							"tcp:443": "http://localhost:8080",
							"tcp:80": "tcp://localhost:8000",
							"tcp:1000": "https+insecure://127.0.0.1:1000"
						}
					}
				}
			}`,
			want: &ServicesConfigFile{
				Services: map[tailcfg.ServiceName]*ServiceDetailsFile{
					tailcfg.ServiceName("svc:test"): {
						Endpoints: map[*tailcfg.ProtoPortRange]*Target{
							mustParseProtoPortRange("tcp:443"): &Target{
								Protocol:         ProtoHTTP,
								Destination:      "localhost",
								DestinationPorts: tailcfg.PortRange{First: 8000, Last: 8000},
							},
							mustParseProtoPortRange("tcp:80"): &Target{
								Protocol:         ProtoTCP,
								Destination:      "localhost",
								DestinationPorts: tailcfg.PortRange{First: 8000, Last: 8000},
							},
							mustParseProtoPortRange("tcp:1000"): &Target{
								Protocol:         ProtoHTTPSInsecure,
								Destination:      "127.0.0.1",
								DestinationPorts: tailcfg.PortRange{First: 1000, Last: 1000},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadConfigV0([]byte(tt.config), tt.forService)
			if tt.wantErr && err == nil {
				t.Fatalf("want err, got success")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("want success, got err: %v", err)
			}
			if diff := cmp.Diff(
				got,
				tt.want,
				cmp.Comparer(func(x, y *tailcfg.ProtoPortRange) bool { return *x == *y }),
				cmp.Comparer(func(x, y reflect.Type) bool { return x == y }),
				cmp.Transformer("ppr", func(ppr *tailcfg.ProtoPortRange) tailcfg.ProtoPortRange { return *ppr }),
			); diff != "" {
				t.Fatalf("incorrect config (-want,+got):\n%s", diff)
			}
		})
	}
}
