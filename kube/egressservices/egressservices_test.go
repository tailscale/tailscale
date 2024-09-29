// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package egressservices

import (
	"encoding/json"
	"reflect"
	"testing"
)

func Test_jsonUnmarshalConfig(t *testing.T) {
	tests := []struct {
		name     string
		bs       []byte
		wantsCfg Config
		wantsErr bool
	}{
		{
			name:     "success",
			bs:       []byte(`{"ports":{"tcp:4003:80":{}}}`),
			wantsCfg: Config{Ports: map[PortMap]struct{}{{Protocol: "tcp", MatchPort: 4003, TargetPort: 80}: {}}},
		},
		{
			name:     "failure_invalid_format",
			bs:       []byte(`{"ports":{"tcp:80":{}}}`),
			wantsCfg: Config{Ports: map[PortMap]struct{}{}},
			wantsErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{}
			if gotErr := json.Unmarshal(tt.bs, &cfg); (gotErr != nil) != tt.wantsErr {
				t.Errorf("json.Unmarshal returned error %v, wants error %v", gotErr, tt.wantsErr)
			}
			if !reflect.DeepEqual(cfg, tt.wantsCfg) {
				t.Errorf("json.Unmarshal produced Config %v, wants Config %v", cfg, tt.wantsCfg)
			}
		})
	}
}

func Test_jsonMarshalConfig(t *testing.T) {
	tests := []struct {
		name       string
		protocol   string
		matchPort  uint16
		targetPort uint16
		wantsBs    []byte
	}{
		{
			name:       "success",
			protocol:   "tcp",
			matchPort:  4003,
			targetPort: 80,
			wantsBs:    []byte(`{"tailnetTarget":{"ip":"","fqdn":""},"ports":{"tcp:4003:80":{}}}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Ports: map[PortMap]struct{}{{
				Protocol:   tt.protocol,
				MatchPort:  tt.matchPort,
				TargetPort: tt.targetPort}: {}}}

			gotBs, gotErr := json.Marshal(&cfg)
			if gotErr != nil {
				t.Errorf("json.Marshal(%+#v) returned unexpected error %v", cfg, gotErr)
			}
			if !reflect.DeepEqual(gotBs, tt.wantsBs) {
				t.Errorf("json.Marshal(%+#v) returned '%v', wants '%v'", cfg, string(gotBs), string(tt.wantsBs))
			}
		})
	}
}
