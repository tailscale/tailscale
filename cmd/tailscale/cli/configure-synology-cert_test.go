// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_acme

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

type fakeAPICaller struct {
	Data  json.RawMessage
	Error error
}

func (c fakeAPICaller) Call(_ context.Context, _, _ string, _ map[string]string) (json.RawMessage, error) {
	return c.Data, c.Error
}

func Test_listCerts(t *testing.T) {
	tests := []struct {
		name    string
		caller  synoAPICaller
		want    []certificateInfo
		wantErr bool
	}{
		{
			name: "normal response",
			caller: fakeAPICaller{
				Data: json.RawMessage(`{
"certificates" : [
	{
		"desc" : "Tailnet Certificate",
		"id" : "cG2XBt",
		"is_broken" : false,
		"is_default" : false,
		"issuer" : {
			"common_name" : "R3",
			"country" : "US",
			"organization" : "Let's Encrypt"
		},
		"key_types" : "ECC",
		"renewable" : false,
		"services" : [
			{
			"display_name" : "DSM Desktop Service",
			"display_name_i18n" : "common:web_desktop",
			"isPkg" : false,
			"multiple_cert" : true,
			"owner" : "root",
			"service" : "default",
			"subscriber" : "system",
			"user_setable" : true
			}
		],
		"signature_algorithm" : "sha256WithRSAEncryption",
		"subject" : {
			"common_name" : "foo.tailscale.ts.net",
			"sub_alt_name" : [ "foo.tailscale.ts.net" ]
		},
		"user_deletable" : true,
		"valid_from" : "Sep 26 11:39:43 2023 GMT",
		"valid_till" : "Dec 25 11:39:42 2023 GMT"
	},
	{
		"desc" : "",
		"id" : "sgmnpb",
		"is_broken" : false,
		"is_default" : false,
		"issuer" : {
			"city" : "Taipei",
			"common_name" : "Synology Inc. CA",
			"country" : "TW",
			"organization" : "Synology Inc."
		},
		"key_types" : "",
		"renewable" : false,
		"self_signed_cacrt_info" : {
			"issuer" : {
			"city" : "Taipei",
			"common_name" : "Synology Inc. CA",
			"country" : "TW",
			"organization" : "Synology Inc."
			},
			"subject" : {
			"city" : "Taipei",
			"common_name" : "Synology Inc. CA",
			"country" : "TW",
			"organization" : "Synology Inc."
			}
		},
		"services" : [],
		"signature_algorithm" : "sha256WithRSAEncryption",
		"subject" : {
			"city" : "Taipei",
			"common_name" : "synology.com",
			"country" : "TW",
			"organization" : "Synology Inc.",
			"sub_alt_name" : []
		},
		"user_deletable" : true,
		"valid_from" : "May 27 00:23:19 2019 GMT",
		"valid_till" : "Feb 11 00:23:19 2039 GMT"
	}
]
}`),
				Error: nil,
			},
			want: []certificateInfo{
				{Desc: "Tailnet Certificate", ID: "cG2XBt", Subject: subject{CommonName: "foo.tailscale.ts.net"}},
				{Desc: "", ID: "sgmnpb", Subject: subject{CommonName: "synology.com"}},
			},
		},
		{
			name:    "call error",
			caller:  fakeAPICaller{nil, fmt.Errorf("caller failed")},
			wantErr: true,
		},
		{
			name:    "payload decode error",
			caller:  fakeAPICaller{json.RawMessage("This isn't JSON!"), nil},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := listCerts(context.Background(), tt.caller)
			if (err != nil) != tt.wantErr {
				t.Errorf("listCerts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("listCerts() = %v, want %v", got, tt.want)
			}
		})
	}
}
