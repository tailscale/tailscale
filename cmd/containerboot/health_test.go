// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/kube/certs"
	"tailscale.com/kube/localclient"
	"tailscale.com/tailcfg"
)

type fakeHealthLocalClient struct {
	status      *ipnstate.Status
	prefs       *ipn.Prefs
	serveConfig *ipn.ServeConfig
	err         error
}

func (f *fakeHealthLocalClient) StatusWithoutPeers(context.Context) (*ipnstate.Status, error) {
	return f.status, f.err
}

func (f *fakeHealthLocalClient) GetPrefs(context.Context) (*ipn.Prefs, error) {
	return f.prefs, f.err
}

func (f *fakeHealthLocalClient) GetServeConfig(context.Context) (*ipn.ServeConfig, error) {
	return f.serveConfig, f.err
}

func TestTailscaledResponding(t *testing.T) {
	for name, tt := range map[string]struct {
		err     error
		wantErr string
	}{
		"responding":     {},
		"not_responding": {err: errors.New("connection refused"), wantErr: "failed to get status"},
		"timed_out":      {err: context.DeadlineExceeded, wantErr: "failed to get status"},
	} {
		t.Run(name, func(t *testing.T) {
			lc := &fakeHealthLocalClient{status: &ipnstate.Status{}, err: tt.err}
			checkErr(t, tailscaledResponding(lc)(t.Context()), tt.wantErr)
		})
	}
}

func TestCertsPresent(t *testing.T) {
	const domain = "my-app.tailnetxyz.ts.net"
	withHTTPS := &ipn.ServeConfig{
		Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
			"svc:my-app": {
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					ipn.HostPort(domain + ":443"): {},
				},
			},
		},
	}
	withHTTPAndHTTPS := &ipn.ServeConfig{
		Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
			"svc:my-app": {
				TCP: map[uint16]*ipn.TCPPortHandler{
					80:  {HTTP: true},
					443: {HTTPS: true},
				},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					ipn.HostPort(domain + ":80"):  {},
					ipn.HostPort(domain + ":443"): {},
				},
			},
		},
	}
	validCert := map[string]*tailcfg.C2NTLSCertInfo{domain: {Valid: true}}

	for name, tt := range map[string]struct {
		serveConfig *ipn.ServeConfig
		advertised  []string
		certs       map[string]*tailcfg.C2NTLSCertInfo
		wantErr     string
	}{
		"advertised_no_cert":     {serveConfig: withHTTPS, advertised: []string{"svc:my-app"}, wantErr: reasonCertsNotPresent},
		"advertised_cert":        {serveConfig: withHTTPS, advertised: []string{"svc:my-app"}, certs: validCert},
		"not_advertised_no_cert": {serveConfig: withHTTPS},
		"http_and_https_no_cert": {serveConfig: withHTTPAndHTTPS, advertised: []string{"svc:my-app"}},
		"no_services":            {serveConfig: &ipn.ServeConfig{}},
	} {
		t.Run(name, func(t *testing.T) {
			cm := certs.NewCertManager(&localclient.FakeLocalClient{CertStatusResults: tt.certs}, t.Logf)
			lc := &fakeHealthLocalClient{prefs: &ipn.Prefs{AdvertiseServices: tt.advertised}, serveConfig: tt.serveConfig}
			checkErr(t, certsPresent(cm, lc)(t.Context()), tt.wantErr)
		})
	}
}

// checkErr checks that err is nil if wantErr is empty, or otherwise contains
// wantErr.
func checkErr(t *testing.T, err error, wantErr string) {
	t.Helper()
	switch {
	case wantErr == "" && err != nil:
		t.Errorf("unexpected error: %v", err)
	case wantErr != "" && (err == nil || !strings.Contains(err.Error(), wantErr)):
		t.Errorf("error = %v, want it to contain %q", err, wantErr)
	}
}
