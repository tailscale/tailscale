// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netlog

import (
	"context"
	"net/http"
	"testing"

	qt "github.com/frankban/quicktest"
	"tailscale.com/logtail"
	"tailscale.com/net/flowtrack"
	"tailscale.com/net/tunstats"
	"tailscale.com/tstest"
	"tailscale.com/util/must"
	"tailscale.com/wgengine/router"
)

func init() {
	testClient = &http.Client{Transport: &roundTripper}
}

var roundTripper roundTripperFunc

type roundTripperFunc struct {
	F func(*http.Request) (*http.Response, error)
}

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f.F(r)
}

type fakeDevice struct {
	toggled int // even => disabled, odd => enabled
}

func (d *fakeDevice) SetStatisticsEnabled(enable bool) {
	if enabled := d.toggled%2 == 1; enabled != enable {
		d.toggled++
	}

}
func (fakeDevice) ExtractStatistics() map[flowtrack.Tuple]tunstats.Counts {
	// TODO(dsnet): Add a test that verifies that statistics are correctly
	// extracted from the device and uploaded. Unfortunately,
	// we can't reliably run this test until we fix http://go/oss/5856.
	return nil
}

func TestResourceCheck(t *testing.T) {
	roundTripper.F = func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200}, nil
	}

	c := qt.New(t)
	tstest.ResourceCheck(t)
	var l Logger
	var d fakeDevice
	for i := 0; i < 10; i++ {
		must.Do(l.Startup(logtail.PrivateID{}, logtail.PrivateID{}, &d, &router.Config{}))
		l.ReconfigRoutes(&router.Config{})
		must.Do(l.Shutdown(context.Background()))
		c.Assert(d.toggled, qt.Equals, 2*(i+1))
	}
}
