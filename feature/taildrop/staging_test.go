// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
)

// Removed by the enablement commit: every preceding commit must keep the
// protocol and its user-visible surfaces dormant in real production binaries.
func TestTaildropStagingSurfaces(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires userspace-peer harness")
	}
	if tailcfg.CurrentCapabilityVersion != 149 {
		t.Fatal("consent capability advertised before enablement")
	}
	env := integration.NewTestEnv(t)
	n := integration.NewTestNode(t, env)
	n.StartDaemon()
	n.AwaitListening()
	n.MustUp()
	n.AwaitRunning()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	c := n.LocalClient()
	for _, route := range []struct{ method, path string }{
		{"POST", "file-put-request/unknown/file"},
		{"GET", "taildrop-consent/pending"},
		{"POST", "taildrop-consent/respond"},
	} {
		req, err := http.NewRequestWithContext(ctx, route.method, "http://"+apitype.LocalAPIHost+"/localapi/v0/"+route.path, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.DoLocalRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s exposed before enablement: %s", route.path, resp.Status)
		}
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+apitype.LocalAPIHost+"/localapi/v0/prefs", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.DoLocalRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var prefs map[string]json.RawMessage
	if err := json.Unmarshal(raw, &prefs); err != nil {
		t.Fatal(err)
	}
	if _, ok := prefs["AllowExternalTaildrop"]; ok {
		t.Fatal("receive preference exposed before enablement")
	}
	metrics, err := c.DaemonMetrics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"taildrop_consent", "peerapi_put_request", "localapi_file_put_request"} {
		if bytes.Contains(metrics, []byte(name)) {
			t.Errorf("%s metrics published before enablement", name)
		}
	}
	for _, cmd := range []struct {
		args   []string
		hidden string
	}{
		{[]string{"file", "--help"}, "consent"},
		{[]string{"set", "--help"}, "allow-external-taildrop"},
	} {
		output, err := n.TailscaleForOutput(cmd.args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v: %s", cmd.args, err, output)
		}
		if bytes.Contains(output, []byte(cmd.hidden)) {
			t.Errorf("%s exposed before enablement", cmd.hidden)
		}
	}
}
