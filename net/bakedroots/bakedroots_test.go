// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package bakedroots

import (
	"crypto/tls"
	"flag"
	"io"
	"net/http"
	"slices"
	"testing"
	"time"

	"tailscale.com/util/cibuild"
)

func TestBakedInRoots(t *testing.T) {
	ResetForTest(t, nil)
	p := Get()
	got := p.Subjects()
	if len(got) != 4 {
		t.Errorf("subjects = %v; want 4", len(got))
	}

	// TODO(bradfitz): is there a way to easily make this test prettier without
	// writing a DER decoder? I'm not seeing how.
	var name []string
	for _, der := range got {
		name = append(name, string(der))
	}
	want := []string{
		"0O1\v0\t\x06\x03U\x04\x06\x13\x02US1)0'\x06\x03U\x04\n\x13 Internet Security Research Group1\x150\x13\x06\x03U\x04\x03\x13\fISRG Root X1",
		"0O1\v0\t\x06\x03U\x04\x06\x13\x02US1)0'\x06\x03U\x04\n\x13 Internet Security Research Group1\x150\x13\x06\x03U\x04\x03\x13\fISRG Root X2",
		"0.1\v0\t\x06\x03U\x04\x06\x13\x02US1\r0\v\x06\x03U\x04\n\x13\x04ISRG1\x100\x0e\x06\x03U\x04\x03\x13\aRoot YE",
		"0.1\v0\t\x06\x03U\x04\x06\x13\x02US1\r0\v\x06\x03U\x04\n\x13\x04ISRG1\x100\x0e\x06\x03U\x04\x03\x13\aRoot YR",
	}
	if !slices.Equal(name, want) {
		t.Errorf("subjects = %q; want %q", name, want)
	}
}

var runLiveLetsEncryptTest = flag.Bool("run-live-lets-encrypt-test", cibuild.On(),
	"run tests that hit LetsEncrypt's live test-certs endpoints over the network")

// TestLiveLetsEncrypt verifies that the baked-in roots alone (without any
// system roots) are sufficient to validate the certificate chains served by
// LetsEncrypt's per-root test endpoints.
func TestLiveLetsEncrypt(t *testing.T) {
	if !*runLiveLetsEncryptTest {
		t.Skip("skipping live network test; set --run-live-lets-encrypt-test to run")
	}
	ResetForTest(t, nil)

	for _, host := range []string{
		"valid.ye.test-certs.letsencrypt.org",
		"valid.yr.test-certs.letsencrypt.org",
		"valid.x2.test-certs.letsencrypt.org",
		"valid.x1.test-certs.letsencrypt.org",
	} {
		t.Run(host, func(t *testing.T) {
			c := &http.Client{
				Timeout: 30 * time.Second,
				Transport: &http.Transport{
					DisableKeepAlives: true,
					TLSClientConfig: &tls.Config{
						RootCAs: Get(), // baked-in roots only; no system roots
					},
				},
			}
			res, err := c.Get("https://" + host + "/")
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			io.Copy(io.Discard, res.Body)
			t.Logf("status: %v", res.Status)
		})
	}
}
