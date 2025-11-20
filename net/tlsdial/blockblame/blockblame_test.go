// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package blockblame

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

const controlplaneDotTailscaleDotComPEM = `
-----BEGIN CERTIFICATE-----
MIIDkzCCAxqgAwIBAgISA2GOahsftpp59yuHClbDuoduMAoGCCqGSM49BAMDMDIx
CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJF
NjAeFw0yNDEwMTIxNjE2NDVaFw0yNTAxMTAxNjE2NDRaMCUxIzAhBgNVBAMTGmNv
bnRyb2xwbGFuZS50YWlsc2NhbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAExfraDUc1t185zuGtZlnPDtEJJSDBqvHN4vQcXSzSTPSAdDYHcA8fL5woU2Kg
jK/2C0wm/rYy2Rre/ulhkS4wB6OCAhswggIXMA4GA1UdDwEB/wQEAwIHgDAdBgNV
HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4E
FgQUpArnpDj8Yh6NTgMOZjDPx0TuLmcwHwYDVR0jBBgwFoAUkydGmAOpUWiOmNbE
QkjbI79YlNIwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8vZTYu
by5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9lNi5pLmxlbmNyLm9yZy8w
JQYDVR0RBB4wHIIaY29udHJvbHBsYW5lLnRhaWxzY2FsZS5jb20wEwYDVR0gBAww
CjAIBgZngQwBAgEwggEDBgorBgEEAdZ5AgQCBIH0BIHxAO8AdgDgkrP8DB3I52g2
H95huZZNClJ4GYpy1nLEsE2lbW9UBAAAAZKBujCyAAAEAwBHMEUCIQDHMgUaL4H9
ZJa090ZOpBeEVu3+t+EF4HlHI1NqAai6uQIgeY/lLfjAXfcVgxBHHR4zjd0SzhaP
TREHXzwxzN/8blkAdQDPEVbu1S58r/OHW9lpLpvpGnFnSrAX7KwB0lt3zsw7CAAA
AZKBujh8AAAEAwBGMEQCICQwhMk45t9aiFjfwOC/y6+hDbszqSCpIv63kFElweUy
AiAqTdkqmbqUVpnav5JdWkNERVAIlY4jqrThLsCLZYbNszAKBggqhkjOPQQDAwNn
ADBkAjALyfgAt1XQp1uSfxy4GapR5OsmjEMBRVq6IgsPBlCRBfmf0Q3/a6mF0pjb
Sj4oa+cCMEhZk4DmBTIdZY9zjuh8s7bXNfKxUQS0pEhALtXqyFr+D5dF7JcQo9+s
Z98JY7/PCA==
-----END CERTIFICATE-----`

func TestVerifyCertificateOurControlPlane(t *testing.T) {
	p, _ := pem.Decode([]byte(controlplaneDotTailscaleDotComPEM))
	if p == nil {
		t.Fatalf("failed to extract certificate bytes for controlplane.tailscale.com")
		return
	}
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
		return
	}
	m, found := VerifyCertificate(cert)
	if found {
		t.Fatalf("expected to not get a result for the controlplane.tailscale.com certificate")
	}
	if m != nil {
		t.Fatalf("expected nil manufacturer for controlplane.tailscale.com certificate")
	}
}
