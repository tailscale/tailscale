// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package bakedroots contains WebPKI CA roots we bake into the tailscaled binary,
// lest the system's CA roots be missing them (or entirely empty).
package bakedroots

import (
	"crypto/x509"
	"sync"

	"tailscale.com/util/testenv"
)

// Get returns the baked-in roots.
//
// As of 2025-01-21, this includes only the LetsEncrypt ISRG Root X1 root.
func Get() *x509.CertPool {
	roots.once.Do(func() {
		roots.parsePEM(append(
			[]byte(letsEncryptX1),
			letsEncryptX2...,
		))
	})
	return roots.p
}

// testingTB is a subset of testing.TB needed
// to verify the caller isn't in a parallel test.
type testingTB interface {
	// Setenv panics if it's in a parallel test.
	Setenv(k, v string)
}

// ResetForTest resets the cached roots for testing,
// optionally setting them to caPEM if non-nil.
func ResetForTest(tb testingTB, caPEM []byte) {
	if !testenv.InTest() {
		panic("not in test")
	}
	tb.Setenv("ASSERT_NOT_PARALLEL_TEST", "1") // panics if tb's Parallel was called

	roots = rootsOnce{}
	if caPEM != nil {
		roots.once.Do(func() { roots.parsePEM(caPEM) })
	}
}

var roots rootsOnce

type rootsOnce struct {
	once sync.Once
	p    *x509.CertPool
}

func (r *rootsOnce) parsePEM(caPEM []byte) {
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(caPEM) {
		panic("bogus PEM")
	}
	r.p = p
}

/*
letsEncryptX1 is the LetsEncrypt X1 root:

Certificate:

	Data:
	    Version: 3 (0x2)
	    Serial Number:
	        82:10:cf:b0:d2:40:e3:59:44:63:e0:bb:63:82:8b:00
	    Signature Algorithm: sha256WithRSAEncryption
	    Issuer: C = US, O = Internet Security Research Group, CN = ISRG Root X1
	    Validity
	        Not Before: Jun  4 11:04:38 2015 GMT
	        Not After : Jun  4 11:04:38 2035 GMT
	    Subject: C = US, O = Internet Security Research Group, CN = ISRG Root X1
	    Subject Public Key Info:
	        Public Key Algorithm: rsaEncryption
	            RSA Public-Key: (4096 bit)

We bake it into the binary as a fallback verification root,
in case the system we're running on doesn't have it.
(Tailscale runs on some ancient devices.)

To test that this code is working on Debian/Ubuntu:

$ sudo mv /usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt{,.old}
$ sudo update-ca-certificates

Then restart tailscaled. To also test dnsfallback's use of it, nuke
your /etc/resolv.conf and it should still start & run fine.
*/
const letsEncryptX1 = `
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
`

// letsEncryptX2 is the ISRG Root X2.
//
// Subject: O = Internet Security Research Group, CN = ISRG Root X2
// Key type: ECDSA P-384
// Validity: until 2035-09-04 (generated 2020-09-04)
const letsEncryptX2 = `
-----BEGIN CERTIFICATE-----
MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/q4AaOeMSQ+2b1tbFfLn
-----END CERTIFICATE-----
`
