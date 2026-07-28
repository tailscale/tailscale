// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !ts_omit_acme

package local

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go4.org/mem"
)

// rateLimitedError is returned from cert-fetching methods when the
// upstream ACME CA reported a rate limit. Callers should unpack it via
// [RateLimitRetryAfter].
type rateLimitedError struct {
	retryAfter time.Duration
	underlying error
}

func (e rateLimitedError) Error() string { return e.underlying.Error() }
func (e rateLimitedError) Unwrap() error { return e.underlying }

// RateLimitRetryAfter reports whether err was a rate-limit failure from
// the upstream ACME CA and, if so, returns the CA's suggested wait
// (zero if none was provided).
func RateLimitRetryAfter(err error) (retryAfter time.Duration, ok bool) {
	var rl rateLimitedError
	if errors.As(err, &rl) {
		return rl.retryAfter, true
	}
	return 0, false
}

// retryAfterFromHeader parses a Retry-After header, matching the
// delta-seconds + HTTP-date pattern in tempfork/acme/http.go.
func retryAfterFromHeader(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if i, err := strconv.Atoi(v); err == nil {
		return time.Duration(i) * time.Second
	}
	t, err := http.ParseTime(v)
	if err != nil {
		return 0
	}
	d := time.Until(t)
	if d < 0 {
		return 0
	}
	return d
}

// SetDNS adds a DNS TXT record for the given domain name, containing
// the provided TXT value. The intended use case is answering
// LetsEncrypt/ACME dns-01 challenges.
//
// The control plane will only permit SetDNS requests with very
// specific names and values. The name should be
// "_acme-challenge." + your node's MagicDNS name. It's expected that
// clients cache the certs from LetsEncrypt (or whichever CA is
// providing them) and only request new ones as needed; the control plane
// rate limits SetDNS requests.
//
// This is a low-level interface; it's expected that most Tailscale
// users use a higher level interface to getting/using TLS
// certificates.
func (lc *Client) SetDNS(ctx context.Context, name, value string) error {
	v := url.Values{}
	v.Set("name", name)
	v.Set("value", value)
	_, err := lc.send(ctx, "POST", "/localapi/v0/set-dns?"+v.Encode(), 200, nil)
	return err
}

// CertPair returns a cert and private key for the provided DNS domain.
//
// It returns a cached certificate from disk if it's still valid.
//
// Rate-limit failures can be identified via [RateLimitRetryAfter].
//
// Deprecated: use [Client.CertPair].
func CertPair(ctx context.Context, domain string) (certPEM, keyPEM []byte, err error) {
	return defaultClient.CertPair(ctx, domain)
}

// CertPair returns a cert and private key for the provided DNS domain.
//
// It returns a cached certificate from disk if it's still valid.
//
// Rate-limit failures can be identified via [RateLimitRetryAfter].
//
// API maturity: this is considered a stable API.
func (lc *Client) CertPair(ctx context.Context, domain string) (certPEM, keyPEM []byte, err error) {
	return lc.CertPairWithValidity(ctx, domain, 0)
}

// CertPairWithValidity returns a cert and private key for the provided DNS
// domain.
//
// It returns a cached certificate from disk if it's still valid.
// When minValidity is non-zero, the returned certificate will be valid for at
// least the given duration, if permitted by the CA. If the certificate is
// valid, but for less than minValidity, it will be synchronously renewed.
//
// Rate-limit failures can be identified via [RateLimitRetryAfter].
//
// API maturity: this is considered a stable API.
func (lc *Client) CertPairWithValidity(ctx context.Context, domain string, minValidity time.Duration) (certPEM, keyPEM []byte, err error) {
	res, err := lc.send(ctx, "GET", fmt.Sprintf("/localapi/v0/cert/%s?type=pair&min_validity=%s", domain, minValidity), 200, nil)
	if err != nil {
		if hse, ok := errors.AsType[httpStatusError](err); ok && hse.HTTPStatus == http.StatusTooManyRequests {
			return nil, nil, rateLimitedError{
				retryAfter: retryAfterFromHeader(hse.Header),
				underlying: err,
			}
		}
		return nil, nil, err
	}
	// with ?type=pair, the response PEM is first the one private
	// key PEM block, then the cert PEM blocks.
	i := mem.Index(mem.B(res), mem.S("--\n--"))
	if i == -1 {
		return nil, nil, fmt.Errorf("unexpected output: no delimiter")
	}
	i += len("--\n")
	keyPEM, certPEM = res[:i], res[i:]
	if mem.Contains(mem.B(certPEM), mem.S(" PRIVATE KEY-----")) {
		return nil, nil, fmt.Errorf("unexpected output: key in cert")
	}
	return certPEM, keyPEM, nil
}

// GetCertificate fetches a TLS certificate for the TLS ClientHello in hi.
//
// It returns a cached certificate from disk if it's still valid.
//
// It's the right signature to use as the value of
// [tls.Config.GetCertificate].
//
// Deprecated: use [Client.GetCertificate].
func GetCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return defaultClient.GetCertificate(hi)
}

// GetCertificate fetches a TLS certificate for the TLS ClientHello in hi.
//
// It returns a cached certificate from disk if it's still valid.
//
// It's the right signature to use as the value of
// [tls.Config.GetCertificate].
//
// API maturity: this is considered a stable API.
func (lc *Client) GetCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hi == nil || hi.ServerName == "" {
		return nil, errors.New("no SNI ServerName")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	name := hi.ServerName
	if !strings.Contains(name, ".") {
		if v, ok := lc.ExpandSNIName(ctx, name); ok {
			name = v
		}
	}
	certPEM, keyPEM, err := lc.CertPair(ctx, name)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// ExpandSNIName expands bare label name into the most likely actual TLS cert name.
//
// Deprecated: use [Client.ExpandSNIName].
func ExpandSNIName(ctx context.Context, name string) (fqdn string, ok bool) {
	return defaultClient.ExpandSNIName(ctx, name)
}

// ExpandSNIName expands bare label name into the most likely actual TLS cert name.
func (lc *Client) ExpandSNIName(ctx context.Context, name string) (fqdn string, ok bool) {
	st, err := lc.StatusWithoutPeers(ctx)
	if err != nil {
		return "", false
	}
	for _, d := range st.CertDomains {
		if len(d) > len(name)+1 && strings.HasPrefix(d, name) && d[len(name)] == '.' {
			return d, true
		}
	}
	return "", false
}
