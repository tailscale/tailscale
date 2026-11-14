// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tlsdial

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/health"
	"tailscale.com/net/bakedroots"
	"tailscale.com/util/eventbus/eventbustest"
)

func TestFallbackRootWorks(t *testing.T) {
	defer bakedroots.ResetForTest(t, nil)

	const debug = false
	if runtime.GOOS != "linux" {
		t.Skip("test assumes Linux")
	}
	d := t.TempDir()
	crtFile := filepath.Join(d, "tlsdial.test.crt")
	keyFile := filepath.Join(d, "tlsdial.test.key")
	caFile := filepath.Join(d, "rootCA.pem")
	cmd := exec.Command("go",
		"run", "filippo.io/mkcert",
		"--cert-file="+crtFile,
		"--key-file="+keyFile,
		"tlsdial.test")
	cmd.Env = append(os.Environ(), "CAROOT="+d)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("mkcert: %v, %s", err, out)
	}
	if debug {
		t.Logf("Ran: %s", out)
		dents, err := os.ReadDir(d)
		if err != nil {
			t.Fatal(err)
		}
		for _, de := range dents {
			t.Logf(" - %v", de)
		}
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	bakedroots.ResetForTest(t, caPEM)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if debug {
		t.Logf("listener running at %v", ln.Addr())
	}
	done := make(chan struct{})
	defer close(done)

	errc := make(chan error, 1)
	go func() {
		err := http.ServeTLS(ln, http.HandlerFunc(sayHi), crtFile, keyFile)
		select {
		case <-done:
			return
		default:
			t.Logf("ServeTLS: %v", err)
			errc <- err
		}
	}()

	tr := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return net.Dial("tcp", ln.Addr().String())
		},
		DisableKeepAlives: true, // for test cleanup ease
	}
	ht := health.NewTracker(eventbustest.NewBus(t))
	tr.TLSClientConfig = Config(ht, tr.TLSClientConfig)
	c := &http.Client{Transport: tr}

	ctr0 := atomic.LoadInt32(&counterFallbackOK)

	res, err := c.Get("https://tlsdial.test/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.Status)
	}

	ctrDelta := atomic.LoadInt32(&counterFallbackOK) - ctr0
	if ctrDelta != 1 {
		t.Errorf("fallback root success count = %d; want 1", ctrDelta)
	}
}

func sayHi(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "hi")
}

// TestExpiredCertReportsTLSError verifies that a server certificate that has
// expired surfaces as a TLS connection health warning, rather than failing
// silently.
func TestExpiredCertReportsTLSError(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const host = "expired.example.com"
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour), // expired
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	bus := eventbustest.NewBus(t)
	ht := health.NewTracker(bus)
	conf := Config(ht, nil)
	err = conf.VerifyConnection(tls.ConnectionState{
		ServerName:       host,
		PeerCertificates: []*x509.Certificate{leaf, caCert},
	})
	if err == nil {
		t.Fatal("VerifyConnection succeeded for expired cert; want error")
	}
	if verr := certValidityPeriodError(err); verr == nil {
		t.Fatalf("certValidityPeriodError(%v) = nil; want non-nil", err)
	}
	if verr := certValidityPeriodError(errors.New("unrelated")); verr != nil {
		t.Fatalf("certValidityPeriodError(unrelated) = %v; want nil", verr)
	}
}
