// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tlsdial

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sync/atomic"
	"testing"

	"tailscale.com/health"
)

func resetOnce() {
	rv := reflect.ValueOf(&bakedInRootsOnce).Elem()
	rv.Set(reflect.Zero(rv.Type()))
}

func TestBakedInRoots(t *testing.T) {
	resetOnce()
	p := bakedInRoots()
	got := p.Subjects()
	if len(got) != 1 {
		t.Errorf("subjects = %v; want 1", len(got))
	}
}

func TestFallbackRootWorks(t *testing.T) {
	defer resetOnce()

	const debug = false
	if runtime.GOOS != "linux" {
		t.Skip("test assumes Linux")
	}
	crtFile, keyFile, caFile := mkcert(t, "tlsdial.test")

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	resetOnce()
	bakedInRootsOnce.Do(func() {
		p := x509.NewCertPool()
		if !p.AppendCertsFromPEM(caPEM) {
			t.Fatal("failed to add")
		}
		bakedInRootsOnce.p = p
	})

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
	ht := new(health.Tracker)
	tr.TLSClientConfig = Config("tlsdial.test", ht, tr.TLSClientConfig)
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

func TestMITMDetection(t *testing.T) {
	defer resetOnce()

	if runtime.GOOS != "linux" {
		t.Skip("test assumes Linux")
	}
	crtFile, keyFile, caFile := mkcert(t, "test.tailscale.com")

	oldSystemCertPool := systemCertPool
	defer func() { systemCertPool = oldSystemCertPool }()
	systemCertPool = func() (*x509.CertPool, error) {
		roots := x509.NewCertPool()
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA file %q", caFile)
		}
		return roots, nil
	}

	crt, err := tls.LoadX509KeyPair(crtFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(sayHi))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{crt},
	}
	srv.StartTLS()
	defer srv.Close()

	srv.Client()
	ht := new(health.Tracker)
	c := &http.Client{Transport: &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return net.Dial("tcp", srv.Listener.Addr().String())
		},
		TLSClientConfig: Config("test.tailscale.com", ht, nil),
	}}

	res, err := c.Get("https://test.tailscale.com/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatal(res.Status)
	}

	detected := ht.CurrentState().Warnings[mitmDetectWarnable.Code].BrokenSince != nil
	if !detected {
		t.Errorf("mitmDetectWarnable did not become unhealthy after the request")
	}
}

func mkcert(t *testing.T, domain string) (crtFile, keyFile, caFile string) {
	d := t.TempDir()
	crtFile = filepath.Join(d, domain+".crt")
	keyFile = filepath.Join(d, domain+".key")
	caFile = filepath.Join(d, "rootCA.pem")
	cmd := exec.Command("go",
		"run", "filippo.io/mkcert",
		"--cert-file="+crtFile,
		"--key-file="+keyFile,
		domain)
	cmd.Env = append(os.Environ(), "CAROOT="+d)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("mkcert: %v, %s", err, out)
	}
	return crtFile, keyFile, caFile
}

func sayHi(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "hi")
}
