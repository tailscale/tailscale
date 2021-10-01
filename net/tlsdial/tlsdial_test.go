// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tlsdial

import (
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sync/atomic"
	"testing"
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
	d := t.TempDir()
	crtFile := filepath.Join(d, "tlsdial.test.crt")
	keyFile := filepath.Join(d, "tlsdial.test.key")
	caFile := filepath.Join(d, "rootCA.pem")
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"),
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
	tr.TLSClientConfig = Config("tlsdial.test", tr.TLSClientConfig)
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
