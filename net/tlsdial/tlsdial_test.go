// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tlsdial

import (
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

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
