// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package main

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/ipn/ipnstate"
)

func TestContainerBoot(t *testing.T) {
	d, err := os.MkdirTemp("", "containerboot")
	if err != nil {
		t.Fatal(err)
	}

	lapi := localAPI{FSRoot: d}
	if err := lapi.Start(); err != nil {
		t.Fatal(err)
	}
	defer lapi.Close()

	kube := kubeServer{FSRoot: d}
	if err := kube.Start(); err != nil {
		t.Fatal(err)
	}
	defer kube.Close()

	for _, path := range []string{"var/lib", "usr/bin", "tmp"} {
		if err := os.MkdirAll(filepath.Join(d, path), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(d, "usr/bin/tailscaled"), fakeTailscaled, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "usr/bin/tailscale"), fakeTailscale, 0700); err != nil {
		t.Fatal(err)
	}

	boot := filepath.Join(d, "containerboot")
	if err := exec.Command("go", "build", "-o", boot, "tailscale.com/cmd/containerboot").Run(); err != nil {
		t.Fatalf("Building containerboot: %v", err)
	}

	argFile := filepath.Join(d, "args")

	lapi.Reset()
	kube.Reset()

	cmd := exec.Command(boot)
	cmd.Env = []string{
		fmt.Sprintf("PATH=%s/usr/bin:%s", d, os.Getenv("PATH")),
		fmt.Sprintf("TS_TEST_RECORD_ARGS=%s", argFile),
		fmt.Sprintf("TS_TEST_SOCKET=%s", lapi.Path),
		fmt.Sprintf("TS_SOCKET=%s", filepath.Join(d, "tmp/tailscaled.sock")),
	}
	cbOut := &lockingBuffer{}
	cmd.Stderr = cbOut
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting containerboot: %v", err)
	}
	defer func() {
		cmd.Process.Signal(unix.SIGTERM)
		cmd.Process.Wait()
	}()

	want := `
/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking
/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false
`
	waitArgs(t, 2*time.Second, d, argFile, want)

	lapi.SetStatus(ipnstate.Status{
		BackendState: "Running",
		TailscaleIPs: []netip.Addr{
			netip.MustParseAddr("100.64.0.1"),
		},
	})

	waitLogLine(t, 2*time.Second, cbOut, "Startup complete, waiting for shutdown signal")
}

type lockingBuffer struct {
	sync.Mutex
	b bytes.Buffer
}

func (b *lockingBuffer) Write(bs []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.b.Write(bs)
}

func (b *lockingBuffer) String() string {
	b.Lock()
	defer b.Unlock()
	return b.b.String()
}

// waitLogLine looks for want in the contents of b.
//
// Only lines starting with 'boot: ' (the output of containerboot
// itself) are considered, and the logged timestamp is ignored.
//
// waitLogLine fails the entire test if path doesn't contain want
// before the timeout.
func waitLogLine(t *testing.T, timeout time.Duration, b *lockingBuffer, want string) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(b.String(), "\n") {
			if !strings.HasPrefix(line, "boot: ") {
				continue
			}
			if strings.HasSuffix(line, " "+want) {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for wanted output line %q. Output:\n%s", want, b.String())
}

// waitArgs waits until the contents of path matches wantArgs, a set
// of command lines recorded by test_tailscale.sh and
// test_tailscaled.sh.
//
// All occurrences of removeStr are removed from the file prior to
// comparison. This is used to remove the varying temporary root
// directory name from recorded commandlines, so that wantArgs can be
// a constant value.
//
// waitArgs fails the entire test if path doesn't contain wantArgs
// before the timeout.
func waitArgs(t *testing.T, timeout time.Duration, removeStr, path, wantArgs string) {
	t.Helper()
	wantArgs = strings.TrimSpace(wantArgs)
	deadline := time.Now().Add(timeout)
	var got string
	for time.Now().Before(deadline) {
		bs, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			// Don't bother logging that the file doesn't exist, it
			// should start existing soon.
			goto loop
		} else if err != nil {
			t.Logf("reading %q: %v", path, err)
			goto loop
		}
		got = strings.TrimSpace(string(bs))
		got = strings.ReplaceAll(got, removeStr, "")
		if got == wantArgs {
			return
		}
	loop:
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("waiting for args file %q to have expected output, got:\n%s\n\nWant: %s", path, got, wantArgs)
}

//go:embed test_tailscaled.sh
var fakeTailscaled []byte

//go:embed test_tailscale.sh
var fakeTailscale []byte

// localAPI is a minimal fake tailscaled LocalAPI server that presents
// just enough functionality for containerboot to function
// correctly. In practice this means it only supports querying
// tailscaled status, and panics on all other uses to make it very
// obvious that something unexpected happened.
type localAPI struct {
	FSRoot string
	Path   string // populated by Start

	srv *http.Server

	sync.Mutex
	status ipnstate.Status
}

func (l *localAPI) Start() error {
	path := filepath.Join(l.FSRoot, "tmp/tailscaled.sock.fake")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}

	l.srv = &http.Server{
		Handler: l,
	}
	l.Path = path
	go l.srv.Serve(ln)
	return nil
}

func (l *localAPI) Close() {
	l.srv.Close()
}

func (l *localAPI) Reset() {
	l.SetStatus(ipnstate.Status{
		BackendState: "NoState",
	})
}

func (l *localAPI) SetStatus(st ipnstate.Status) {
	l.Lock()
	defer l.Unlock()
	l.status = st
}

func (l *localAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		panic(fmt.Sprintf("unsupported method %q", r.Method))
	}
	if r.URL.Path != "/localapi/v0/status" {
		panic(fmt.Sprintf("unsupported localAPI path %q", r.URL.Path))
	}
	w.Header().Set("Content-Type", "application/json")
	l.Lock()
	defer l.Unlock()
	if err := json.NewEncoder(w).Encode(l.status); err != nil {
		panic("json encode failed")
	}
}

// kubeServer is a minimal fake Kubernetes server that presents just
// enough functionality for containerboot to function correctly. In
// practice this means it only supports reading and modifying a single
// kube secret, and panics on all other uses to make it very obvious
// that something unexpected happened.
type kubeServer struct {
	FSRoot string
	Addr   string // populated by Start

	srv *httptest.Server

	sync.Mutex
	secret map[string]string
}

func (k *kubeServer) Secret() map[string]string {
	k.Lock()
	defer k.Unlock()
	ret := map[string]string{}
	for k, v := range k.secret {
		ret[k] = v
	}
	return ret
}

func (k *kubeServer) SetSecret(key, val string) {
	k.Lock()
	defer k.Unlock()
	k.secret[key] = val
}

func (k *kubeServer) Reset() {
	k.Lock()
	defer k.Unlock()
	k.secret = map[string]string{}
}

func (k *kubeServer) Start() error {
	root := filepath.Join(k.FSRoot, "var/run/secrets/kubernetes.io/serviceaccount")

	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(root, "namespace"), []byte("default"), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "token"), []byte("bearer_token"), 0600); err != nil {
		return err
	}

	k.srv = httptest.NewTLSServer(k)
	k.Addr = k.srv.Listener.Addr().String()

	var cert bytes.Buffer
	if err := pem.Encode(&cert, &pem.Block{Type: "CERTIFICATE", Bytes: k.srv.Certificate().Raw}); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "ca.crt"), cert.Bytes(), 0600); err != nil {
		return err
	}

	return nil
}

func (k *kubeServer) Close() {
	k.srv.Close()
}

func (k *kubeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer bearer_token" {
		panic("client didn't provide bearer token in request")
	}
	if r.URL.Path != "/api/v1/namespaces/default/secrets/tailscale" {
		panic(fmt.Sprintf("unhandled fake kube api path %q", r.URL.Path))
	}

	bs, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("reading request body: %v", err), http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case "GET":
		w.Header().Set("Content-Type", "application/json")
		ret := map[string]map[string]string{
			"data": map[string]string{},
		}
		k.Lock()
		defer k.Unlock()
		for k, v := range k.secret {
			v := base64.StdEncoding.EncodeToString([]byte(v))
			if err != nil {
				panic("encode failed")
			}
			ret["data"][k] = v
		}
		if err := json.NewEncoder(w).Encode(ret); err != nil {
			panic("encode failed")
		}
	case "PATCH":
		switch r.Header.Get("Content-Type") {
		case "application/json-patch+json":
			req := []struct {
				Op   string `json:"op"`
				Path string `json:"path"`
			}{}
			if err := json.Unmarshal(bs, &req); err != nil {
				panic(fmt.Sprintf("json decode failed: %v. Body:\n\n%s", err, string(bs)))
			}
			k.Lock()
			defer k.Unlock()
			for _, op := range req {
				if op.Op != "remove" {
					panic(fmt.Sprintf("unsupported json-patch op %q", op.Op))
				}
				if !strings.HasPrefix(op.Path, "/data/") {
					panic(fmt.Sprintf("unsupported json-patch path %q", op.Path))
				}
				delete(k.secret, strings.TrimPrefix(op.Path, "/data/"))
			}
		case "application/strategic-merge-patch+json":
			req := struct {
				Data map[string]string `json:"stringData"`
			}{}
			if err := json.Unmarshal(bs, &req); err != nil {
				panic(fmt.Sprintf("json decode failed: %v. Body:\n\n%s", err, string(bs)))
			}
			k.Lock()
			defer k.Unlock()
			for key, val := range req.Data {
				k.secret[key] = val
			}
		default:
			panic(fmt.Sprintf("unknown content type %q", r.Header.Get("Content-Type")))
		}
	default:
		panic(fmt.Sprintf("unhandled HTTP method %q", r.Method))
	}
}
