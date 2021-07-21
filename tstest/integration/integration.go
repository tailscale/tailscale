// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package integration contains Tailscale integration tests.
//
// This package is considered internal and the public API is subject
// to change without notice.
package integration

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"go4.org/mem"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/smallzstd"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
	"tailscale.com/version"
)

// BuildTestBinaries builds tailscale and tailscaled.
// It puts the paths to the binaries in the Binaries var.
// If err is nil, the caller should execute cleanup
// when the binaries are no longer needed.
func BuildTestBinaries() (err error, cleanup func()) {
	bindir, err := ioutil.TempDir("", "")
	if err != nil {
		return err, func() {}
	}
	cleanup = func() { os.RemoveAll(bindir) }
	err = build(bindir, "tailscale.com/cmd/tailscaled", "tailscale.com/cmd/tailscale")
	if err != nil {
		cleanup()
		return err, func() {}
	}

	Binaries.Dir = bindir
	Binaries.Daemon = filepath.Join(bindir, "tailscaled"+exe())
	Binaries.CLI = filepath.Join(bindir, "tailscale"+exe())
	return nil, cleanup
}

// Binaries are the paths to a tailscaled and tailscale binary.
// It is populated by BuildTestBinaries.
var Binaries struct {
	Dir    string // temp dir for tailscale and tailscaled
	Daemon string // tailscaled
	CLI    string // tailscale
}

func build(outDir string, targets ...string) error {
	goBin, err := findGo()
	if err != nil {
		return err
	}
	cmd := exec.Command(goBin, "install")
	if version.IsRace() {
		cmd.Args = append(cmd.Args, "-race")
	}
	cmd.Args = append(cmd.Args, targets...)
	cmd.Env = append(os.Environ(), "GOARCH="+runtime.GOARCH, "GOBIN="+outDir)
	errOut, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	if strings.Contains(string(errOut), "when GOBIN is set") {
		// Fallback slow path for cross-compiled binaries.
		for _, target := range targets {
			outFile := filepath.Join(outDir, path.Base(target)+exe())
			cmd := exec.Command(goBin, "build", "-o", outFile, target)
			cmd.Env = append(os.Environ(), "GOARCH="+runtime.GOARCH)
			if errOut, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("failed to build %v with %v: %v, %s", target, goBin, err, errOut)
			}
		}
		return nil
	}
	return fmt.Errorf("failed to build %v with %v: %v, %s", targets, goBin, err, errOut)
}

func findGo() (string, error) {
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go"+exe())
	if fi, err := os.Stat(goBin); err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("failed to find go at %v", goBin)
		}
		return "", fmt.Errorf("looking for go binary: %v", err)
	} else if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%v is unexpected %v", goBin, fi.Mode())
	}
	return goBin, nil
}

func exe() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// RunDERPAndSTUN runs a local DERP and STUN server for tests, returning the derpMap
// that clients should use. This creates resources that must be cleaned up with the
// returned cleanup function.
func RunDERPAndSTUN(t testing.TB, logf logger.Logf, ipAddress string) (derpMap *tailcfg.DERPMap) {
	t.Helper()

	var serverPrivateKey key.Private
	if _, err := rand.Read(serverPrivateKey[:]); err != nil {
		t.Fatal(err)
	}
	d := derp.NewServer(serverPrivateKey, logf)

	httpsrv := httptest.NewUnstartedServer(derphttp.Handler(d))
	httpsrv.Config.ErrorLog = logger.StdLogger(logf)
	httpsrv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	httpsrv.StartTLS()

	stunAddr, stunCleanup := stuntest.ServeWithPacketListener(t, nettype.Std{})

	m := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:             "t1",
						RegionID:         1,
						HostName:         ipAddress,
						IPv4:             ipAddress,
						IPv6:             "none",
						STUNPort:         stunAddr.Port,
						DERPPort:         httpsrv.Listener.Addr().(*net.TCPAddr).Port,
						InsecureForTests: true,
						STUNTestIP:       stunAddr.IP.String(),
					},
				},
			},
		},
	}

	t.Cleanup(func() {
		httpsrv.CloseClientConnections()
		httpsrv.Close()
		d.Close()
		stunCleanup()
	})

	return m
}

// LogCatcher is a minimal logcatcher for the logtail upload client.
type LogCatcher struct {
	mu     sync.Mutex
	logf   logger.Logf
	buf    bytes.Buffer
	gotErr error
	reqs   int
}

// UseLogf makes the logcatcher implementation use a given logf function
// to dump all logs to.
func (lc *LogCatcher) UseLogf(fn logger.Logf) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.logf = fn
}

func (lc *LogCatcher) logsContains(sub mem.RO) bool {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return mem.Contains(mem.B(lc.buf.Bytes()), sub)
}

func (lc *LogCatcher) numRequests() int {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.reqs
}

func (lc *LogCatcher) logsString() string {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.buf.String()
}

// Reset clears the buffered logs from memory.
func (lc *LogCatcher) Reset() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.buf.Reset()
}

func (lc *LogCatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "zstd" {
		var err error
		body, err = smallzstd.NewDecoder(body)
		if err != nil {
			log.Printf("bad caught zstd: %v", err)
			http.Error(w, err.Error(), 400)
			return
		}
	}
	bodyBytes, _ := ioutil.ReadAll(body)

	type Entry struct {
		Logtail struct {
			ClientTime time.Time `json:"client_time"`
			ServerTime time.Time `json:"server_time"`
			Error      struct {
				BadData string `json:"bad_data"`
			} `json:"error"`
		} `json:"logtail"`
		Text string `json:"text"`
	}
	var jreq []Entry
	var err error
	if len(bodyBytes) > 0 && bodyBytes[0] == '[' {
		err = json.Unmarshal(bodyBytes, &jreq)
	} else {
		var ent Entry
		err = json.Unmarshal(bodyBytes, &ent)
		jreq = append(jreq, ent)
	}

	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.reqs++
	if lc.gotErr == nil && err != nil {
		lc.gotErr = err
	}
	if err != nil {
		fmt.Fprintf(&lc.buf, "error from %s of %#q: %v\n", r.Method, bodyBytes, err)
	} else {
		for _, ent := range jreq {
			fmt.Fprintf(&lc.buf, "%s\n", strings.TrimSpace(ent.Text))
			if lc.logf != nil {
				lc.logf("%s", strings.TrimSpace(ent.Text))
			}
		}
	}
	w.WriteHeader(200) // must have no content, but not a 204
}
