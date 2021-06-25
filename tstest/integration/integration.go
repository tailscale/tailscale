// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package integration contains Tailscale integration tests.
//
// This package is considered internal and the public API is subject
// to change without notice.
package integration

import (
	"crypto/rand"
	"crypto/tls"
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

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
	"tailscale.com/version"
)

// Binaries are the paths to a tailscaled and tailscale binary.
// These can be shared by multiple nodes.
type Binaries struct {
	Dir    string // temp dir for tailscale & tailscaled
	Daemon string // tailscaled
	CLI    string // tailscale
}

// BuildTestBinaries builds tailscale and tailscaled, failing the test
// if they fail to compile.
func BuildTestBinaries(t testing.TB) *Binaries {
	td := t.TempDir()
	build(t, td, "tailscale.com/cmd/tailscaled", "tailscale.com/cmd/tailscale")
	return &Binaries{
		Dir:    td,
		Daemon: filepath.Join(td, "tailscaled"+exe()),
		CLI:    filepath.Join(td, "tailscale"+exe()),
	}
}

// buildMu limits our use of "go build" to one at a time, so we don't
// fight Go's built-in caching trying to do the same build concurrently.
var buildMu sync.Mutex

func build(t testing.TB, outDir string, targets ...string) {
	buildMu.Lock()
	defer buildMu.Unlock()

	t0 := time.Now()
	defer func() { t.Logf("built %s in %v", targets, time.Since(t0).Round(time.Millisecond)) }()

	goBin := findGo(t)
	cmd := exec.Command(goBin, "install")
	if version.IsRace() {
		cmd.Args = append(cmd.Args, "-race")
	}
	cmd.Args = append(cmd.Args, targets...)
	cmd.Env = append(os.Environ(), "GOARCH="+runtime.GOARCH, "GOBIN="+outDir)
	errOut, err := cmd.CombinedOutput()
	if err == nil {
		return
	}
	if strings.Contains(string(errOut), "when GOBIN is set") {
		// Fallback slow path for cross-compiled binaries.
		for _, target := range targets {
			outFile := filepath.Join(outDir, path.Base(target)+exe())
			cmd := exec.Command(goBin, "build", "-o", outFile, target)
			cmd.Env = append(os.Environ(), "GOARCH="+runtime.GOARCH)
			if errOut, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("failed to build %v with %v: %v, %s", target, goBin, err, errOut)
			}
		}
		return
	}
	t.Fatalf("failed to build %v with %v: %v, %s", targets, goBin, err, errOut)
}

func findGo(t testing.TB) string {
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go"+exe())
	if fi, err := os.Stat(goBin); err != nil {
		if os.IsNotExist(err) {
			t.Fatalf("failed to find go at %v", goBin)
		}
		t.Fatalf("looking for go binary: %v", err)
	} else if !fi.Mode().IsRegular() {
		t.Fatalf("%v is unexpected %v", goBin, fi.Mode())
	}
	return goBin
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
						Name:         "t1",
						RegionID:     1,
						HostName:     ipAddress,
						IPv4:         ipAddress,
						IPv6:         "none",
						STUNPort:     stunAddr.Port,
						DERPTestPort: httpsrv.Listener.Addr().(*net.TCPAddr).Port,
						STUNTestIP:   stunAddr.IP.String(),
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
