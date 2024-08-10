// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package integration contains Tailscale integration tests.
//
// This package is considered internal and the public API is subject
// to change without notice.
package integration

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/nettype"
	"tailscale.com/util/zstdframe"
	"tailscale.com/version"
)

// CleanupBinaries cleans up any resources created by calls to BinaryDir, TailscaleBinary, or TailscaledBinary.
// It should be called from TestMain after all tests have completed.
func CleanupBinaries() {
	buildOnce.Do(func() {})
	if binDir != "" {
		os.RemoveAll(binDir)
	}
}

// BinaryDir returns a directory containing test tailscale and tailscaled binaries.
// If any test calls BinaryDir, there must be a TestMain function that calls
// CleanupBinaries after all tests are complete.
func BinaryDir(tb testing.TB) string {
	buildOnce.Do(func() {
		binDir, buildErr = buildTestBinaries()
	})
	if buildErr != nil {
		tb.Fatal(buildErr)
	}
	return binDir
}

// TailscaleBinary returns the path to the test tailscale binary.
// If any test calls TailscaleBinary, there must be a TestMain function that calls
// CleanupBinaries after all tests are complete.
func TailscaleBinary(tb testing.TB) string {
	return filepath.Join(BinaryDir(tb), "tailscale"+exe())
}

// TailscaledBinary returns the path to the test tailscaled binary.
// If any test calls TailscaleBinary, there must be a TestMain function that calls
// CleanupBinaries after all tests are complete.
func TailscaledBinary(tb testing.TB) string {
	return filepath.Join(BinaryDir(tb), "tailscaled"+exe())
}

var (
	buildOnce sync.Once
	buildErr  error
	binDir    string
)

// buildTestBinaries builds tailscale and tailscaled.
// It returns the dir containing the binaries.
func buildTestBinaries() (string, error) {
	bindir, err := os.MkdirTemp("", "")
	if err != nil {
		return "", err
	}
	err = build(bindir, "tailscale.com/cmd/tailscaled", "tailscale.com/cmd/tailscale")
	if err != nil {
		os.RemoveAll(bindir)
		return "", err
	}
	return bindir, nil
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
			cmd := exec.Command(goBin, "build", "-o", outFile)
			if version.IsRace() {
				cmd.Args = append(cmd.Args, "-race")
			}
			cmd.Args = append(cmd.Args, target)
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
	// Go 1.19 attempted to be helpful by prepending $PATH with GOROOT/bin based
	// on the executed go binary when invoked using `go test` or `go generate`,
	// however, this doesn't cover cases when run otherwise, such as via `go run`.
	// runtime.GOROOT() may often be empty these days, so the safe thing to do
	// here is, in order:
	// 1. Look for a go binary in $PATH[0].
	// 2. Look for a go binary in runtime.GOROOT()/bin if runtime.GOROOT() is non-empty.
	// 3. Look for a go binary in $PATH.

	// For tests we want to run as root on GitHub actions, we run with -exec=sudo,
	// but that results in this test running with a different PATH and picking the
	// wrong Go. So hard code the GitHub Actions case.
	if os.Getuid() == 0 && os.Getenv("GITHUB_ACTIONS") == "true" {
		const sudoGithubGo = "/home/runner/.cache/tailscale-go/bin/go"
		if _, err := os.Stat(sudoGithubGo); err == nil {
			return sudoGithubGo, nil
		}
	}

	paths := strings.FieldsFunc(os.Getenv("PATH"), func(r rune) bool { return os.IsPathSeparator(uint8(r)) })
	if len(paths) > 0 {
		candidate := filepath.Join(paths[0], "go"+exe())
		if path, err := exec.LookPath(candidate); err == nil {
			return path, err
		}
	}

	if runtime.GOROOT() != "" {
		candidate := filepath.Join(runtime.GOROOT(), "bin", "go"+exe())
		if path, err := exec.LookPath(candidate); err == nil {
			return path, err
		}
	}

	return exec.LookPath("go")
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

	d := derp.NewServer(key.NewNode(), logf)

	ln, err := net.Listen("tcp", net.JoinHostPort(ipAddress, "0"))
	if err != nil {
		t.Fatal(err)
	}

	httpsrv := httptest.NewUnstartedServer(derphttp.Handler(d))
	httpsrv.Listener.Close()
	httpsrv.Listener = ln
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
						STUNTestIP:       ipAddress,
					},
				},
			},
		},
	}

	t.Logf("DERP httpsrv listener: %v", httpsrv.Listener.Addr())

	t.Cleanup(func() {
		httpsrv.CloseClientConnections()
		httpsrv.Close()
		d.Close()
		stunCleanup()
		ln.Close()
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
	raw    bool // indicates whether to store the raw JSON logs uploaded, instead of just the text
}

// UseLogf makes the logcatcher implementation use a given logf function
// to dump all logs to.
func (lc *LogCatcher) UseLogf(fn logger.Logf) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.logf = fn
}

// StoreRawJSON instructs lc to save the raw JSON uploads, rather than just the text.
func (lc *LogCatcher) StoreRawJSON() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.raw = true
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
	// POST /c/<collection-name>/<private-ID>
	if r.Method != "POST" {
		log.Printf("bad logcatcher method: %v", r.Method)
		http.Error(w, "only POST is supported", 400)
		return
	}
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/c/"), "/")
	if len(pathParts) != 2 {
		log.Printf("bad logcatcher path: %q", r.URL.Path)
		http.Error(w, "bad URL", 400)
		return
	}
	// collectionName := pathPaths[0]
	privID, err := logid.ParsePrivateID(pathParts[1])
	if err != nil {
		log.Printf("bad log ID: %q: %v", r.URL.Path, err)
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("http.Request.Body.Read: %v", err)
		return
	}
	if r.Header.Get("Content-Encoding") == "zstd" {
		bodyBytes, err = zstdframe.AppendDecode(nil, bodyBytes)
		if err != nil {
			log.Printf("zstdframe.AppendDecode: %v", err)
			http.Error(w, err.Error(), 400)
			return
		}
	}

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
		if lc.logf != nil {
			lc.logf("error from %s of %#q: %v\n", r.Method, bodyBytes, err)
		}
	} else {
		id := privID.Public().String()[:3] // good enough for integration tests
		for _, ent := range jreq {
			if lc.raw {
				lc.buf.Write(bodyBytes)
				continue
			}
			fmt.Fprintf(&lc.buf, "%s\n", strings.TrimSpace(ent.Text))
			if lc.logf != nil {
				lc.logf("logcatch:%s: %s", id, strings.TrimSpace(ent.Text))
			}
		}
	}
	w.WriteHeader(200) // must have no content, but not a 204
}
