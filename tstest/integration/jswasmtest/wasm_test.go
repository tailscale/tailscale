// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package jswasmtest contains headless-browser tests for the
// @tailscale/connect NPM package, built by cmd/tsconnect from
// tailscale.com/cmd/tsconnect/wasm (the js/wasm build of the client).
//
// To run locally:
//
//	./tool/go run ./cmd/tsconnect build-pkg
//	./tool/go test ./tstest/integration/jswasmtest/ -v --run-headless-browser-tests
//
// Tests are skipped unless --run-headless-browser-tests is set. When the
// flag is set, tests are also skipped if cmd/tsconnect/pkg/ has not been
// built, and fail with t.Error if no chromium binary is found in $PATH
// (honoring $CHROME_BIN as an override). On macOS, /Applications/Google
// Chrome.app and /Applications/Chromium.app are also tried.
//
// macOS note: launching Chrome from a terminal as a child process may
// trigger the system "App Management" privacy prompt on Sonoma and later
// (a one-shot prompt that says "<terminal> was prevented from modifying
// apps on your Mac"). Grant the terminal app this permission under
// System Settings → Privacy & Security → App Management and re-run.
package jswasmtest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	cdpruntime "github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"tailscale.com/cmd/tsconnect/wasmbuild"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
)

// pkgDir is the path to cmd/tsconnect/pkg/ (the directory written by
// `go run ./cmd/tsconnect build-pkg`), relative to this test file's
// directory (the cwd `go test` sets).
const pkgDir = "../../../cmd/tsconnect/pkg"

var runHeadlessBrowserTests = flag.Bool("run-headless-browser-tests", false,
	"run tests that require a headless browser (Chromium / Google Chrome)")

// preflight returns the chromium binary path, or fails / skips the test as
// appropriate. Tests skip if --run-headless-browser-tests is not set or if
// cmd/tsconnect/pkg/ has not been built. They t.Error if the flag is set
// but no chromium binary is on $PATH.
func preflight(t *testing.T) (chromiumBin string) {
	t.Helper()
	if !*runHeadlessBrowserTests {
		t.Skip("skipping headless-browser test; set --run-headless-browser-tests to run")
	}
	if _, err := os.Stat(filepath.Join(pkgDir, "main.wasm")); err != nil {
		t.Skipf("cmd/tsconnect/pkg/ not built; run "+
			"`./tool/go run ./cmd/tsconnect build-pkg` first: %v", err)
	}
	checkPkgFreshness(t)
	if t.Failed() {
		return ""
	}
	bin := findChromium()
	if bin == "" {
		t.Errorf("no chromium / chromium-browser / google-chrome binary in $PATH " +
			"(set $CHROME_BIN to override)")
		return ""
	}
	return bin
}

// launchChrome boots a headless chromium under chromedp and returns a context
// whose cancellation tears down the browser.
func launchChrome(t *testing.T, bin string, extraFlags map[string]any) context.Context {
	t.Helper()
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(bin),
		chromedp.Flag("headless", "new"),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)
	for k, v := range extraFlags {
		opts = append(opts, chromedp.Flag(k, v))
	}
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(t.Context(), opts...)
	t.Cleanup(cancelAlloc)
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx, chromedp.WithLogf(t.Logf))
	t.Cleanup(cancelBrowser)

	// Pipe browser console output and uncaught exceptions into go test logs.
	chromedp.ListenTarget(browserCtx, func(ev any) {
		switch ev := ev.(type) {
		case *cdpruntime.EventConsoleAPICalled:
			var sb strings.Builder
			for i, arg := range ev.Args {
				if i > 0 {
					sb.WriteByte(' ')
				}
				if len(arg.Value) > 0 {
					sb.Write(arg.Value)
				} else {
					sb.WriteString(arg.Description)
				}
			}
			t.Logf("[chrome console.%s] %s", ev.Type, sb.String())
		case *cdpruntime.EventExceptionThrown:
			t.Logf("[chrome exception] %s", ev.ExceptionDetails.Text)
		}
	})
	return browserCtx
}

// TestCreateIPN loads pkg.js into a real browser, calls createIPN with a
// junk auth key, and verifies that the documented public API surface is
// present on both the module exports and the returned IPN object. It does
// no control-plane traffic.
func TestCreateIPN(t *testing.T) {
	chromiumBin := preflight(t)
	if t.Failed() {
		return
	}

	mux := http.NewServeMux()
	mux.Handle("/_pkg/", http.StripPrefix("/_pkg/", http.FileServer(http.Dir(pkgDir))))
	mux.Handle("/", http.FileServer(http.Dir(".")))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	browserCtx := launchChrome(t, chromiumBin, nil)
	runCtx, cancelRun := context.WithTimeout(browserCtx, 60*time.Second)
	t.Cleanup(cancelRun)

	var (
		done             bool
		imported         bool
		importErrors     []string
		runtimeErrs      []string
		panics           []string
		exports          map[string]string
		ipnMethods       map[string]string
		instantiateError string
	)

	if err := chromedp.Run(runCtx,
		chromedp.Navigate(srv.URL+"/index.html"),
		chromedp.Poll("window.tsTest && window.tsTest.done === true", &done,
			chromedp.WithPollingTimeout(45*time.Second)),
		chromedp.Evaluate("window.tsTest.imported", &imported),
		chromedp.Evaluate("window.tsTest.importErrors", &importErrors),
		chromedp.Evaluate("window.tsTest.exports", &exports),
		chromedp.Evaluate("window.tsTest.instantiateError || ''", &instantiateError),
		chromedp.Evaluate("window.tsTest.ipnMethods", &ipnMethods),
		chromedp.Evaluate("window.tsTest.runtimeErrors", &runtimeErrs),
		chromedp.Evaluate("window.tsTest.panics", &panics),
	); err != nil {
		t.Fatalf("chromedp run: %v", err)
	}

	if !done {
		t.Fatalf("page never set window.tsTest.done = true")
	}
	if !imported {
		t.Fatalf("pkg.js import failed: %v", importErrors)
	}
	if instantiateError != "" {
		t.Fatalf("createIPN() rejected: %s", instantiateError)
	}

	wantExports := map[string]string{
		"createIPN":     "function",
		"runSSHSession": "function",
	}
	for name, want := range wantExports {
		if got := exports[name]; got != want {
			t.Errorf("typeof pkg.%s = %q; want %q", name, got, want)
		}
	}

	wantIPN := []string{"run", "login", "logout", "ssh", "fetch"}
	for _, name := range wantIPN {
		if got := ipnMethods[name]; got != "function" {
			t.Errorf("createIPN() result: typeof ipn.%s = %q; want %q",
				name, got, "function")
		}
	}

	for _, e := range panics {
		t.Errorf("WASM panic handler invoked: %s", e)
	}
	for _, e := range runtimeErrs {
		// The WASM may emit non-fatal console errors (e.g. failed log uploads,
		// no DERP, etc.); only fail on errors that look like a real crash.
		if strings.Contains(e, "RuntimeError") || strings.Contains(e, "panic:") {
			t.Errorf("page runtime error: %s", e)
		} else {
			t.Logf("benign page runtime message: %s", e)
		}
	}
}

// TestFetchTailnetPeer wires a full local control-plane world
// (testcontrol + DERP + a tsnet.Server peer) and verifies that the
// browser-side WASM client can join the same tailnet over WebSocket
// transport and then ipn.fetch() an HTTP service hosted on the tsnet peer.
//
// The transport stack exercised by this test (browser-only):
//   - control plane noise upgrade over ws:// (via control/controlhttp/client_js.go)
//   - DERP relay over wss:// (via derp/derphttp + derpserver.AddWebSocketSupport)
//   - ipn.fetch dials via netstack through DERP to the tsnet peer
//
// The DERP server uses a self-signed httptest TLS cert; Chromium is
// launched with --ignore-certificate-errors so the WSS connect succeeds.
func TestFetchTailnetPeer(t *testing.T) {
	chromiumBin := preflight(t)
	if t.Failed() {
		return
	}

	const authKey = "tskey-pkgtest-not-a-real-key"
	const wantBody = "hello-from-tsnet-pkgtest"

	derpMap := integration.RunDERPAndSTUN(t, t.Logf, "127.0.0.1")

	control := &testcontrol.Server{
		DERPMap:        derpMap,
		Logf:           t.Logf,
		RequireAuthKey: authKey,
		AllOnline:      true,
	}

	// Single-origin HTTP server: static fixtures + pkg + testcontrol all on
	// one origin so the browser's WebSocket-upgrade dial to /ts2021 stays
	// same-origin and so the WASM can configure controlURL = page origin.
	//
	// Only route testcontrol's known paths to it; everything else returns
	// 404. testcontrol's default-handler panics on any unrecognized request,
	// and Chromium spontaneously fetches /favicon.ico and similar browser
	// chrome that would otherwise crash the test.
	mux := http.NewServeMux()
	mux.Handle("/_pkg/", http.StripPrefix("/_pkg/", http.FileServer(http.Dir(pkgDir))))
	mux.Handle("/_fixture/", http.StripPrefix("/_fixture/", http.FileServer(http.Dir("."))))
	mux.Handle("/key", control)
	mux.Handle("/ts2021", control)
	mux.Handle("/machine/", control)
	mux.Handle("/c2n/", control)
	mux.HandleFunc("/", http.NotFound)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	peer := &tsnet.Server{
		Dir:        t.TempDir(),
		ControlURL: srv.URL,
		AuthKey:    authKey,
		Hostname:   "tsnetpeer",
		Ephemeral:  true,
		Logf:       t.Logf,
		Store:      new(mem.Store),
	}
	t.Cleanup(func() { peer.Close() })

	upCtx, cancelUp := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancelUp()
	status, err := peer.Up(upCtx)
	if err != nil {
		t.Fatalf("tsnet peer Up: %v", err)
	}
	if len(status.TailscaleIPs) == 0 {
		t.Fatalf("tsnet peer has no TailscaleIPs")
	}
	peerIP := status.TailscaleIPs[0]
	t.Logf("tsnet peer up at %v", peerIP)

	ln, err := peer.Listen("tcp", ":80")
	if err != nil {
		t.Fatalf("tsnet peer Listen :80: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, wantBody)
	}))

	browserCtx := launchChrome(t, chromiumBin, map[string]any{
		"ignore-certificate-errors": true,
	})
	runCtx, cancelRun := context.WithTimeout(browserCtx, 120*time.Second)
	t.Cleanup(cancelRun)

	peerURL := fmt.Sprintf("http://%s/", peerIP)
	pageURL := srv.URL + "/_fixture/index.html?" + url.Values{
		"mode":       {"fetch"},
		"controlURL": {srv.URL},
		"authKey":    {authKey},
		"peerURL":    {peerURL},
		"hostname":   {"browser-pkgtest"},
	}.Encode()
	t.Logf("navigating to %s", pageURL)

	var (
		done         bool
		imported     bool
		importErrors []string
		states       []string
		browseURLs   []string
		runError     string
		fetchError   string
		fetchResult  map[string]any
		panics       []string
		runtimeErrs  []string
	)

	if err := chromedp.Run(runCtx,
		chromedp.Navigate(pageURL),
		chromedp.Poll("window.tsTest && window.tsTest.done === true", &done,
			chromedp.WithPollingTimeout(100*time.Second)),
		chromedp.Evaluate("window.tsTest.imported", &imported),
		chromedp.Evaluate("window.tsTest.importErrors", &importErrors),
		chromedp.Evaluate("window.tsTest.states", &states),
		chromedp.Evaluate("window.tsTest.browseURLs", &browseURLs),
		chromedp.Evaluate("window.tsTest.runError || ''", &runError),
		chromedp.Evaluate("window.tsTest.fetchError || ''", &fetchError),
		chromedp.Evaluate("window.tsTest.fetchResult", &fetchResult),
		chromedp.Evaluate("window.tsTest.panics", &panics),
		chromedp.Evaluate("window.tsTest.runtimeErrors", &runtimeErrs),
	); err != nil {
		t.Fatalf("chromedp run: %v", err)
	}

	t.Logf("browser state transitions: %v", states)
	if len(browseURLs) > 0 {
		t.Logf("browser notifyBrowseToURL: %v", browseURLs)
	}

	if !done {
		t.Fatalf("page never set window.tsTest.done = true")
	}
	if !imported {
		t.Fatalf("pkg.js import failed: %v", importErrors)
	}
	if runError != "" {
		t.Fatalf("ipn.run did not reach Running: %s (states=%v)", runError, states)
	}
	if fetchError != "" {
		t.Fatalf("ipn.fetch failed: %s (states=%v)", fetchError, states)
	}
	if fetchResult == nil {
		t.Fatalf("fetchResult is nil; states=%v", states)
	}

	if statusCode, _ := fetchResult["status"].(float64); int(statusCode) != http.StatusOK {
		t.Errorf("fetch status = %v; want %d", fetchResult["status"], http.StatusOK)
	}
	body, _ := fetchResult["body"].(string)
	if !strings.Contains(body, wantBody) {
		t.Errorf("fetch body = %q; want substring %q", body, wantBody)
	}

	for _, e := range panics {
		t.Errorf("WASM panic handler invoked: %s", e)
	}
	for _, e := range runtimeErrs {
		if strings.Contains(e, "RuntimeError") || strings.Contains(e, "panic:") {
			t.Errorf("page runtime error: %s", e)
		} else {
			t.Logf("benign page runtime message: %s", e)
		}
	}
}

func findChromium() string {
	if p := os.Getenv("CHROME_BIN"); p != "" {
		return p
	}
	for _, name := range []string{
		"chromium",
		"chromium-browser",
		"google-chrome",
		"google-chrome-stable",
		"chrome",
	} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	if runtime.GOOS == "darwin" {
		// On macOS, Chrome installs as an .app bundle whose executable is
		// not on $PATH.
		for _, p := range []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

// checkPkgFreshness fails the test if pkg/main.wasm was built from source
// that differs from what `go build` would produce against the current
// working tree. The mechanism is to do a fresh `go build` of
// cmd/tsconnect/wasm with the same flags build-pkg used, sha256 the
// output, and compare against pkg/build-info.json's recorded raw sha256.
// The Go build cache makes the rebuild nearly instant when CI just ran
// build-pkg, and equally fast locally between iterations.
func checkPkgFreshness(t *testing.T) {
	t.Helper()
	biPath := filepath.Join(pkgDir, wasmbuild.BuildInfoFile)
	biBytes, err := os.ReadFile(biPath)
	if err != nil {
		t.Fatalf("reading %s: %v\nRe-run `./tool/go run ./cmd/tsconnect build-pkg`.", biPath, err)
	}
	var bi wasmbuild.BuildInfo
	if err := json.Unmarshal(biBytes, &bi); err != nil {
		t.Fatalf("parsing %s: %v", biPath, err)
	}

	tmpWasm := filepath.Join(t.TempDir(), "main.wasm")
	cmd := wasmbuild.ProdCommand("", tmpWasm)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	t.Logf("checking pkg freshness: %s", strings.Join(cmd.Args, " "))
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build cmd/tsconnect/wasm: %v", err)
	}
	freshSum, err := sha256File(tmpWasm)
	if err != nil {
		t.Fatalf("sha256 %s: %v", tmpWasm, err)
	}
	if freshSum != bi.RawWasmSHA256 {
		t.Fatalf("pkg/main.wasm is stale\n"+
			"  build-info.json raw_wasm_sha256: %s\n"+
			"  freshly built (same -tags/-ldflags): %s\n"+
			"Re-run `./tool/go run ./cmd/tsconnect build-pkg`.",
			bi.RawWasmSHA256, freshSum)
	}
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
