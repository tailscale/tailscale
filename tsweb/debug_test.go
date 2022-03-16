// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsweb

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

func TestDebugger(t *testing.T) {
	mux := http.NewServeMux()

	dbg1 := Debugger(mux)
	if dbg1 == nil {
		t.Fatal("didn't get a debugger from mux")
	}

	dbg2 := Debugger(mux)
	if dbg2 != dbg1 {
		t.Fatal("Debugger returned different debuggers for the same mux")
	}

	t.Run("cpu_pprof", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping second long test")
		}
		switch runtime.GOOS {
		case "linux", "darwin":
		default:
			t.Skipf("skipping test on %v", runtime.GOOS)
		}
		req := httptest.NewRequest("GET", "/debug/pprof/profile?seconds=1", nil)
		req.RemoteAddr = "100.101.102.103:1234"
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		res := rec.Result()
		if res.StatusCode != 200 {
			t.Errorf("unexpected %v", res.Status)
		}
	})
}

func get(m http.Handler, path, srcIP string) (int, string) {
	req := httptest.NewRequest("GET", path, nil)
	req.RemoteAddr = srcIP + ":1234"
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)
	return rec.Result().StatusCode, rec.Body.String()
}

const (
	tsIP  = "100.100.100.100"
	pubIP = "8.8.8.8"
)

func TestDebuggerKV(t *testing.T) {
	mux := http.NewServeMux()
	dbg := Debugger(mux)
	dbg.KV("Donuts", 42)
	dbg.KV("Secret code", "hunter2")
	val := "red"
	dbg.KVFunc("Condition", func() any { return val })

	code, _ := get(mux, "/debug/", pubIP)
	if code != 403 {
		t.Fatalf("debug access wasn't denied, got %v", code)
	}

	code, body := get(mux, "/debug/", tsIP)
	if code != 200 {
		t.Fatalf("debug access failed, got %v", code)
	}
	for _, want := range []string{"Donuts", "42", "Secret code", "hunter2", "Condition", "red"} {
		if !strings.Contains(body, want) {
			t.Errorf("want %q in output, not found", want)
		}
	}

	val = "green"
	code, body = get(mux, "/debug/", tsIP)
	if code != 200 {
		t.Fatalf("debug access failed, got %v", code)
	}
	for _, want := range []string{"Condition", "green"} {
		if !strings.Contains(body, want) {
			t.Errorf("want %q in output, not found", want)
		}
	}
}

func TestDebuggerURL(t *testing.T) {
	mux := http.NewServeMux()
	dbg := Debugger(mux)
	dbg.URL("https://www.tailscale.com", "Homepage")

	code, body := get(mux, "/debug/", tsIP)
	if code != 200 {
		t.Fatalf("debug access failed, got %v", code)
	}
	for _, want := range []string{"https://www.tailscale.com", "Homepage"} {
		if !strings.Contains(body, want) {
			t.Errorf("want %q in output, not found", want)
		}
	}
}

func TestDebuggerSection(t *testing.T) {
	mux := http.NewServeMux()
	dbg := Debugger(mux)
	dbg.Section(func(w io.Writer, r *http.Request) {
		fmt.Fprintf(w, "Test output %v", r.RemoteAddr)
	})

	code, body := get(mux, "/debug/", tsIP)
	if code != 200 {
		t.Fatalf("debug access failed, got %v", code)
	}
	want := `Test output 100.100.100.100:1234`
	if !strings.Contains(body, want) {
		t.Errorf("want %q in output, not found", want)
	}
}

func TestDebuggerHandle(t *testing.T) {
	mux := http.NewServeMux()
	dbg := Debugger(mux)
	dbg.Handle("check", "Consistency check", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Test output %v", r.RemoteAddr)
	}))

	code, body := get(mux, "/debug/", tsIP)
	if code != 200 {
		t.Fatalf("debug access failed, got %v", code)
	}
	for _, want := range []string{"/debug/check", "Consistency check"} {
		if !strings.Contains(body, want) {
			t.Errorf("want %q in output, not found", want)
		}
	}

	code, _ = get(mux, "/debug/check", pubIP)
	if code != 403 {
		t.Fatal("/debug/check should be protected, but isn't")
	}

	code, body = get(mux, "/debug/check", tsIP)
	if code != 200 {
		t.Fatal("/debug/check denied debug access")
	}
	want := "Test output " + tsIP
	if !strings.Contains(body, want) {
		t.Errorf("want %q in output, not found", want)
	}
}

func ExampleDebugHandler_Handle() {
	mux := http.NewServeMux()
	dbg := Debugger(mux)
	// Registers /debug/flushcache with the given handler, and adds a
	// link to /debug/ with the description "Flush caches".
	dbg.Handle("flushcache", "Flush caches", http.HandlerFunc(http.NotFound))
}

func ExampleDebugHandler_KV() {
	mux := http.NewServeMux()
	dbg := Debugger(mux)
	// Adds two list items to /debug/, showing that the condition is
	// red and there are 42 donuts.
	dbg.KV("Condition", "red")
	dbg.KV("Donuts", 42)
}

func ExampleDebugHandler_KVFunc() {
	mux := http.NewServeMux()
	dbg := Debugger(mux)
	// Adds an count of page renders to /debug/. Note this example
	// isn't concurrency-safe.
	views := 0
	dbg.KVFunc("Debug pageviews", func() any {
		views = views + 1
		return views
	})
	dbg.KV("Donuts", 42)
}

func ExampleDebugHandler_URL() {
	mux := http.NewServeMux()
	dbg := Debugger(mux)
	// Links to the Tailscale website from /debug/.
	dbg.URL("https://www.tailscale.com", "Homepage")
}

func ExampleDebugHandler_Section() {
	mux := http.NewServeMux()
	dbg := Debugger(mux)
	// Adds a section to /debug/ that dumps the HTTP request of the
	// visitor.
	dbg.Section(func(w io.Writer, r *http.Request) {
		io.WriteString(w, "<h3>Dump of your HTTP request</h3>")
		fmt.Fprintf(w, "<code>%#v</code>", r)
	})
}
