// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package web

import (
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	prebuilt "github.com/tailscale/web-client-prebuilt"
)

var start = time.Now()

func assetsHandler(devMode bool) (_ http.Handler, cleanup func()) {
	if devMode {
		// When in dev mode, proxy asset requests to the Vite dev server.
		cleanup := startDevServer()
		return devServerProxy(), cleanup
	}

	fsys := prebuilt.FS()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		f, err := openPrecompressedFile(w, r, path, fsys)
		if err != nil {
			// Rewrite request to just fetch index.html and let
			// the frontend router handle it.
			r = r.Clone(r.Context())
			path = "index.html"
			f, err = openPrecompressedFile(w, r, path, fsys)
		}
		if f == nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()

		// fs.File does not claim to implement Seeker, but in practice it does.
		fSeeker, ok := f.(io.ReadSeeker)
		if !ok {
			http.Error(w, "Not seekable", http.StatusInternalServerError)
			return
		}

		if strings.HasPrefix(path, "assets/") {
			// Aggressively cache static assets, since we cache-bust our assets with
			// hashed filenames.
			w.Header().Set("Cache-Control", "public, max-age=31535996")
			w.Header().Set("Vary", "Accept-Encoding")
		}

		http.ServeContent(w, r, path, start, fSeeker)
	}), nil
}

func openPrecompressedFile(w http.ResponseWriter, r *http.Request, path string, fs fs.FS) (fs.File, error) {
	if f, err := fs.Open(path + ".gz"); err == nil {
		w.Header().Set("Content-Encoding", "gzip")
		return f, nil
	}
	return fs.Open(path) // fallback
}

// startDevServer starts the JS dev server that does on-demand rebuilding
// and serving of web client JS and CSS resources.
func startDevServer() (cleanup func()) {
	root := gitRootDir()
	webClientPath := filepath.Join(root, "client", "web")

	yarn := filepath.Join(root, "tool", "yarn")
	node := filepath.Join(root, "tool", "node")
	vite := filepath.Join(webClientPath, "node_modules", ".bin", "vite")

	log.Printf("installing JavaScript deps using %s...", yarn)
	out, err := exec.Command(yarn, "--non-interactive", "-s", "--cwd", webClientPath, "install").CombinedOutput()
	if err != nil {
		log.Fatalf("error running tailscale web's yarn install: %v, %s", err, out)
	}
	log.Printf("starting JavaScript dev server...")
	cmd := exec.Command(node, vite)
	cmd.Dir = webClientPath
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		log.Fatalf("Starting JS dev server: %v", err)
	}
	log.Printf("JavaScript dev server running as pid %d", cmd.Process.Pid)
	return func() {
		cmd.Process.Signal(os.Interrupt)
		err := cmd.Wait()
		log.Printf("JavaScript dev server exited: %v", err)
	}
}

// devServerProxy returns a reverse proxy to the vite dev server.
func devServerProxy() *httputil.ReverseProxy {
	// We use Vite to develop on the web client.
	// Vite starts up its own local server for development,
	// which we proxy requests to from Server.ServeHTTP.
	// Here we set up the proxy to Vite's server.
	handleErr := func(w http.ResponseWriter, r *http.Request, err error) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("The web client development server isn't running. " +
			"Run `./tool/yarn --cwd client/web start` from " +
			"the repo root to start the development server."))
		w.Write([]byte("\n\nError: " + err.Error()))
	}
	viteTarget, _ := url.Parse("http://127.0.0.1:4000")
	devProxy := httputil.NewSingleHostReverseProxy(viteTarget)
	devProxy.ErrorHandler = handleErr
	return devProxy
}

func gitRootDir() string {
	top, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		log.Fatalf("failed to find git top level (not in corp git?): %v", err)
	}
	return strings.TrimSpace(string(top))
}
