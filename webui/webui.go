// Package webui provides the Tailscale client for web.
package webui

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Server struct {
	DevMode bool
}

func (s *Server) Start() {
}

func (s *Server) Handle(w http.ResponseWriter, r *http.Request) {
	if s.DevMode {
		au, _ := url.Parse("http://127.0.0.1:4000")
		proxy := httputil.NewSingleHostReverseProxy(au)
		proxy.ServeHTTP(w, r)
		return
	}
	fmt.Fprintf(w, "Hello production")
}

func RunJSDevServer() (cleanup func()) {
	root := gitRootDir()
	webuiPath := filepath.Join(root, "webui")

	yarn := filepath.Join(root, "tool", "yarn")
	node := filepath.Join(root, "tool", "node")
	vite := filepath.Join(webuiPath, "node_modules", ".bin", "vite")

	log.Printf("installing JavaScript deps using %s... (might take ~30s)", yarn)
	out, err := exec.Command(yarn, "--non-interactive", "-s", "--cwd", webuiPath, "install").CombinedOutput()
	if err != nil {
		log.Fatalf("error running admin panel's yarn install: %v, %s", err, out)
	}
	log.Printf("starting JavaScript dev server...")
	cmd := exec.Command(node, vite)
	cmd.Dir = webuiPath
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

func gitRootDir() string {
	top, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		log.Fatalf("failed to find git top level (not in corp git?): %v", err)
	}
	return strings.TrimSpace(string(top))
}
