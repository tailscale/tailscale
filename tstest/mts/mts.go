// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The mts ("Multiple Tailscale") command runs multiple tailscaled instances for
// development, manging their directories and sockets, and lets you easily direct
// tailscale CLI commands to them.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"tailscale.com/types/lazy"
	"tailscale.com/util/mak"
)

func usage() {
	fmt.Fprintf(os.Stderr, strings.TrimSpace(`
	usage: mts run   # start mts daemon, runs all tailscaled daemons
		   mts list  # list all tailscaled daemons
		   mts rm <name> # remove a named tailscaled daemon
		   mts <name> <tailscale args> # run a tailscale command against a named daemon, creating as needed
	`))
	os.Exit(1)
}

func main() {
	// Don't use flag.Parse here; we mostly just delegate through
	// to the Tailscale CLI.

	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	var c Client
	switch cmd {
	case "run":
		var s Server
		s.Run()
		return
	case "list":
		list, err := c.ListNames()
		if err != nil {
			log.Fatal(err)
		}
		for _, name := range list {
			fmt.Println(name)
		}
		return
	case "rm":
		if len(os.Args) != 3 {
			usage()
		}
		name := os.Args[2]
		if err := c.Remove(name); err != nil {
			log.Fatal(err)
		}
		return
	case "add":
		if len(os.Args) != 3 {
			usage()
		}
		name := os.Args[2]
		if err := c.Remove(name); err != nil {
			log.Fatal(err)
		}
		return
	}
	inst := os.Args[1]
	c.RunCommand(inst, os.Args[2:])
}

type Client struct {
}

func (c *Client) client() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", mtsSock())
			},
		},
	}
}

func (c *Client) ListNames() ([]string, error) {
	panic("TODO")
	return []string{}, nil
}

func (c *Client) Remove(name string) error {
	panic("TODO")
	return nil
}

func (c *Client) Create(name string) error {
	req, err := http.NewRequest("POST", "http://mts/create/"+name, nil)
	if err != nil {
		return err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status: %v: %s", resp.Status, body)
	}
	return nil
}

func (c *Client) RunCommand(name string, args []string) {
	if err := c.Create(name); err != nil {
		log.Fatal(err)
	}
	sock := instSock(name)
	args = append([]string{"run", "tailscale.com/cmd/tailscale", "--socket=" + sock}, args...)
	cmd := exec.Command("go", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if err == nil {
		os.Exit(0)
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		os.Exit(exitErr.ExitCode())
	}
	panic(err)
}

type Server struct {
	lazyTailscaled lazy.GValue[string]

	mu   sync.Mutex
	cmds map[string]*exec.Cmd // running tailscaled instances
}

func (s *Server) tailscaled() string {
	v, err := s.lazyTailscaled.GetErr(func() (string, error) {
		out, err := exec.Command("go", "list", "-f", "{{.Target}}", "tailscale.com/cmd/tailscaled").CombinedOutput()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(out)), nil
	})
	if err != nil {
		panic(err)
	}
	return v
}

func (s *Server) Run() {
	if err := os.MkdirAll(instDir(), 0700); err != nil {
		panic(err)
	}

	log.Printf("Running all Tailscale daemons: %q", s.InstanceNames())
	for _, name := range s.InstanceNames() {
		go s.RunInstance(name)
	}

	sock := mtsSock()
	os.Remove(sock)
	log.Printf("Listening on %q ...", sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		panic(err)
	}
	log.Fatal(http.Serve(ln, s))
}

var validNameRx = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func validInstanceName(name string) bool {
	return validNameRx.MatchString(name)
}

func (s *Server) InstanceRunning(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.cmds[name]
	return ok
}

func (s *Server) RunInstance(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.cmds[name]; ok {
		return fmt.Errorf("instance %q already running", name)
	}

	if !validInstanceName(name) {
		panic(fmt.Sprintf("invalid instance name %q", name))
	}
	dir := filepath.Join(instDir(), name)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	log.Printf("Running Tailscale daemon %q in %q", name, dir)

	cmd := exec.Command(s.tailscaled(),
		"--tun=userspace-networking",
		"--statedir="+filepath.Join(dir),
		"--socket="+filepath.Join(dir, "tailscaled.sock"),
		"--verbose=1",
	)
	cmd.Dir = dir

	// TODO(bradfitz): capture these, record in memory, serve
	// them via HTTP?
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		err := cmd.Wait()
		log.Printf("Tailscale daemon %q exited: %v", name, err)
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.cmds, name)
	}()

	mak.Set(&s.cmds, name, cmd)
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if inst, ok := strings.CutPrefix(r.URL.Path, "/create/"); ok {
		if !s.InstanceRunning(inst) {
			if err := s.RunInstance(inst); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		fmt.Fprintf(w, "OK\n")
		return
	}
	fmt.Fprintf(w, "Hello, %s\n", r.URL.Path)
}

func (s *Server) InstanceNames() []string {
	var ret []string
	des, err := os.ReadDir(instDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		panic(err)
	}
	for _, de := range des {
		if !de.IsDir() {
			continue
		}
		ret = append(ret, de.Name())
	}
	return ret
}

func instDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		panic(err)
	}
	return filepath.Join(dir, "multi-tailscale-dev")
}

func instSock(name string) string {
	return filepath.Join(instDir(), name, "tailscaled.sock")
}

func mtsSock() string {
	return filepath.Join(instDir(), "mts.sock")
}
