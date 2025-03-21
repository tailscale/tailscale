// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

// The mts ("Multiple Tailscale") command runs multiple tailscaled instances for
// development, managing their directories and sockets, and lets you easily direct
// tailscale CLI commands to them.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/types/bools"
	"tailscale.com/types/lazy"
	"tailscale.com/util/mak"
)

func usage(args ...any) {
	var format string
	if len(args) > 0 {
		format, args = args[0].(string), args[1:]
	}
	if format != "" {
		format = strings.TrimSpace(format) + "\n\n"
		fmt.Fprintf(os.Stderr, format, args...)
	}
	io.WriteString(os.Stderr, strings.TrimSpace(`
usage:

   mts server <subcommand>      # manage tailscaled instances
   mts server run               # run the mts server (parent process of all tailscaled)
   mts server list              # list all tailscaled and their state
   mts server list <name>       # show details of named instance
   mts server add <name>        # add+start new named tailscaled
   mts server start <name>      # start a previously added tailscaled
   mts server stop <name>       # stop & remove a named tailscaled
   mts server rm <name>         # stop & remove a named tailscaled
   mts server logs [-f] <name>  # get/follow tailscaled logs

  mts <inst-name> [tailscale CLI args] # run Tailscale CLI against a named instance
    e.g.
      mts gmail1 up
      mts github2 status --json
	`)+"\n")
	os.Exit(1)
}

func main() {
	// Don't use flag.Parse here; we mostly just delegate through
	// to the Tailscale CLI.

	if len(os.Args) < 2 {
		usage()
	}
	firstArg, args := os.Args[1], os.Args[2:]
	if firstArg == "server" || firstArg == "s" {
		if err := runMTSServer(args); err != nil {
			log.Fatal(err)
		}
	} else {
		var c Client
		inst := firstArg
		c.RunCommand(inst, args)
	}
}

func runMTSServer(args []string) error {
	if len(args) == 0 {
		usage()
	}
	cmd, args := args[0], args[1:]
	if cmd == "run" {
		var s Server
		return s.Run()
	}

	// Commands other than "run" all use the HTTP client to
	// hit the mts server over its unix socket.
	var c Client

	switch cmd {
	default:
		usage("unknown mts server subcommand %q", cmd)
	case "list", "ls":
		list, err := c.List()
		if err != nil {
			return err
		}
		if len(args) == 0 {
			names := slices.Sorted(maps.Keys(list.Instances))
			for _, name := range names {
				running := list.Instances[name].Running
				fmt.Printf("%10s %s\n", bools.IfElse(running, "RUNNING", "stopped"), name)
			}
		} else {
			for _, name := range args {
				inst, ok := list.Instances[name]
				if !ok {
					return fmt.Errorf("no instance named %q", name)
				}
				je := json.NewEncoder(os.Stdout)
				je.SetIndent("", "  ")
				if err := je.Encode(inst); err != nil {
					return err
				}
			}
		}

	case "rm":
		if len(args) == 0 {
			return fmt.Errorf("missing instance name(s) to remove")
		}
		log.SetFlags(0)
		for _, name := range args {
			ok, err := c.Remove(name)
			if err != nil {
				return err
			}
			if ok {
				log.Printf("%s deleted.", name)
			} else {
				log.Printf("%s didn't exist.", name)
			}
		}
	case "stop":
		if len(args) == 0 {
			return fmt.Errorf("missing instance name(s) to stop")
		}
		log.SetFlags(0)
		for _, name := range args {
			ok, err := c.Stop(name)
			if err != nil {
				return err
			}
			if ok {
				log.Printf("%s stopped.", name)
			} else {
				log.Printf("%s didn't exist.", name)
			}
		}
	case "start", "restart":
		list, err := c.List()
		if err != nil {
			return err
		}
		shouldStop := cmd == "restart"
		for _, arg := range args {
			is, ok := list.Instances[arg]
			if !ok {
				return fmt.Errorf("no instance named %q", arg)
			}
			if is.Running {
				if shouldStop {
					if _, err := c.Stop(arg); err != nil {
						return fmt.Errorf("stopping %q: %w", arg, err)
					}
				} else {
					log.SetFlags(0)
					log.Printf("%s already running.", arg)
					continue
				}
			}
			// Creating an existing one starts it up.
			if err := c.Create(arg); err != nil {
				return fmt.Errorf("starting %q: %w", arg, err)
			}
		}
	case "add":
		if len(args) == 0 {
			return fmt.Errorf("missing instance name(s) to add")
		}
		for _, name := range args {
			if err := c.Create(name); err != nil {
				return fmt.Errorf("creating %q: %w", name, err)
			}
		}
	case "logs":
		fs := flag.NewFlagSet("logs", flag.ExitOnError)
		fs.Usage = func() { usage() }
		follow := fs.Bool("f", false, "follow logs")
		fs.Parse(args)
		log.Printf("Parsed; following=%v, args=%q", *follow, fs.Args())
		if fs.NArg() != 1 {
			usage()
		}
		cmd := bools.IfElse(*follow, "tail", "cat")
		args := []string{cmd}
		if *follow {
			args = append(args, "-f")
		}
		path, err := exec.LookPath(cmd)
		if err != nil {
			return fmt.Errorf("looking up %q: %w", cmd, err)
		}
		args = append(args, instLogsFile(fs.Arg(0)))
		log.Fatal(syscall.Exec(path, args, os.Environ()))
	}
	return nil
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

func getJSON[T any](res *http.Response, err error) (T, error) {
	var ret T
	if err != nil {
		return ret, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return ret, fmt.Errorf("unexpected status: %v: %s", res.Status, body)
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return ret, err
	}
	return ret, nil
}

func (c *Client) List() (listResponse, error) {
	return getJSON[listResponse](c.client().Get("http://mts/list"))
}

func (c *Client) Remove(name string) (found bool, err error) {
	return getJSON[bool](c.client().PostForm("http://mts/rm", url.Values{
		"name": []string{name},
	}))
}

func (c *Client) Stop(name string) (found bool, err error) {
	return getJSON[bool](c.client().PostForm("http://mts/stop", url.Values{
		"name": []string{name},
	}))
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
	sock := instSock(name)
	lc := &local.Client{
		Socket:        sock,
		UseSocketOnly: true,
	}
	probeCtx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if _, err := lc.StatusWithoutPeers(probeCtx); err != nil {
		log.Fatalf("instance %q not running? start with 'mts server start %q'; got error: %v", name, name, err)
	}
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

func (s *Server) Run() error {
	if err := os.MkdirAll(mtsRoot(), 0700); err != nil {
		return err
	}
	sock := mtsSock()
	os.Remove(sock)
	log.Printf("Multi-Tailscaled Server running; listening on %q ...", sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	return http.Serve(ln, s)
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

func (s *Server) Stop(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cmd, ok := s.cmds[name]; ok {
		if err := cmd.Process.Kill(); err != nil {
			log.Printf("error killing %q: %v", name, err)
		}
		delete(s.cmds, name)
	}
}

func (s *Server) RunInstance(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.cmds[name]; ok {
		return fmt.Errorf("instance %q already running", name)
	}

	if !validInstanceName(name) {
		return fmt.Errorf("invalid instance name %q", name)
	}
	dir := filepath.Join(mtsRoot(), name)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	env := os.Environ()
	env = append(env, "TS_DEBUG_LOG_RATE=all")
	if ef, err := os.Open(instEnvFile(name)); err == nil {
		defer ef.Close()
		sc := bufio.NewScanner(ef)
		for sc.Scan() {
			t := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(t, "#") || !strings.Contains(t, "=") {
				continue
			}
			env = append(env, t)
		}
	} else if os.IsNotExist(err) {
		// Write an example one.
		os.WriteFile(instEnvFile(name), fmt.Appendf(nil, "# Example mts env.txt file; uncomment/add stuff you want for %q\n\n#TS_DEBUG_MAP=1\n#TS_DEBUG_REGISTER=1\n#TS_NO_LOGS_NO_SUPPORT=1\n", name), 0600)
	}

	extraArgs := []string{"--verbose=1"}
	if af, err := os.Open(instArgsFile(name)); err == nil {
		extraArgs = nil // clear default args
		defer af.Close()
		sc := bufio.NewScanner(af)
		for sc.Scan() {
			t := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(t, "#") || t == "" {
				continue
			}
			extraArgs = append(extraArgs, t)
		}
	} else if os.IsNotExist(err) {
		// Write an example one.
		os.WriteFile(instArgsFile(name), fmt.Appendf(nil, "# Example mts args.txt file for instance %q.\n# One line per extra arg to tailscaled; no magic string quoting\n\n--verbose=1\n#--socks5-server=127.0.0.1:5000\n", name), 0600)
	}

	log.Printf("Running Tailscale daemon %q in %q", name, dir)

	args := []string{
		"--tun=userspace-networking",
		"--statedir=" + filepath.Join(dir),
		"--socket=" + filepath.Join(dir, "tailscaled.sock"),
	}
	args = append(args, extraArgs...)

	cmd := exec.Command(s.tailscaled(), args...)
	cmd.Dir = dir
	cmd.Env = env

	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout

	logs := instLogsFile(name)
	logFile, err := os.OpenFile(logs, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("opening logs file: %w", err)
	}

	go func() {
		bs := bufio.NewScanner(out)
		for bs.Scan() {
			// TODO(bradfitz): record in memory too, serve via HTTP
			line := strings.TrimSpace(bs.Text())
			fmt.Fprintf(logFile, "%s\n", line)
			fmt.Printf("tailscaled[%s]: %s\n", name, line)
		}
	}()

	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		err := cmd.Wait()
		logFile.Close()
		log.Printf("Tailscale daemon %q exited: %v", name, err)
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.cmds, name)
	}()

	mak.Set(&s.cmds, name, cmd)
	return nil
}

type listResponse struct {
	// Instances maps instance name to its details.
	Instances map[string]listResponseInstance `json:"instances"`
}

type listResponseInstance struct {
	Name    string `json:"name"`
	Dir     string `json:"dir"`
	Sock    string `json:"sock"`
	Running bool   `json:"running"`
	Env     string `json:"env"`
	Args    string `json:"args"`
	Logs    string `json:"logs"`
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(v)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/list" {
		var res listResponse
		for _, name := range s.InstanceNames() {
			mak.Set(&res.Instances, name, listResponseInstance{
				Name:    name,
				Dir:     instDir(name),
				Sock:    instSock(name),
				Running: s.InstanceRunning(name),
				Env:     instEnvFile(name),
				Args:    instArgsFile(name),
				Logs:    instLogsFile(name),
			})
		}
		writeJSON(w, res)
		return
	}
	if r.URL.Path == "/rm" || r.URL.Path == "/stop" {
		shouldRemove := r.URL.Path == "/rm"
		if r.Method != "POST" {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		target := r.FormValue("name")
		var ok bool
		for _, name := range s.InstanceNames() {
			if name != target {
				continue
			}
			ok = true
			s.Stop(name)
			if shouldRemove {
				if err := os.RemoveAll(instDir(name)); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
			break
		}
		writeJSON(w, ok)
		return
	}
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
	if r.URL.Path == "/" {
		fmt.Fprintf(w, "This is mts, the multi-tailscaled server.\n")
		return
	}
	http.NotFound(w, r)
}

func (s *Server) InstanceNames() []string {
	var ret []string
	des, err := os.ReadDir(mtsRoot())
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

func mtsRoot() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		panic(err)
	}
	return filepath.Join(dir, "multi-tailscale-dev")
}

func instDir(name string) string {
	return filepath.Join(mtsRoot(), name)
}

func instSock(name string) string {
	return filepath.Join(instDir(name), "tailscaled.sock")
}

func instEnvFile(name string) string {
	return filepath.Join(mtsRoot(), name, "env.txt")
}

func instArgsFile(name string) string {
	return filepath.Join(mtsRoot(), name, "args.txt")
}

func instLogsFile(name string) string {
	return filepath.Join(mtsRoot(), name, "logs.txt")
}

func mtsSock() string {
	return filepath.Join(mtsRoot(), "mts.sock")
}
