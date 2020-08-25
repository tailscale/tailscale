// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cli contains the cmd/tailscale CLI code in a package that can be included
// in other wrapper binaries such as the Mac and Windows clients.
package cli

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/peterbourgon/ff/v2/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/paths"
	"tailscale.com/safesocket"
)

// ActLikeCLI reports whether a GUI application should act like the
// CLI based on os.Args, GOOS, the context the process is running in
// (pty, parent PID), etc.
func ActLikeCLI() bool {
	if len(os.Args) < 2 {
		return false
	}
	switch os.Args[1] {
	case "up", "status", "netcheck", "ping", "version",
		"debug",
		"-V", "--version", "-h", "--help":
		return true
	}
	return false
}

// Run runs the CLI. The args do not include the binary name.
func Run(args []string) error {
	if len(args) == 1 && (args[0] == "-V" || args[0] == "--version") {
		args = []string{"version"}
	}

	rootfs := flag.NewFlagSet("tailscale", flag.ExitOnError)
	rootfs.StringVar(&rootArgs.socket, "socket", paths.DefaultTailscaledSocket(), "path to tailscaled's unix socket")

	rootCmd := &ffcli.Command{
		Name:       "tailscale",
		ShortUsage: "tailscale subcommand [flags]",
		ShortHelp:  "The easiest, most secure way to use WireGuard.",
		LongHelp: strings.TrimSpace(`
This CLI is still under active development. Commands and flags will
change in the future.
`),
		Subcommands: []*ffcli.Command{
			upCmd,
			netcheckCmd,
			statusCmd,
			pingCmd,
			versionCmd,
		},
		FlagSet: rootfs,
		Exec:    func(context.Context, []string) error { return flag.ErrHelp },
	}

	// Don't advertise the debug command, but it exists.
	if strSliceContains(args, "debug") {
		rootCmd.Subcommands = append(rootCmd.Subcommands, debugCmd)
	}

	if err := rootCmd.Parse(args); err != nil {
		return err
	}

	err := rootCmd.Run(context.Background())
	if err == flag.ErrHelp {
		return nil
	}
	return err
}

func fatalf(format string, a ...interface{}) {
	log.SetFlags(0)
	log.Fatalf(format, a...)
}

var rootArgs struct {
	socket string
}

func connect(ctx context.Context) (net.Conn, *ipn.BackendClient, context.Context, context.CancelFunc) {
	c, err := safesocket.Connect(rootArgs.socket, 41112)
	if err != nil {
		if runtime.GOOS != "windows" && rootArgs.socket == "" {
			fatalf("--socket cannot be empty")
		}
		fatalf("Failed to connect to connect to tailscaled. (safesocket.Connect: %v)\n", err)
	}
	clientToServer := func(b []byte) {
		ipn.WriteMsg(c, b)
	}

	ctx, cancel := context.WithCancel(ctx)

	go func() {
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
		<-interrupt
		c.Close()
		cancel()
	}()

	bc := ipn.NewBackendClient(log.Printf, clientToServer)
	return c, bc, ctx, cancel
}

// pump receives backend messages on conn and pushes them into bc.
func pump(ctx context.Context, bc *ipn.BackendClient, conn net.Conn) {
	defer conn.Close()
	for ctx.Err() == nil {
		msg, err := ipn.ReadMsg(conn)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("ReadMsg: %v\n", err)
			break
		}
		bc.GotNotifyMsg(msg)
	}
}

func strSliceContains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
