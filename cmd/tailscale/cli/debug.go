// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/paths"
	"tailscale.com/safesocket"
)

var debugCmd = &ffcli.Command{
	Name:     "debug",
	Exec:     runDebug,
	LongHelp: `"tailscale debug" contains misc debug facilities; it is not a stable interface.`,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("debug")
		fs.StringVar(&debugArgs.file, "file", "", "get, delete:NAME, or NAME")
		fs.StringVar(&debugArgs.cpuFile, "cpu-profile", "", "if non-empty, grab a CPU profile for --profile-sec seconds and write it to this file; - for stdout")
		fs.StringVar(&debugArgs.memFile, "mem-profile", "", "if non-empty, grab a memory profile and write it to this file; - for stdout")
		fs.IntVar(&debugArgs.cpuSec, "profile-seconds", 15, "number of seconds to run a CPU profile for, when --cpu-profile is non-empty")
		return fs
	})(),
	Subcommands: []*ffcli.Command{
		{
			Name:      "derp-map",
			Exec:      runDERPMap,
			ShortHelp: "print DERP map",
		},
		{
			Name:      "daemon-goroutines",
			Exec:      runDaemonGoroutines,
			ShortHelp: "print tailscaled's goroutines",
		},
		{
			Name:      "metrics",
			Exec:      runDaemonMetrics,
			ShortHelp: "print tailscaled's metrics",
		},
		{
			Name:      "env",
			Exec:      runEnv,
			ShortHelp: "print cmd/tailscale environment",
		},
		{
			Name:      "local-creds",
			Exec:      runLocalCreds,
			ShortHelp: "print how to access Tailscale local API",
		},
		{
			Name:      "prefs",
			Exec:      runPrefs,
			ShortHelp: "print prefs",
			FlagSet: (func() *flag.FlagSet {
				fs := newFlagSet("prefs")
				fs.BoolVar(&prefsArgs.pretty, "pretty", false, "If true, pretty-print output")
				return fs
			})(),
		},
		{
			Name:      "watch-ipn",
			Exec:      runWatchIPN,
			ShortHelp: "subscribe to IPN message bus",
			FlagSet: (func() *flag.FlagSet {
				fs := newFlagSet("watch-ipn")
				fs.BoolVar(&watchIPNArgs.netmap, "netmap", true, "include netmap in messages")
				return fs
			})(),
		},
	},
}

var debugArgs struct {
	file    string
	cpuSec  int
	cpuFile string
	memFile string
}

func writeProfile(dst string, v []byte) error {
	if dst == "-" {
		_, err := Stdout.Write(v)
		return err
	}
	return os.WriteFile(dst, v, 0600)
}

func outName(dst string) string {
	if dst == "-" {
		return "stdout"
	}
	if runtime.GOOS == "darwin" {
		return fmt.Sprintf("%s (warning: sandboxed macOS binaries write to Library/Containers; use - to write to stdout and redirect to file instead)", dst)
	}
	return dst
}

func runDebug(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unknown arguments")
	}
	var usedFlag bool
	if out := debugArgs.cpuFile; out != "" {
		usedFlag = true // TODO(bradfitz): add "profile" subcommand
		log.Printf("Capturing CPU profile for %v seconds ...", debugArgs.cpuSec)
		if v, err := tailscale.Profile(ctx, "profile", debugArgs.cpuSec); err != nil {
			return err
		} else {
			if err := writeProfile(out, v); err != nil {
				return err
			}
			log.Printf("CPU profile written to %s", outName(out))
		}
	}
	if out := debugArgs.memFile; out != "" {
		usedFlag = true // TODO(bradfitz): add "profile" subcommand
		log.Printf("Capturing memory profile ...")
		if v, err := tailscale.Profile(ctx, "heap", 0); err != nil {
			return err
		} else {
			if err := writeProfile(out, v); err != nil {
				return err
			}
			log.Printf("Memory profile written to %s", outName(out))
		}
	}
	if debugArgs.file != "" {
		usedFlag = true // TODO(bradfitz): add "file" subcommand
		if debugArgs.file == "get" {
			wfs, err := tailscale.WaitingFiles(ctx)
			if err != nil {
				fatalf("%v\n", err)
			}
			e := json.NewEncoder(Stdout)
			e.SetIndent("", "\t")
			e.Encode(wfs)
			return nil
		}
		delete := strings.HasPrefix(debugArgs.file, "delete:")
		if delete {
			return tailscale.DeleteWaitingFile(ctx, strings.TrimPrefix(debugArgs.file, "delete:"))
		}
		rc, size, err := tailscale.GetWaitingFile(ctx, debugArgs.file)
		if err != nil {
			return err
		}
		log.Printf("Size: %v\n", size)
		io.Copy(Stdout, rc)
		return nil
	}
	if usedFlag {
		// TODO(bradfitz): delete this path when all debug flags are migrated
		// to subcommands.
		return nil
	}
	return errors.New("see 'tailscale debug --help")
}

func runLocalCreds(ctx context.Context, args []string) error {
	port, token, err := safesocket.LocalTCPPortAndToken()
	if err == nil {
		printf("curl -u:%s http://localhost:%d/localapi/v0/status\n", token, port)
		return nil
	}
	if runtime.GOOS == "windows" {
		printf("curl http://localhost:%v/localapi/v0/status\n", safesocket.WindowsLocalPort)
		return nil
	}
	printf("curl --unix-socket %s http://foo/localapi/v0/status\n", paths.DefaultTailscaledSocket())
	return nil
}

var prefsArgs struct {
	pretty bool
}

func runPrefs(ctx context.Context, args []string) error {
	prefs, err := tailscale.GetPrefs(ctx)
	if err != nil {
		return err
	}
	if prefsArgs.pretty {
		outln(prefs.Pretty())
	} else {
		j, _ := json.MarshalIndent(prefs, "", "\t")
		outln(string(j))
	}
	return nil
}

var watchIPNArgs struct {
	netmap bool
}

func runWatchIPN(ctx context.Context, args []string) error {
	c, bc, ctx, cancel := connect(ctx)
	defer cancel()

	bc.SetNotifyCallback(func(n ipn.Notify) {
		if !watchIPNArgs.netmap {
			n.NetMap = nil
		}
		j, _ := json.MarshalIndent(n, "", "\t")
		printf("%s\n", j)
	})
	bc.RequestEngineStatus()
	pump(ctx, bc, c)
	return errors.New("exit")
}

func runDERPMap(ctx context.Context, args []string) error {
	dm, err := tailscale.CurrentDERPMap(ctx)
	if err != nil {
		return fmt.Errorf(
			"failed to get local derp map, instead `curl %s/derpmap/default`: %w", ipn.DefaultControlURL, err,
		)
	}
	enc := json.NewEncoder(Stdout)
	enc.SetIndent("", "\t")
	enc.Encode(dm)
	return nil
}

func runEnv(ctx context.Context, args []string) error {
	for _, e := range os.Environ() {
		outln(e)
	}
	return nil
}

func runDaemonGoroutines(ctx context.Context, args []string) error {
	goroutines, err := tailscale.Goroutines(ctx)
	if err != nil {
		return err
	}
	Stdout.Write(goroutines)
	return nil
}

func runDaemonMetrics(ctx context.Context, args []string) error {
	out, err := tailscale.DaemonMetrics(ctx)
	if err != nil {
		return err
	}
	Stdout.Write(out)
	return nil
}
