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
	Name: "debug",
	Exec: runDebug,
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("debug", flag.ExitOnError)
		fs.BoolVar(&debugArgs.goroutines, "daemon-goroutines", false, "If true, dump the tailscaled daemon's goroutines")
		fs.BoolVar(&debugArgs.ipn, "ipn", false, "If true, subscribe to IPN notifications")
		fs.BoolVar(&debugArgs.prefs, "prefs", false, "If true, dump active prefs")
		fs.BoolVar(&debugArgs.derpMap, "derp", false, "If true, dump DERP map")
		fs.BoolVar(&debugArgs.pretty, "pretty", false, "If true, pretty-print output (for --prefs)")
		fs.BoolVar(&debugArgs.netMap, "netmap", true, "whether to include netmap in --ipn mode")
		fs.BoolVar(&debugArgs.localCreds, "local-creds", false, "print how to connect to local tailscaled")
		fs.StringVar(&debugArgs.file, "file", "", "get, delete:NAME, or NAME")
		fs.StringVar(&debugArgs.cpuFile, "cpu-profile", "", "if non-empty, grab a CPU profile for --profile-sec seconds and write it to this file; - for stdout")
		fs.StringVar(&debugArgs.memFile, "mem-profile", "", "if non-empty, grab a memory profile and write it to this file; - for stdout")
		fs.IntVar(&debugArgs.cpuSec, "profile-seconds", 15, "number of seconds to run a CPU profile for, when --cpu-profile is non-empty")
		return fs
	})(),
}

var debugArgs struct {
	localCreds bool
	goroutines bool
	ipn        bool
	netMap     bool
	derpMap    bool
	file       string
	prefs      bool
	pretty     bool
	cpuSec     int
	cpuFile    string
	memFile    string
}

func writeProfile(dst string, v []byte) error {
	if dst == "-" {
		_, err := os.Stdout.Write(v)
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
	if debugArgs.localCreds {
		port, token, err := safesocket.LocalTCPPortAndToken()
		if err == nil {
			fmt.Printf("curl -u:%s http://localhost:%d/localapi/v0/status\n", token, port)
			return nil
		}
		if runtime.GOOS == "windows" {
			fmt.Printf("curl http://localhost:41112/localapi/v0/status\n")
			return nil
		}
		fmt.Printf("curl --unix-socket %s http://foo/localapi/v0/status\n", paths.DefaultTailscaledSocket())
		return nil
	}
	if out := debugArgs.cpuFile; out != "" {
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
	if debugArgs.prefs {
		prefs, err := tailscale.GetPrefs(ctx)
		if err != nil {
			return err
		}
		if debugArgs.pretty {
			fmt.Println(prefs.Pretty())
		} else {
			j, _ := json.MarshalIndent(prefs, "", "\t")
			fmt.Println(string(j))
		}
		return nil
	}
	if debugArgs.goroutines {
		goroutines, err := tailscale.Goroutines(ctx)
		if err != nil {
			return err
		}
		os.Stdout.Write(goroutines)
		return nil
	}
	if debugArgs.derpMap {
		dm, err := tailscale.CurrentDERPMap(ctx)
		if err != nil {
			return fmt.Errorf(
				"failed to get local derp map, instead `curl %s/derpmap/default`: %w", ipn.DefaultControlURL, err,
			)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "\t")
		enc.Encode(dm)
		return nil
	}
	if debugArgs.ipn {
		c, bc, ctx, cancel := connect(ctx)
		defer cancel()

		bc.SetNotifyCallback(func(n ipn.Notify) {
			if !debugArgs.netMap {
				n.NetMap = nil
			}
			j, _ := json.MarshalIndent(n, "", "\t")
			fmt.Printf("%s\n", j)
		})
		bc.RequestEngineStatus()
		pump(ctx, bc, c)
		return errors.New("exit")
	}
	if debugArgs.file != "" {
		if debugArgs.file == "get" {
			wfs, err := tailscale.WaitingFiles(ctx)
			if err != nil {
				log.Fatal(err)
			}
			e := json.NewEncoder(os.Stdout)
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
		io.Copy(os.Stdout, rc)
		return nil
	}
	return nil
}
