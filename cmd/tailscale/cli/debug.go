// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"inet.af/netaddr"
	"tailscale.com/client/tailscale"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/net/tsaddr"
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
			FlagSet: (func() *flag.FlagSet {
				fs := newFlagSet("metrics")
				fs.BoolVar(&metricsArgs.watch, "watch", false, "print JSON dump of delta values")
				return fs
			})(),
		},
		{
			Name:      "env",
			Exec:      runEnv,
			ShortHelp: "print cmd/tailscale environment",
		},
		{
			Name:      "hostinfo",
			Exec:      runHostinfo,
			ShortHelp: "print hostinfo",
		},
		{
			Name:      "local-creds",
			Exec:      runLocalCreds,
			ShortHelp: "print how to access Tailscale local API",
		},
		{
			Name:      "restun",
			Exec:      localAPIAction("restun"),
			ShortHelp: "force a magicsock restun",
		},
		{
			Name:      "rebind",
			Exec:      localAPIAction("rebind"),
			ShortHelp: "force a magicsock rebind",
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
		{
			Name:      "via",
			Exec:      runVia,
			ShortHelp: "convert between site-specific IPv4 CIDRs and IPv6 'via' routes",
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

func localAPIAction(action string) func(context.Context, []string) error {
	return func(ctx context.Context, args []string) error {
		if len(args) > 0 {
			return errors.New("unexpected arguments")
		}
		return tailscale.DebugAction(ctx, action)
	}
}

func runEnv(ctx context.Context, args []string) error {
	for _, e := range os.Environ() {
		outln(e)
	}
	return nil
}

func runHostinfo(ctx context.Context, args []string) error {
	hi := hostinfo.New()
	j, _ := json.MarshalIndent(hi, "", "  ")
	os.Stdout.Write(j)
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

var metricsArgs struct {
	watch bool
}

func runDaemonMetrics(ctx context.Context, args []string) error {
	last := map[string]int64{}
	for {
		out, err := tailscale.DaemonMetrics(ctx)
		if err != nil {
			return err
		}
		if !metricsArgs.watch {
			Stdout.Write(out)
			return nil
		}
		bs := bufio.NewScanner(bytes.NewReader(out))
		type change struct {
			name     string
			from, to int64
		}
		var changes []change
		var maxNameLen int
		for bs.Scan() {
			line := bytes.TrimSpace(bs.Bytes())
			if len(line) == 0 || line[0] == '#' {
				continue
			}
			f := strings.Fields(string(line))
			if len(f) != 2 {
				continue
			}
			name := f[0]
			n, _ := strconv.ParseInt(f[1], 10, 64)
			prev, ok := last[name]
			if ok && prev == n {
				continue
			}
			last[name] = n
			if !ok {
				continue
			}
			changes = append(changes, change{name, prev, n})
			if len(name) > maxNameLen {
				maxNameLen = len(name)
			}
		}
		if len(changes) > 0 {
			format := fmt.Sprintf("%%-%ds %%+5d => %%v\n", maxNameLen)
			for _, c := range changes {
				fmt.Fprintf(Stdout, format, c.name, c.to-c.from, c.to)
			}
			io.WriteString(Stdout, "\n")
		}
		time.Sleep(time.Second)
	}
}

func runVia(ctx context.Context, args []string) error {
	switch len(args) {
	default:
		return errors.New("expect either <site-id> <v4-cidr> or <v6-route>")
	case 1:
		ipp, err := netaddr.ParseIPPrefix(args[0])
		if err != nil {
			return err
		}
		if !ipp.IP().Is6() {
			return errors.New("with one argument, expect an IPv6 CIDR")
		}
		if !tsaddr.TailscaleViaRange().Contains(ipp.IP()) {
			return errors.New("not a via route")
		}
		if ipp.Bits() < 96 {
			return errors.New("short length, want /96 or more")
		}
		v4 := tsaddr.UnmapVia(ipp.IP())
		a := ipp.IP().As16()
		siteID := binary.BigEndian.Uint32(a[8:12])
		fmt.Printf("site %v (0x%x), %v\n", siteID, siteID, netaddr.IPPrefixFrom(v4, ipp.Bits()-96))
	case 2:
		siteID, err := strconv.ParseUint(args[0], 0, 32)
		if err != nil {
			return fmt.Errorf("invalid site-id %q; must be decimal or hex with 0x prefix", args[0])
		}
		if siteID > 0xff {
			return fmt.Errorf("site-id values over 255 are currently reserved")
		}
		ipp, err := netaddr.ParseIPPrefix(args[1])
		if err != nil {
			return err
		}
		via, err := tsaddr.MapVia(uint32(siteID), ipp)
		if err != nil {
			return err
		}
		fmt.Println(via)
	}
	return nil
}
