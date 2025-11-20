// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !ts_omit_capture

package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/feature/capture/dissector"
)

func init() {
	debugCaptureCmd = mkDebugCaptureCmd
}

func mkDebugCaptureCmd() *ffcli.Command {
	return &ffcli.Command{
		Name:       "capture",
		ShortUsage: "tailscale debug capture",
		Exec:       runCapture,
		ShortHelp:  "Stream pcaps for debugging",
		FlagSet: (func() *flag.FlagSet {
			fs := newFlagSet("capture")
			fs.StringVar(&captureArgs.outFile, "o", "", "path to stream the pcap (or - for stdout), leave empty to start wireshark")
			return fs
		})(),
	}
}

var captureArgs struct {
	outFile string
}

func runCapture(ctx context.Context, args []string) error {
	stream, err := localClient.StreamDebugCapture(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	switch captureArgs.outFile {
	case "-":
		fmt.Fprintln(Stderr, "Press Ctrl-C to stop the capture.")
		_, err = io.Copy(os.Stdout, stream)
		return err
	case "":
		lua, err := os.CreateTemp("", "ts-dissector")
		if err != nil {
			return err
		}
		defer os.Remove(lua.Name())
		io.WriteString(lua, dissector.Lua)
		if err := lua.Close(); err != nil {
			return err
		}

		wireshark := exec.CommandContext(ctx, "wireshark", "-X", "lua_script:"+lua.Name(), "-k", "-i", "-")
		wireshark.Stdin = stream
		wireshark.Stdout = os.Stdout
		wireshark.Stderr = os.Stderr
		return wireshark.Run()
	}

	f, err := os.OpenFile(captureArgs.outFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	fmt.Fprintln(Stderr, "Press Ctrl-C to stop the capture.")
	_, err = io.Copy(f, stream)
	return err
}
