// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/peterbourgon/ff/v2/ffcli"
	"golang.org/x/time/rate"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
)

var pushCmd = &ffcli.Command{
	Name:       "push",
	ShortUsage: "push [--flags] <hostname-or-IP> <file>",
	ShortHelp:  "Push a file to a host",
	Exec:       runPush,
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("push", flag.ExitOnError)
		fs.StringVar(&pushArgs.name, "name", "", "alternate filename to use, especially useful when <file> is \"-\" (stdin)")
		fs.BoolVar(&pushArgs.verbose, "verbose", false, "verbose output")
		fs.BoolVar(&pushArgs.targets, "targets", false, "list possible push targets")
		return fs
	})(),
}

var pushArgs struct {
	name    string
	verbose bool
	targets bool
}

func runPush(ctx context.Context, args []string) error {
	if pushArgs.targets {
		return runPushTargets(ctx, args)
	}
	if len(args) != 2 || args[0] == "" {
		return errors.New("usage: push <hostname-or-IP> <file>\n       push --targets")
	}
	var ip string

	hostOrIP, fileArg := args[0], args[1]
	ip, err := tailscaleIPFromArg(ctx, hostOrIP)
	if err != nil {
		return err
	}

	peerAPIPort, err := discoverPeerAPIPort(ctx, ip)
	if err != nil {
		return err
	}

	var fileContents io.Reader
	var name = pushArgs.name
	var contentLength int64 = -1
	if fileArg == "-" {
		fileContents = os.Stdin
		if name == "" {
			name, fileContents, err = pickStdinFilename()
			if err != nil {
				return err
			}
		}
	} else {
		f, err := os.Open(fileArg)
		if err != nil {
			return err
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return errors.New("directories not supported")
		}
		contentLength = fi.Size()
		fileContents = io.LimitReader(f, contentLength)
		if name == "" {
			name = fileArg
		}

		if slow, _ := strconv.ParseBool(os.Getenv("TS_DEBUG_SLOW_PUSH")); slow {
			fileContents = &slowReader{r: fileContents}
		}
	}

	dstURL := "http://" + net.JoinHostPort(ip, fmt.Sprint(peerAPIPort)) + "/v0/put/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, "PUT", dstURL, fileContents)
	if err != nil {
		return err
	}
	req.ContentLength = contentLength
	if pushArgs.verbose {
		log.Printf("sending to %v ...", dstURL)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == 200 {
		return nil
	}
	io.Copy(os.Stdout, res.Body)
	return errors.New(res.Status)
}

func discoverPeerAPIPort(ctx context.Context, ip string) (port uint16, err error) {
	c, bc, ctx, cancel := connect(ctx)
	defer cancel()

	prc := make(chan *ipnstate.PingResult, 2)
	bc.SetNotifyCallback(func(n ipn.Notify) {
		if n.ErrMessage != nil {
			log.Fatal(*n.ErrMessage)
		}
		if pr := n.PingResult; pr != nil && pr.IP == ip {
			prc <- pr
		}
	})
	go pump(ctx, bc, c)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	discoPings := 0
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()

	sendPings := func() {
		bc.Ping(ip, false)
		bc.Ping(ip, true)
	}
	sendPings()
	for {
		select {
		case <-ticker.C:
			sendPings()
		case <-timer.C:
			return 0, fmt.Errorf("timeout contacting %v; it offline?", ip)
		case pr := <-prc:
			if p := pr.PeerAPIPort; p != 0 {
				return p, nil
			}
			discoPings++
			if discoPings == 3 {
				return 0, fmt.Errorf("%v is online, but seems to be running an old Tailscale version", ip)
			}
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

const maxSniff = 4 << 20

func ext(b []byte) string {
	if len(b) < maxSniff && utf8.Valid(b) {
		return ".txt"
	}
	if exts, _ := mime.ExtensionsByType(http.DetectContentType(b)); len(exts) > 0 {
		return exts[0]
	}
	return ""
}

// pickStdinFilename reads a bit of stdin to return a good filename
// for its contents. The returned Reader is the concatenation of the
// read and unread bits.
func pickStdinFilename() (name string, r io.Reader, err error) {
	sniff, err := io.ReadAll(io.LimitReader(os.Stdin, maxSniff))
	if err != nil {
		return "", nil, err
	}
	return "stdin" + ext(sniff), io.MultiReader(bytes.NewReader(sniff), os.Stdin), nil
}

type slowReader struct {
	r  io.Reader
	rl *rate.Limiter
}

func (r *slowReader) Read(p []byte) (n int, err error) {
	const burst = 4 << 10
	plen := len(p)
	if plen > burst {
		plen = burst
	}
	if r.rl == nil {
		r.rl = rate.NewLimiter(rate.Limit(1<<10), burst)
	}
	n, err = r.r.Read(p[:plen])
	r.rl.WaitN(context.Background(), n)
	return
}

func runPushTargets(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("invalid arguments with --targets")
	}
	fts, err := tailscale.FileTargets(ctx)
	if err != nil {
		return err
	}
	for _, ft := range fts {
		n := ft.Node
		var ago string
		if n.LastSeen == nil {
			ago = "\tnode never seen"
		} else {
			if d := time.Since(*n.LastSeen); d > 20*time.Minute {
				ago = fmt.Sprintf("\tlast seen %v ago", d.Round(time.Minute))
			}
		}
		fmt.Printf("%s\t%s%s\n", n.Addresses[0].IP, n.ComputedName, ago)
	}
	return nil
}
