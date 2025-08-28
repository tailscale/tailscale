// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_taildrop

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
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/mattn/go-isatty"
	"github.com/peterbourgon/ff/v3/ffcli"
	"golang.org/x/time/rate"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/cmd/tailscale/cli/ffcomplete"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	tsrate "tailscale.com/tstime/rate"
	"tailscale.com/util/quarantine"
	"tailscale.com/util/truncate"
	"tailscale.com/version"
)

func init() {
	fileCmd = getFileCmd
}

func getFileCmd() *ffcli.Command {
	return &ffcli.Command{
		Name:       "file",
		ShortUsage: "tailscale file <cp|get> ...",
		ShortHelp:  "Send or receive files",
		Subcommands: []*ffcli.Command{
			fileCpCmd,
			fileGetCmd,
		},
	}
}

type countingReader struct {
	io.Reader
	n atomic.Int64
}

func (c *countingReader) Read(buf []byte) (int, error) {
	n, err := c.Reader.Read(buf)
	c.n.Add(int64(n))
	return n, err
}

var fileCpCmd = &ffcli.Command{
	Name:       "cp",
	ShortUsage: "tailscale file cp <files...> <target>:",
	ShortHelp:  "Copy file(s) to a host",
	Exec:       runCp,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("cp")
		fs.StringVar(&cpArgs.name, "name", "", "alternate filename to use, especially useful when <file> is \"-\" (stdin)")
		fs.BoolVar(&cpArgs.verbose, "verbose", false, "verbose output")
		fs.BoolVar(&cpArgs.targets, "targets", false, "list possible file cp targets")
		return fs
	})(),
}

var cpArgs struct {
	name    string
	verbose bool
	targets bool
}

func runCp(ctx context.Context, args []string) error {
	if cpArgs.targets {
		return runCpTargets(ctx, args)
	}
	if len(args) < 2 {
		return errors.New("usage: tailscale file cp <files...> <target>:")
	}
	files, target := args[:len(args)-1], args[len(args)-1]
	target, ok := strings.CutSuffix(target, ":")
	if !ok {
		return fmt.Errorf("final argument to 'tailscale file cp' must end in colon")
	}
	hadBrackets := false
	if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
		hadBrackets = true
		target = strings.TrimSuffix(strings.TrimPrefix(target, "["), "]")
	}
	if ip, err := netip.ParseAddr(target); err == nil && ip.Is6() && !hadBrackets {
		return fmt.Errorf("an IPv6 literal must be written as [%s]", ip)
	} else if hadBrackets && (err != nil || !ip.Is6()) {
		return errors.New("unexpected brackets around target")
	}
	ip, _, err := tailscaleIPFromArg(ctx, target)
	if err != nil {
		return err
	}

	stableID, isOffline, err := getTargetStableID(ctx, ip)
	if err != nil {
		return fmt.Errorf("can't send to %s: %v", target, err)
	}
	if isOffline {
		fmt.Fprintf(Stderr, "# warning: %s is offline\n", target)
	}

	if len(files) > 1 {
		if cpArgs.name != "" {
			return errors.New("can't use --name= with multiple files")
		}
		for _, fileArg := range files {
			if fileArg == "-" {
				return errors.New("can't use '-' as STDIN file when providing filename arguments")
			}
		}
	}

	for _, fileArg := range files {
		var fileContents *countingReader
		var name = cpArgs.name
		var contentLength int64 = -1
		if fileArg == "-" {
			fileContents = &countingReader{Reader: os.Stdin}
			if name == "" {
				name, fileContents, err = pickStdinFilename()
				if err != nil {
					return err
				}
			}
		} else {
			f, err := os.Open(fileArg)
			if err != nil {
				if version.IsSandboxedMacOS() {
					return errors.New("the GUI version of Tailscale on macOS runs in a macOS sandbox that can't read files")
				}
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
			fileContents = &countingReader{Reader: io.LimitReader(f, contentLength)}
			if name == "" {
				name = filepath.Base(fileArg)
			}

			if envknob.Bool("TS_DEBUG_SLOW_PUSH") {
				fileContents = &countingReader{Reader: &slowReader{r: fileContents}}
			}
		}

		if cpArgs.verbose {
			log.Printf("sending %q to %v/%v/%v ...", name, target, ip, stableID)
		}

		var group sync.WaitGroup
		ctxProgress, cancelProgress := context.WithCancel(ctx)
		defer cancelProgress()
		if isatty.IsTerminal(os.Stderr.Fd()) {
			group.Go(func() { progressPrinter(ctxProgress, name, fileContents.n.Load, contentLength) })
		}

		err := localClient.PushFile(ctx, stableID, contentLength, name, fileContents)
		cancelProgress()
		group.Wait() // wait for progress printer to stop before reporting the error
		if err != nil {
			return err
		}
		if cpArgs.verbose {
			log.Printf("sent %q", name)
		}
	}
	return nil
}

func progressPrinter(ctx context.Context, name string, contentCount func() int64, contentLength int64) {
	var rateValueFast, rateValueSlow tsrate.Value
	rateValueFast.HalfLife = 1 * time.Second  // fast response for rate measurement
	rateValueSlow.HalfLife = 10 * time.Second // slow response for ETA measurement
	var prevContentCount int64
	print := func() {
		currContentCount := contentCount()
		rateValueFast.Add(float64(currContentCount - prevContentCount))
		rateValueSlow.Add(float64(currContentCount - prevContentCount))
		prevContentCount = currContentCount

		const vtRestartLine = "\r\x1b[K"
		fmt.Fprintf(os.Stderr, "%s%s    %s    %s",
			vtRestartLine,
			rightPad(name, 36),
			leftPad(formatIEC(float64(currContentCount), "B"), len("1023.00MiB")),
			leftPad(formatIEC(rateValueFast.Rate(), "B/s"), len("1023.00MiB/s")))
		if contentLength >= 0 {
			currContentCount = min(currContentCount, contentLength) // cap at 100%
			ratioRemain := float64(currContentCount) / float64(contentLength)
			bytesRemain := float64(contentLength - currContentCount)
			secsRemain := bytesRemain / rateValueSlow.Rate()
			secs := int(min(max(0, secsRemain), 99*60*60+59+60+59))
			fmt.Fprintf(os.Stderr, "    %s    %s",
				leftPad(fmt.Sprintf("%0.2f%%", 100.0*ratioRemain), len("100.00%")),
				fmt.Sprintf("ETA %02d:%02d:%02d", secs/60/60, (secs/60)%60, secs%60))
		}
	}

	tc := time.NewTicker(250 * time.Millisecond)
	defer tc.Stop()
	print()
	for {
		select {
		case <-ctx.Done():
			print()
			fmt.Fprintln(os.Stderr)
			return
		case <-tc.C:
			print()
		}
	}
}

func leftPad(s string, n int) string {
	s = truncateString(s, n)
	return strings.Repeat(" ", max(n-len(s), 0)) + s
}

func rightPad(s string, n int) string {
	s = truncateString(s, n)
	return s + strings.Repeat(" ", max(n-len(s), 0))
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return truncate.String(s, max(n-1, 0)) + "…"
}

func formatIEC(n float64, unit string) string {
	switch {
	case n < 1<<10:
		return fmt.Sprintf("%0.2f%s", n/(1<<0), unit)
	case n < 1<<20:
		return fmt.Sprintf("%0.2fKi%s", n/(1<<10), unit)
	case n < 1<<30:
		return fmt.Sprintf("%0.2fMi%s", n/(1<<20), unit)
	case n < 1<<40:
		return fmt.Sprintf("%0.2fGi%s", n/(1<<30), unit)
	default:
		return fmt.Sprintf("%0.2fTi%s", n/(1<<40), unit)
	}
}

func getTargetStableID(ctx context.Context, ipStr string) (id tailcfg.StableNodeID, isOffline bool, err error) {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return "", false, err
	}

	st, err := localClient.Status(ctx)
	if err != nil {
		// This likely means tailscaled is unreachable or returned an error on /localapi/v0/status.
		return "", false, fmt.Errorf("failed to get local status: %w", err)
	}
	if st == nil {
		// Handle the case if the daemon returns nil with no error.
		return "", false, errors.New("no status available")
	}
	if st.Self == nil {
		// We have a status structure, but it doesn’t include Self info. Probably not connected.
		return "", false, errors.New("local node is not configured or missing Self information")
	}

	// Find the PeerStatus that corresponds to ip.
	var foundPeer *ipnstate.PeerStatus
peerLoop:
	for _, ps := range st.Peer {
		for _, pip := range ps.TailscaleIPs {
			if pip == ip {
				foundPeer = ps
				break peerLoop
			}
		}
	}

	// If we didn’t find a matching peer at all:
	if foundPeer == nil {
		if !tsaddr.IsTailscaleIP(ip) {
			return "", false, fmt.Errorf("unknown target; %v is not a Tailscale IP address", ip)
		}
		return "", false, errors.New("unknown target; not in your Tailnet")
	}

	// We found a peer. Decide whether we can send files to it:
	isOffline = !foundPeer.Online

	switch foundPeer.TaildropTarget {
	case ipnstate.TaildropTargetAvailable:
		return foundPeer.ID, isOffline, nil

	case ipnstate.TaildropTargetNoNetmapAvailable:
		return "", isOffline, errors.New("cannot send files: no netmap available on this node")

	case ipnstate.TaildropTargetIpnStateNotRunning:
		return "", isOffline, errors.New("cannot send files: local Tailscale is not connected to the tailnet")

	case ipnstate.TaildropTargetMissingCap:
		return "", isOffline, errors.New("cannot send files: missing required Taildrop capability")

	case ipnstate.TaildropTargetOffline:
		return "", isOffline, errors.New("cannot send files: peer is offline")

	case ipnstate.TaildropTargetNoPeerInfo:
		return "", isOffline, errors.New("cannot send files: invalid or unrecognized peer")

	case ipnstate.TaildropTargetUnsupportedOS:
		return "", isOffline, errors.New("cannot send files: target's OS does not support Taildrop")

	case ipnstate.TaildropTargetNoPeerAPI:
		return "", isOffline, errors.New("cannot send files: target is not advertising a file sharing API")

	case ipnstate.TaildropTargetOwnedByOtherUser:
		return "", isOffline, errors.New("cannot send files: peer is owned by a different user")

	case ipnstate.TaildropTargetUnknown:
		fallthrough
	default:
		return "", isOffline, fmt.Errorf("cannot send files: unknown or indeterminate reason")
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
func pickStdinFilename() (name string, r *countingReader, err error) {
	sniff, err := io.ReadAll(io.LimitReader(os.Stdin, maxSniff))
	if err != nil {
		return "", nil, err
	}
	return "stdin" + ext(sniff), &countingReader{Reader: io.MultiReader(bytes.NewReader(sniff), os.Stdin)}, nil
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

func runCpTargets(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("invalid arguments with --targets")
	}
	fts, err := localClient.FileTargets(ctx)
	if err != nil {
		return err
	}
	for _, ft := range fts {
		n := ft.Node
		var detail string
		if n.Online != nil {
			if !*n.Online {
				detail = "offline"
			}
		} else {
			detail = "unknown-status"
		}
		if detail != "" && n.LastSeen != nil {
			d := time.Since(*n.LastSeen)
			detail += fmt.Sprintf("; last seen %v ago", d.Round(time.Minute))
		}
		if detail != "" {
			detail = "\t" + detail
		}
		printf("%s\t%s%s\n", n.Addresses[0].Addr(), n.ComputedName, detail)
	}
	return nil
}

// onConflict is a flag.Value for the --conflict flag's three string options.
type onConflict string

const (
	skipOnExist         onConflict = "skip"
	overwriteExisting   onConflict = "overwrite" //  Overwrite any existing file at the target location
	createNumberedFiles onConflict = "rename"    //  Create an alternately named file in the style of Chrome Downloads
)

func (v *onConflict) String() string { return string(*v) }

func (v *onConflict) Set(s string) error {
	if s == "" {
		*v = skipOnExist
		return nil
	}
	*v = onConflict(strings.ToLower(s))
	if *v != skipOnExist && *v != overwriteExisting && *v != createNumberedFiles {
		return fmt.Errorf("%q is not one of (skip|overwrite|rename)", s)
	}
	return nil
}

var fileGetCmd = &ffcli.Command{
	Name:       "get",
	ShortUsage: "tailscale file get [--wait] [--verbose] [--conflict=(skip|overwrite|rename)] <target-directory>",
	ShortHelp:  "Move files out of the Tailscale file inbox",
	Exec:       runFileGet,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("get")
		fs.BoolVar(&getArgs.wait, "wait", false, "wait for a file to arrive if inbox is empty")
		fs.BoolVar(&getArgs.loop, "loop", false, "run get in a loop, receiving files as they come in")
		fs.BoolVar(&getArgs.verbose, "verbose", false, "verbose output")
		fs.Var(&getArgs.conflict, "conflict", "`behavior`"+` when a conflicting (same-named) file already exists in the target directory.
	skip:       skip conflicting files: leave them in the taildrop inbox and print an error. get any non-conflicting files
	overwrite:  overwrite existing file
	rename:     write to a new number-suffixed filename`)
		ffcomplete.Flag(fs, "conflict", ffcomplete.Fixed("skip", "overwrite", "rename"))
		return fs
	})(),
}

var getArgs = struct {
	wait     bool
	loop     bool
	verbose  bool
	conflict onConflict
}{conflict: skipOnExist}

func numberedFileName(dir, name string, i int) string {
	ext := path.Ext(name)
	return filepath.Join(dir, fmt.Sprintf("%s (%d)%s",
		strings.TrimSuffix(name, ext),
		i, ext))
}

func openFileOrSubstitute(dir, base string, action onConflict) (*os.File, error) {
	targetFile := filepath.Join(dir, base)
	f, err := os.OpenFile(targetFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644)
	if err == nil {
		return f, nil
	}
	// Something went wrong trying to open targetFile as a new file for writing.
	switch action {
	default:
		// This should not happen.
		return nil, fmt.Errorf("file issue. how to resolve this conflict? no one knows.")
	case skipOnExist:
		if _, statErr := os.Stat(targetFile); statErr == nil {
			// we can stat a file at that path: so it already exists.
			return nil, fmt.Errorf("refusing to overwrite file: %w", err)
		}
		return nil, fmt.Errorf("failed to write; %w", err)
	case overwriteExisting:
		// remove the target file and create it anew so we don't fall for an
		// attacker who symlinks a known target name to a file he wants changed.
		if err = os.Remove(targetFile); err != nil {
			return nil, fmt.Errorf("unable to remove target file: %w", err)
		}
		if f, err = os.OpenFile(targetFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644); err != nil {
			return nil, fmt.Errorf("unable to overwrite: %w", err)
		}
		return f, nil
	case createNumberedFiles:
		// It's possible the target directory or filesystem isn't writable by us,
		// not just that the target file(s) already exists.  For now, give up after
		// a limited number of attempts.  In future, maybe distinguish this case
		// and follow in the style of https://tinyurl.com/chromium100
		maxAttempts := 100
		for i := 1; i < maxAttempts; i++ {
			if f, err = os.OpenFile(numberedFileName(dir, base, i), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644); err == nil {
				return f, nil
			}
		}
		return nil, fmt.Errorf("unable to find a name for writing %v, final attempt: %w", targetFile, err)
	}
}

func receiveFile(ctx context.Context, wf apitype.WaitingFile, dir string) (targetFile string, size int64, err error) {
	rc, size, err := localClient.GetWaitingFile(ctx, wf.Name)
	if err != nil {
		return "", 0, fmt.Errorf("opening inbox file %q: %w", wf.Name, err)
	}
	defer rc.Close()
	f, err := openFileOrSubstitute(dir, wf.Name, getArgs.conflict)
	if err != nil {
		return "", 0, err
	}
	// Apply quarantine attribute before copying
	if err := quarantine.SetOnFile(f); err != nil {
		return "", 0, fmt.Errorf("failed to apply quarantine attribute to file %v: %v", f.Name(), err)
	}
	_, err = io.Copy(f, rc)
	if err != nil {
		f.Close()
		return "", 0, fmt.Errorf("failed to write %v: %v", f.Name(), err)
	}
	return f.Name(), size, f.Close()
}

func runFileGetOneBatch(ctx context.Context, dir string) []error {
	var wfs []apitype.WaitingFile
	var err error
	var errs []error
	for len(errs) == 0 {
		wfs, err = localClient.WaitingFiles(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("getting WaitingFiles: %w", err))
			break
		}
		if len(wfs) != 0 || !(getArgs.wait || getArgs.loop) {
			break
		}
		if getArgs.verbose {
			printf("waiting for file...")
		}
		if err := waitForFile(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	deleted := 0
	for i, wf := range wfs {
		if len(errs) > 100 {
			// Likely, everything is broken.
			// Don't try to receive any more files in this batch.
			errs = append(errs, fmt.Errorf("too many errors in runFileGetOneBatch(). %d files unexamined", len(wfs)-i))
			break
		}
		writtenFile, size, err := receiveFile(ctx, wf, dir)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if getArgs.verbose {
			printf("wrote %v as %v (%d bytes)\n", wf.Name, writtenFile, size)
		}
		if err = localClient.DeleteWaitingFile(ctx, wf.Name); err != nil {
			errs = append(errs, fmt.Errorf("deleting %q from inbox: %v", wf.Name, err))
			continue
		}
		deleted++
	}
	if deleted == 0 && len(wfs) > 0 {
		// persistently stuck files are basically an error
		errs = append(errs, fmt.Errorf("moved %d/%d files", deleted, len(wfs)))
	} else if getArgs.verbose {
		printf("moved %d/%d files\n", deleted, len(wfs))
	}
	return errs
}

func runFileGet(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tailscale file get <target-directory>")
	}
	log.SetFlags(0)

	dir := args[0]
	if dir == "/dev/null" {
		return wipeInbox(ctx)
	}

	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return fmt.Errorf("%q is not a directory", dir)
	}
	if getArgs.loop {
		for {
			errs := runFileGetOneBatch(ctx, dir)
			for _, err := range errs {
				outln(err)
			}
			if len(errs) > 0 {
				// It's possible whatever caused the error(s) (e.g. conflicting target file,
				// full disk, unwritable target directory) will re-occur if we try again so
				// let's back off and not busy loop on error.
				//
				// If we've been invoked as:
				//    tailscale file get --conflict=skip ~/Downloads
				// then any file coming in named the same as one in ~/Downloads will always
				// appear as an "error" until the user clears it, but other incoming files
				// should be receivable when they arrive, so let's not wait too long to
				// check again.
				time.Sleep(5 * time.Second)
			}
		}
	}
	errs := runFileGetOneBatch(ctx, dir)
	if len(errs) == 0 {
		return nil
	}
	for _, err := range errs[:len(errs)-1] {
		outln(err)
	}
	return errs[len(errs)-1]
}

func wipeInbox(ctx context.Context) error {
	if getArgs.wait {
		return errors.New("can't use --wait with /dev/null target")
	}
	wfs, err := localClient.WaitingFiles(ctx)
	if err != nil {
		return fmt.Errorf("getting WaitingFiles: %w", err)
	}
	deleted := 0
	for _, wf := range wfs {
		if getArgs.verbose {
			log.Printf("deleting %v ...", wf.Name)
		}
		if err := localClient.DeleteWaitingFile(ctx, wf.Name); err != nil {
			return fmt.Errorf("deleting %q: %v", wf.Name, err)
		}
		deleted++
	}
	if getArgs.verbose {
		log.Printf("deleted %d files", deleted)
	}
	return nil
}

func waitForFile(ctx context.Context) error {
	for {
		ff, err := localClient.AwaitWaitingFiles(ctx, time.Hour)
		if len(ff) > 0 {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			return err
		}
	}
}
