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
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/peterbourgon/ff/v3/ffcli"
	"golang.org/x/time/rate"
	"inet.af/netaddr"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/version"
)

var fileCmd = &ffcli.Command{
	Name:       "file",
	ShortUsage: "file <cp|get> ...",
	ShortHelp:  "Send or receive files",
	Subcommands: []*ffcli.Command{
		fileCpCmd,
		fileGetCmd,
	},
	Exec: func(context.Context, []string) error {
		// TODO(bradfitz): is there a better ffcli way to
		// annotate subcommand-required commands that don't
		// have an exec body of their own?
		return errors.New("file subcommand required; run 'tailscale file -h' for details")
	},
}

var fileCpCmd = &ffcli.Command{
	Name:       "cp",
	ShortUsage: "file cp <files...> <target>:",
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
	if !strings.HasSuffix(target, ":") {
		return fmt.Errorf("final argument to 'tailscale file cp' must end in colon")
	}
	target = strings.TrimSuffix(target, ":")
	hadBrackets := false
	if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
		hadBrackets = true
		target = strings.TrimSuffix(strings.TrimPrefix(target, "["), "]")
	}
	if ip, err := netaddr.ParseIP(target); err == nil && ip.Is6() && !hadBrackets {
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
		var fileContents io.Reader
		var name = cpArgs.name
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
			fileContents = io.LimitReader(f, contentLength)
			if name == "" {
				name = filepath.Base(fileArg)
			}

			if envknob.Bool("TS_DEBUG_SLOW_PUSH") {
				fileContents = &slowReader{r: fileContents}
			}
		}

		if cpArgs.verbose {
			log.Printf("sending %q to %v/%v/%v ...", name, target, ip, stableID)
		}
		err := tailscale.PushFile(ctx, stableID, contentLength, name, fileContents)
		if err != nil {
			return err
		}
		if cpArgs.verbose {
			log.Printf("sent %q", name)
		}
	}
	return nil
}

func getTargetStableID(ctx context.Context, ipStr string) (id tailcfg.StableNodeID, isOffline bool, err error) {
	ip, err := netaddr.ParseIP(ipStr)
	if err != nil {
		return "", false, err
	}
	fts, err := tailscale.FileTargets(ctx)
	if err != nil {
		return "", false, err
	}
	for _, ft := range fts {
		n := ft.Node
		for _, a := range n.Addresses {
			if a.IP() != ip {
				continue
			}
			isOffline = n.Online != nil && !*n.Online
			return n.StableID, isOffline, nil
		}
	}
	return "", false, fileTargetErrorDetail(ctx, ip)
}

// fileTargetErrorDetail returns a non-nil error saying why ip is an
// invalid file sharing target.
func fileTargetErrorDetail(ctx context.Context, ip netaddr.IP) error {
	found := false
	if st, err := tailscale.Status(ctx); err == nil && st.Self != nil {
		for _, peer := range st.Peer {
			for _, pip := range peer.TailscaleIPs {
				if pip == ip {
					found = true
					if peer.UserID != st.Self.UserID {
						return errors.New("owned by different user; can only send files to your own devices")
					}
				}
			}
		}
	}
	if found {
		return errors.New("target seems to be running an old Tailscale version")
	}
	if !tsaddr.IsTailscaleIP(ip) {
		return fmt.Errorf("unknown target; %v is not a Tailscale IP address", ip)
	}
	return errors.New("unknown target; not in your Tailnet")
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

func runCpTargets(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("invalid arguments with --targets")
	}
	fts, err := tailscale.FileTargets(ctx)
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
		printf("%s\t%s%s\n", n.Addresses[0].IP(), n.ComputedName, detail)
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
	ShortUsage: "file get [--wait] [--verbose] [--conflict=(skip|overwrite|rename)] <target-directory>",
	ShortHelp:  "Move files out of the Tailscale file inbox",
	Exec:       runFileGet,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("get")
		fs.BoolVar(&getArgs.wait, "wait", false, "wait for a file to arrive if inbox is empty")
		fs.BoolVar(&getArgs.loop, "loop", false, "run get in a loop, receiving files as they come in")
		fs.BoolVar(&getArgs.verbose, "verbose", false, "verbose output")
		fs.Var(&getArgs.conflict, "conflict", `behavior when a conflicting (same-named) file already exists in the target directory.
	skip:       skip conflicting files: leave them in the taildrop inbox and print an error. get any non-conflicting files
	overwrite:  overwrite existing file
	rename:     write to a new number-suffixed filename`)
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
	rc, size, err := tailscale.GetWaitingFile(ctx, wf.Name)
	if err != nil {
		return "", 0, fmt.Errorf("opening inbox file %q: %w", wf.Name, err)
	}
	defer rc.Close()
	f, err := openFileOrSubstitute(dir, wf.Name, getArgs.conflict)
	if err != nil {
		return "", 0, err
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
		wfs, err = tailscale.WaitingFiles(ctx)
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
			errs = append(errs, fmt.Errorf("too many errors in runFileGetOneBatch(). %d files unexamined", len(wfs) - i))
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
		if err = tailscale.DeleteWaitingFile(ctx, wf.Name); err != nil {
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
		return errors.New("usage: file get <target-directory>")
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
	wfs, err := tailscale.WaitingFiles(ctx)
	if err != nil {
		return fmt.Errorf("getting WaitingFiles: %w", err)
	}
	deleted := 0
	for _, wf := range wfs {
		if getArgs.verbose {
			log.Printf("deleting %v ...", wf.Name)
		}
		if err := tailscale.DeleteWaitingFile(ctx, wf.Name); err != nil {
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
	c, bc, pumpCtx, cancel := connect(ctx)
	defer cancel()
	fileWaiting := make(chan bool, 1)
	notifyError := make(chan error, 1)
	bc.SetNotifyCallback(func(n ipn.Notify) {
		if n.ErrMessage != nil {
			notifyError <- fmt.Errorf("Notify.ErrMessage: %v", *n.ErrMessage)
		}
		if n.FilesWaiting != nil {
			select {
			case fileWaiting <- true:
			default:
			}
		}
	})
	go pump(pumpCtx, bc, c)
	select {
	case <-fileWaiting:
		return nil
	case <-pumpCtx.Done():
		return pumpCtx.Err()
	case <-ctx.Done():
		return ctx.Err()
	case err := <-notifyError:
		return err
	}
}
