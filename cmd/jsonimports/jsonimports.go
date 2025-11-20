// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The jsonimports tool formats all Go source files in the repository
// to enforce that "json" imports are consistent.
//
// With Go 1.25, the "encoding/json/v2" and "encoding/json/jsontext"
// packages are now available under goexperiment.jsonv2.
// This leads to possible confusion over the following:
//
//   - "encoding/json"
//   - "encoding/json/v2"
//   - "encoding/json/jsontext"
//   - "github.com/go-json-experiment/json/v1"
//   - "github.com/go-json-experiment/json"
//   - "github.com/go-json-experiment/json/jsontext"
//
// In order to enforce consistent usage, we apply the following rules:
//
//   - Until the Go standard library formally accepts "encoding/json/v2"
//     and "encoding/json/jsontext" into the standard library
//     (i.e., they are no longer considered experimental),
//     we forbid any code from directly importing those packages.
//     Go code should instead import "github.com/go-json-experiment/json"
//     and "github.com/go-json-experiment/json/jsontext".
//     The latter packages contain aliases to the standard library
//     if built on Go 1.25 with the goexperiment.jsonv2 tag specified.
//
//   - Imports of "encoding/json" or "github.com/go-json-experiment/json/v1"
//     must be explicitly imported under the package name "jsonv1".
//     If both packages need to be imported, then the former should
//     be imported under the package name "jsonv1std".
//
//   - Imports of "github.com/go-json-experiment/json"
//     must be explicitly imported under the package name "jsonv2".
//
// The latter two rules exist to provide clarity when reading code.
// Without them, it is unclear whether "json.Marshal" refers to v1 or v2.
// With them, however, it is clear that "jsonv1.Marshal" is calling v1 and
// that "jsonv2.Marshal" is calling v2.
//
// TODO(@joetsai): At this present moment, there is no guidance given on
// whether to use v1 or v2 for newly written Go source code.
// I will write a document in the near future providing more guidance.
// Feel free to continue using v1 "encoding/json" as you are accustomed to.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"tailscale.com/syncs"
	"tailscale.com/util/must"
	"tailscale.com/util/safediff"
)

func main() {
	update := flag.Bool("update", false, "update all Go source files")
	flag.Parse()

	// Change working directory to Git repository root.
	repoRoot := strings.TrimSuffix(string(must.Get(exec.Command(
		"git", "rev-parse", "--show-toplevel",
	).Output())), "\n")
	must.Do(os.Chdir(repoRoot))

	// Iterate over all indexed files in the Git repository.
	var printMu sync.Mutex
	var group sync.WaitGroup
	sema := syncs.NewSemaphore(runtime.NumCPU())
	var numDiffs int
	files := string(must.Get(exec.Command("git", "ls-files").Output()))
	for file := range strings.Lines(files) {
		sema.Acquire()
		group.Go(func() {
			defer sema.Release()

			// Ignore non-Go source files.
			file = strings.TrimSuffix(file, "\n")
			if !strings.HasSuffix(file, ".go") {
				return
			}

			// Format all "json" imports in the Go source file.
			srcIn := must.Get(os.ReadFile(file))
			srcOut := mustFormatFile(srcIn)

			// Print differences with each formatted file.
			if !bytes.Equal(srcIn, srcOut) {
				numDiffs++

				printMu.Lock()
				fmt.Println(file)
				lines, _ := safediff.Lines(string(srcIn), string(srcOut), -1)
				for line := range strings.Lines(lines) {
					fmt.Print("\t", line)
				}
				fmt.Println()
				printMu.Unlock()

				// If -update is specified, write out the changes.
				if *update {
					mode := must.Get(os.Stat(file)).Mode()
					must.Do(os.WriteFile(file, srcOut, mode))
				}
			}
		})
	}
	group.Wait()

	// Report whether any differences were detected.
	if numDiffs > 0 && !*update {
		fmt.Printf(`%d files with "json" imports that need formatting`+"\n", numDiffs)
		fmt.Println("Please run:")
		fmt.Println("\t./tool/go run tailscale.com/cmd/jsonimports -update")
		os.Exit(1)
	}
}
