// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The update program fetches the libbpf headers from the libbpf GitHub repository
// and writes them to disk.
package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	libbpfVersion = "1.4.3"
	prefix        = "libbpf-" + libbpfVersion
)

var (
	filesToExtract = map[string]struct{}{
		prefix + "/LICENSE.BSD-2-Clause":  {},
		prefix + "/src/bpf_endian.h":      {},
		prefix + "/src/bpf_helper_defs.h": {},
		prefix + "/src/bpf_helpers.h":     {},
		prefix + "/src/bpf_tracing.h":     {},
	}
)

var (
	flagDest = flag.String("dest", ".", "destination directory")
)

// TODO(jwhited): go generate strategy for derp/xdp
func main() {
	flag.Parse()

	f, err := os.CreateTemp("", "libbpf")
	if err != nil {
		log.Panic(err)
	}
	defer os.Remove(f.Name())

	resp, err := http.Get(fmt.Sprintf("https://github.com/libbpf/libbpf/archive/refs/tags/v%s.tar.gz", libbpfVersion))
	if err != nil {
		log.Panic(err)
	}
	defer resp.Body.Close()

	_, err = io.Copy(f, resp.Body)
	if err != nil {
		log.Panic(err)
	}

	_, err = f.Seek(0, 0)
	if err != nil {
		log.Panic(err)
	}
	g, err := gzip.NewReader(f)
	if err != nil {
		log.Panic(err)
	}
	defer g.Close()
	t := tar.NewReader(g)

	seen := make(map[string]bool, len(filesToExtract))
	for {
		h, err := t.Next()
		if err != nil {
			log.Panic(err)
		}
		if strings.Contains(h.Name, "..") {
			continue
		}
		_, ok := filesToExtract[h.Name]
		if ok {
			if seen[h.Name] {
				log.Panicf("saw %s more than once in archive", h.Name)
			}
			seen[h.Name] = true
			p := filepath.Join(*flagDest, filepath.Base(h.Name))
			e, err := os.Create(p)
			if err != nil {
				log.Panic(err)
			}
			_, err = io.Copy(e, t)
			if err != nil {
				log.Panic(err)
			}
			if len(seen) == len(filesToExtract) {
				break
			}
		}
	}
}
