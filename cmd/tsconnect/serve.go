// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"path"
	"time"

	"tailscale.com/tsweb"
)

//go:embed dist/* index.html
var embeddedFS embed.FS

var serveStartTime = time.Now()

func runServe() {
	mux := http.NewServeMux()

	indexBytes, err := generateServeIndex()
	if err != nil {
		log.Fatalf("Could not generate index.html: %v", err)
	}
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "index.html", serveStartTime, bytes.NewReader(indexBytes))
	}))
	mux.Handle("/dist/", http.HandlerFunc(handleServeDist))
	tsweb.Debugger(mux)

	log.Printf("Listening on %s", *addr)
	err = http.ListenAndServe(*addr, mux)
	if err != nil {
		log.Fatal(err)
	}
}

func generateServeIndex() ([]byte, error) {
	log.Printf("Generating index.html...\n")
	rawIndexBytes, err := embeddedFS.ReadFile("index.html")
	if err != nil {
		return nil, fmt.Errorf("Could not read index.html: %w", err)
	}

	esbuildMetadataBytes, err := embeddedFS.ReadFile("dist/esbuild-metadata.json")
	if err != nil {
		return nil, fmt.Errorf("Could not read esbuild-metadata.json: %w", err)
	}
	var esbuildMetadata EsbuildMetadata
	if err := json.Unmarshal(esbuildMetadataBytes, &esbuildMetadata); err != nil {
		return nil, fmt.Errorf("Could not parse esbuild-metadata.json: %w", err)
	}
	entryPointsToHashedDistPaths := make(map[string]string)
	for outputPath, output := range esbuildMetadata.Outputs {
		if output.EntryPoint != "" {
			entryPointsToHashedDistPaths[output.EntryPoint] = outputPath
		}
	}

	indexBytes := rawIndexBytes
	for entryPointPath, defaultDistPath := range entryPointsToDefaultDistPaths {
		hashedDistPath := entryPointsToHashedDistPaths[entryPointPath]
		if hashedDistPath != "" {
			indexBytes = bytes.ReplaceAll(indexBytes, []byte(defaultDistPath), []byte(hashedDistPath))
		}
	}

	return indexBytes, nil
}

// EsbuildMetadata is the subset of metadata struct (described by
// https://esbuild.github.io/api/#metafile) that we care about for mapping
// from entry points to hashed file names.
type EsbuildMetadata = struct {
	Outputs map[string]struct {
		EntryPoint string `json:"entryPoint,omitempty"`
	} `json:"outputs,omitempty"`
}

var entryPointsToDefaultDistPaths = map[string]string{
	"src/index.css": "dist/index.css",
	"src/index.js":  "dist/index.js",
}

func handleServeDist(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path[1:]
	var f fs.File
	// Prefer pre-compressed versions generated during the build step.
	if tsweb.AcceptsEncoding(r, "br") {
		if brotliFile, err := embeddedFS.Open(p + ".br"); err == nil {
			f = brotliFile
			w.Header().Set("Content-Encoding", "br")
		}
	}
	if f == nil && tsweb.AcceptsEncoding(r, "gzip") {
		if gzipFile, err := embeddedFS.Open(p + ".gz"); err == nil {
			f = gzipFile
			w.Header().Set("Content-Encoding", "gzip")
		}
	}

	if f == nil {
		if rawFile, err := embeddedFS.Open(r.URL.Path[1:]); err == nil {
			f = rawFile
		} else {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
	}
	defer f.Close()

	// fs.File does not claim to implement Seeker, but in practice it does.
	fSeeker, ok := f.(io.ReadSeeker)
	if !ok {
		http.Error(w, "Not seekable", http.StatusInternalServerError)
		return
	}

	// Aggressively cache static assets, since we cache-bust our assets with
	// hashed filenames.
	w.Header().Set("Cache-Control", "public, max-age=31535996")
	w.Header().Set("Vary", "Accept-Encoding")

	http.ServeContent(w, r, path.Base(r.URL.Path), serveStartTime, fSeeker)
}
