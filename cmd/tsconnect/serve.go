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
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"time"

	"tailscale.com/tsweb"
	"tailscale.com/util/precompress"
)

//go:embed index.html
var embeddedFS embed.FS

//go:embed dist/*
var embeddedDistFS embed.FS

var serveStartTime = time.Now()

func runServe() {
	mux := http.NewServeMux()

	var distFS fs.FS
	if *distDir == "./dist" {
		var err error
		distFS, err = fs.Sub(embeddedDistFS, "dist")
		if err != nil {
			log.Fatalf("Could not drop dist/ prefix from embedded FS: %v", err)
		}
	} else {
		distFS = os.DirFS(*distDir)
	}

	indexBytes, err := generateServeIndex(distFS)
	if err != nil {
		log.Fatalf("Could not generate index.html: %v", err)
	}
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "index.html", serveStartTime, bytes.NewReader(indexBytes))
	}))
	mux.Handle("/dist/", http.StripPrefix("/dist/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleServeDist(w, r, distFS)
	})))
	tsweb.Debugger(mux)

	log.Printf("Listening on %s", *addr)
	err = http.ListenAndServe(*addr, mux)
	if err != nil {
		log.Fatal(err)
	}
}

func generateServeIndex(distFS fs.FS) ([]byte, error) {
	log.Printf("Generating index.html...\n")
	rawIndexBytes, err := embeddedFS.ReadFile("index.html")
	if err != nil {
		return nil, fmt.Errorf("Could not read index.html: %w", err)
	}

	esbuildMetadataFile, err := distFS.Open("esbuild-metadata.json")
	if err != nil {
		return nil, fmt.Errorf("Could not open esbuild-metadata.json: %w", err)
	}
	defer esbuildMetadataFile.Close()
	esbuildMetadataBytes, err := ioutil.ReadAll(esbuildMetadataFile)
	if err != nil {
		return nil, fmt.Errorf("Could not read esbuild-metadata.json: %w", err)
	}
	var esbuildMetadata EsbuildMetadata
	if err := json.Unmarshal(esbuildMetadataBytes, &esbuildMetadata); err != nil {
		return nil, fmt.Errorf("Could not parse esbuild-metadata.json: %w", err)
	}
	entryPointsToHashedDistPaths := make(map[string]string)
	mainWasmPath := ""
	for outputPath, output := range esbuildMetadata.Outputs {
		if output.EntryPoint != "" {
			entryPointsToHashedDistPaths[output.EntryPoint] = path.Join("dist", outputPath)
		}
		if path.Ext(outputPath) == ".wasm" {
			for input := range output.Inputs {
				if input == "src/main.wasm" {
					mainWasmPath = path.Join("dist", outputPath)
					break
				}
			}
		}
	}

	indexBytes := rawIndexBytes
	for entryPointPath, defaultDistPath := range entryPointsToDefaultDistPaths {
		hashedDistPath := entryPointsToHashedDistPaths[entryPointPath]
		if hashedDistPath != "" {
			indexBytes = bytes.ReplaceAll(indexBytes, []byte(defaultDistPath), []byte(hashedDistPath))
		}
	}
	if mainWasmPath != "" {
		mainWasmPrefetch := fmt.Sprintf("</title>\n<link rel='preload' as='fetch' crossorigin='anonymous' href='%s'>", mainWasmPath)
		indexBytes = bytes.ReplaceAll(indexBytes, []byte("</title>"), []byte(mainWasmPrefetch))
	}

	return indexBytes, nil
}

var entryPointsToDefaultDistPaths = map[string]string{
	"src/app/index.css": "dist/index.css",
	"src/app/index.ts":  "dist/index.js",
}

func handleServeDist(w http.ResponseWriter, r *http.Request, distFS fs.FS) {
	path := r.URL.Path
	f, err := precompress.OpenPrecompressedFile(w, r, path, distFS)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
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

	http.ServeContent(w, r, path, serveStartTime, fSeeker)
}
