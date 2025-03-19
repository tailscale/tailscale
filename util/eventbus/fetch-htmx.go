// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ignore

// Program fetch-htmx fetches and installs local copies of the HTMX
// library and its dependencies, used by the debug UI. It is meant to
// be run via go generate.
package main

import (
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	// Hash from https://htmx.org/docs/#installing
	htmx, err := fetchHashed("https://unpkg.com/htmx.org@2.0.4", "HGfztofotfshcF7+8n44JQL2oJmowVChPTg48S+jvZoztPfvwD79OC/LTtG6dMp+")
	if err != nil {
		log.Fatalf("fetching htmx: %v", err)
	}

	// Hash SHOULD be from https://htmx.org/extensions/ws/ , but the
	// hash is currently incorrect, see
	// https://github.com/bigskysoftware/htmx-extensions/issues/153
	//
	// Until that bug is resolved, hash was obtained by rebuilding the
	// extension from git source, and verifying that the hash matches
	// what unpkg is serving.
	ws, err := fetchHashed("https://unpkg.com/htmx-ext-ws@2.0.2", "932iIqjARv+Gy0+r6RTGrfCkCKS5MsF539Iqf6Vt8L4YmbnnWI2DSFoMD90bvXd0")
	if err != nil {
		log.Fatalf("fetching htmx-websockets: %v", err)
	}

	if err := writeGz("assets/htmx.min.js.gz", htmx); err != nil {
		log.Fatalf("writing htmx.min.js.gz: %v", err)
	}
	if err := writeGz("assets/htmx-websocket.min.js.gz", ws); err != nil {
		log.Fatalf("writing htmx-websocket.min.js.gz: %v", err)
	}
}

func writeGz(path string, bs []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	g, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return err
	}

	if _, err := g.Write(bs); err != nil {
		return err
	}

	if err := g.Flush(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return nil
}

func fetchHashed(url, wantHash string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %q returned error status: %s", url, resp.Status)
	}
	ret, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading file from %q: %v", url, err)
	}
	h := sha512.Sum384(ret)
	got := base64.StdEncoding.EncodeToString(h[:])
	if got != wantHash {
		return nil, fmt.Errorf("wrong hash for %q: got %q, want %q", url, got, wantHash)
	}
	return ret, nil
}
