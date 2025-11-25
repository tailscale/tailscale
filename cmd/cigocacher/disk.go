// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/bradfitz/go-tool-cache/cachers"
)

// indexEntry is the metadata that DiskCache stores on disk for an ActionID.
type indexEntry struct {
	Version   int    `json:"v"`
	OutputID  string `json:"o"`
	Size      int64  `json:"n"`
	TimeNanos int64  `json:"t"`
}

func validHex(x string) bool {
	if len(x) < 4 || len(x) > 100 {
		return false
	}
	for _, b := range x {
		if b >= '0' && b <= '9' || b >= 'a' && b <= 'f' {
			continue
		}
		return false
	}
	return true
}

// put is like dc.Put but refactored to support safe concurrent writes on Windows.
// TODO(tomhjp): upstream these changes to go-tool-cache once they look stable.
func put(dc *cachers.DiskCache, actionID, outputID string, size int64, body io.Reader) (diskPath string, _ error) {
	if len(actionID) < 4 || len(outputID) < 4 {
		return "", fmt.Errorf("actionID and outputID must be at least 4 characters long")
	}
	if !validHex(actionID) {
		log.Printf("diskcache: got invalid actionID %q", actionID)
		return "", errors.New("actionID must be hex")
	}
	if !validHex(outputID) {
		log.Printf("diskcache: got invalid outputID %q", outputID)
		return "", errors.New("outputID must be hex")
	}

	actionFile := dc.ActionFilename(actionID)
	outputFile := dc.OutputFilename(outputID)
	actionDir := filepath.Dir(actionFile)
	outputDir := filepath.Dir(outputFile)

	if err := os.MkdirAll(actionDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create action directory: %w", err)
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}

	wrote, err := writeOutputFile(outputFile, body, size, outputID)
	if err != nil {
		return "", err
	}
	if wrote != size {
		return "", fmt.Errorf("wrote %d bytes, expected %d", wrote, size)
	}

	ij, err := json.Marshal(indexEntry{
		Version:   1,
		OutputID:  outputID,
		Size:      size,
		TimeNanos: time.Now().UnixNano(),
	})
	if err != nil {
		return "", err
	}
	if err := writeActionFile(dc.ActionFilename(actionID), ij); err != nil {
		return "", fmt.Errorf("atomic write failed: %w", err)
	}
	return outputFile, nil
}
