// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailsyncimpl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"

	"tailscale.com/tailsync"
	"tailscale.com/types/logger"
)

// syncClient handles network communication with a remote peer's tailsync PeerAPI.
type syncClient struct {
	logf      logger.Logf
	transport http.RoundTripper
	peerURL   tailsync.PeerURLFunc
	peerID    string
	rootName  string
}

func newSyncClient(logf logger.Logf, transport http.RoundTripper, peerURL tailsync.PeerURLFunc, peerID, rootName string) *syncClient {
	return &syncClient{
		logf:      logf,
		transport: transport,
		peerURL:   peerURL,
		peerID:    peerID,
		rootName:  rootName,
	}
}

func (c *syncClient) baseURL() string {
	return c.peerURL(c.peerID) + "/v0/sync"
}

func (c *syncClient) httpClient() *http.Client {
	return &http.Client{Transport: c.transport}
}

// pushFiles sends changed files to the remote peer.
// entries are the metadata, rootPath is the local root to read files from.
func (c *syncClient) pushFiles(entries []*tailsync.FileEntry, rootPath string) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}

	// Build multipart body: first part is JSON metadata, subsequent parts are file data.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	// Write metadata part.
	metaHeader := make(textproto.MIMEHeader)
	metaHeader.Set("Content-Type", "application/json")
	metaHeader.Set("Content-Disposition", `form-data; name="metadata"`)
	metaPart, err := mw.CreatePart(metaHeader)
	if err != nil {
		return 0, fmt.Errorf("create metadata part: %w", err)
	}
	if err := json.NewEncoder(metaPart).Encode(entries); err != nil {
		return 0, fmt.Errorf("encode metadata: %w", err)
	}

	// Write file data parts for non-deleted entries.
	for _, entry := range entries {
		if entry.Deleted || entry.IsSymlink {
			continue
		}
		fileHeader := make(textproto.MIMEHeader)
		fileHeader.Set("Content-Type", "application/octet-stream")
		fileHeader.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename=%q`, entry.Path))
		fileHeader.Set("X-Tailsync-Path", entry.Path)
		fileHeader.Set("X-Tailsync-Size", strconv.FormatInt(entry.Size, 10))
		fileHeader.Set("X-Tailsync-Mode", strconv.FormatUint(uint64(entry.Mode), 8))

		filePart, err := mw.CreatePart(fileHeader)
		if err != nil {
			return 0, fmt.Errorf("create file part for %s: %w", entry.Path, err)
		}

		absPath := filepath.Join(rootPath, entry.Path)
		f, err := os.Open(absPath)
		if err != nil {
			c.logf("tailsync: push: skip %s: %v", entry.Path, err)
			continue
		}
		_, err = io.Copy(filePart, f)
		f.Close()
		if err != nil {
			return 0, fmt.Errorf("copy file %s: %w", entry.Path, err)
		}
	}

	mw.Close()

	url := c.baseURL() + "/push?root=" + c.rootName
	req, err := http.NewRequest("POST", url, &buf)
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return 0, fmt.Errorf("push request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("push failed: %s: %s", resp.Status, string(body))
	}

	var result struct {
		Applied int `json:"applied"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.Applied, nil
}

// pullChanges fetches changed entries from the remote since the given sequence.
func (c *syncClient) pullChanges(sinceSeq uint64) ([]*tailsync.FileEntry, error) {
	url := fmt.Sprintf("%s/pull?root=%s&since=%d", c.baseURL(), c.rootName, sinceSeq)
	resp, err := c.httpClient().Get(url)
	if err != nil {
		return nil, fmt.Errorf("pull request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("pull failed: %s: %s", resp.Status, string(body))
	}

	var entries []*tailsync.FileEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode pull response: %w", err)
	}
	return entries, nil
}

// pullFile downloads a single file from the remote peer.
func (c *syncClient) pullFile(relPath string) (io.ReadCloser, int64, error) {
	url := fmt.Sprintf("%s/file?root=%s&path=%s", c.baseURL(), c.rootName, relPath)
	resp, err := c.httpClient().Get(url)
	if err != nil {
		return nil, 0, fmt.Errorf("pull file request: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, 0, fmt.Errorf("pull file %s: %s", relPath, resp.Status)
	}
	return resp.Body, resp.ContentLength, nil
}

// getRemoteIndex fetches the full index from the remote peer.
func (c *syncClient) getRemoteIndex() (map[string]*tailsync.FileEntry, uint64, error) {
	url := c.baseURL() + "/index?root=" + c.rootName
	resp, err := c.httpClient().Get(url)
	if err != nil {
		return nil, 0, fmt.Errorf("index request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, 0, fmt.Errorf("index failed: %s: %s", resp.Status, string(body))
	}

	var snap struct {
		Entries  map[string]*tailsync.FileEntry `json:"entries"`
		LocalSeq uint64                         `json:"localSeq"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return nil, 0, fmt.Errorf("decode index: %w", err)
	}
	return snap.Entries, snap.LocalSeq, nil
}
