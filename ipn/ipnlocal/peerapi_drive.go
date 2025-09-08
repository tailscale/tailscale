// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive

package ipnlocal

import (
	"net/http"
	"path/filepath"
	"strings"

	"tailscale.com/drive"
	"tailscale.com/tailcfg"
	"tailscale.com/util/httpm"
)

const (
	taildrivePrefix = "/v0/drive"
)

func init() {
	peerAPIHandlerPrefixes[taildrivePrefix] = handleServeDrive
}

func handleServeDrive(hi PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	h := hi.(*peerAPIHandler)

	h.logfv1("taildrive: got %s request from %s", r.Method, h.peerNode.Key().ShortString())
	if !h.ps.b.DriveSharingEnabled() {
		h.logf("taildrive: not enabled")
		http.Error(w, "taildrive not enabled", http.StatusNotFound)
		return
	}

	capsMap := h.PeerCaps()
	driveCaps, ok := capsMap[tailcfg.PeerCapabilityTaildrive]
	if !ok {
		h.logf("taildrive: not permitted")
		http.Error(w, "taildrive not permitted", http.StatusForbidden)
		return
	}

	rawPerms := make([][]byte, 0, len(driveCaps))
	for _, cap := range driveCaps {
		rawPerms = append(rawPerms, []byte(cap))
	}

	p, err := drive.ParsePermissions(rawPerms)
	if err != nil {
		h.logf("taildrive: error parsing permissions: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fs, ok := h.ps.b.sys.DriveForRemote.GetOK()
	if !ok {
		h.logf("taildrive: not supported on platform")
		http.Error(w, "taildrive not supported on platform", http.StatusNotFound)
		return
	}
	wr := &httpResponseWrapper{
		ResponseWriter: w,
	}
	bw := &requestBodyWrapper{
		ReadCloser: r.Body,
	}
	r.Body = bw

	defer func() {
		switch wr.statusCode {
		case 304:
			// 304s are particularly chatty so skip logging.
		default:
			log := h.logf
			if r.Method != httpm.PUT && r.Method != httpm.GET {
				log = h.logfv1
			}
			contentType := "unknown"
			if ct := wr.Header().Get("Content-Type"); ct != "" {
				contentType = ct
			}

			log("taildrive: share: %s from %s to %s: status-code=%d ext=%q content-type=%q tx=%.f rx=%.f", r.Method, h.peerNode.Key().ShortString(), h.selfNode.Key().ShortString(), wr.statusCode, parseDriveFileExtensionForLog(r.URL.Path), contentType, roundTraffic(wr.contentLength), roundTraffic(bw.bytesRead))
		}
	}()

	r.URL.Path = strings.TrimPrefix(r.URL.Path, taildrivePrefix)
	fs.ServeHTTPWithPerms(p, wr, r)
}

// parseDriveFileExtensionForLog parses the file extension, if available.
// If a file extension is not present or parsable, the file extension is
// set to "unknown". If the file extension contains a double quote, it is
// replaced with "removed".
// All whitespace is removed from a parsed file extension.
// File extensions including the leading ., e.g. ".gif".
func parseDriveFileExtensionForLog(path string) string {
	fileExt := "unknown"
	if fe := filepath.Ext(path); fe != "" {
		if strings.Contains(fe, "\"") {
			// Do not log include file extensions with quotes within them.
			return "removed"
		}
		// Remove white space from user defined inputs.
		fileExt = strings.ReplaceAll(fe, " ", "")
	}

	return fileExt
}
