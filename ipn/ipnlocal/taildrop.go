// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"maps"
	"slices"
	"strings"

	"tailscale.com/ipn"
)

// UpdateOutgoingFiles updates b.outgoingFiles to reflect the given updates and
// sends an ipn.Notify with the full list of outgoingFiles.
func (b *LocalBackend) UpdateOutgoingFiles(updates map[string]*ipn.OutgoingFile) {
	b.mu.Lock()
	if b.outgoingFiles == nil {
		b.outgoingFiles = make(map[string]*ipn.OutgoingFile, len(updates))
	}
	maps.Copy(b.outgoingFiles, updates)
	outgoingFiles := make([]*ipn.OutgoingFile, 0, len(b.outgoingFiles))
	for _, file := range b.outgoingFiles {
		outgoingFiles = append(outgoingFiles, file)
	}
	b.mu.Unlock()
	slices.SortFunc(outgoingFiles, func(a, b *ipn.OutgoingFile) int {
		t := a.Started.Compare(b.Started)
		if t != 0 {
			return t
		}
		return strings.Compare(a.Name, b.Name)
	})
	b.send(ipn.Notify{OutgoingFiles: outgoingFiles})
}
