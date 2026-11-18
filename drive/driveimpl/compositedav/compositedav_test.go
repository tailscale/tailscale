// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package compositedav

import (
	"net/http/httptest"
	"sync"
	"testing"

	"tailscale.com/drive/driveimpl/dirfs"
)

// TestCloseConcurrentWithRequests verifies that Close can run while requests
// are being served. Run with -race to detect unsynchronized access to
// h.children.
func TestCloseConcurrentWithRequests(t *testing.T) {
	h := &Handler{}
	h.SetChildren("", &Child{
		Child:   &dirfs.Child{Name: "share"},
		BaseURL: func() (string, error) { return "http://127.0.0.1:1", nil },
	})

	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		wg.Go(func() {
			<-start
			for range 100 {
				// A PROPFIND on the root is served locally by h.handle,
				// which reads h.children.
				r := httptest.NewRequest("PROPFIND", "/", nil)
				r.Header.Set("Depth", "1")
				h.ServeHTTP(httptest.NewRecorder(), r)
				h.GetChild("share")
			}
		})
	}

	close(start)
	h.Close()
	wg.Wait()

	if got := h.GetChild("share"); got != nil {
		t.Errorf("GetChild after Close = %v, want nil", got)
	}
}
