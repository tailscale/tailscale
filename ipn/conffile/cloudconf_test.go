// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conffile

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"tailscale.com/feature/buildfeatures"
)

type blockingTransport struct{}

func (blockingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}

// Tests that readVMUserData gives up when the metadata service does not
// respond, so that tailscaled can go on to start without a config file.
func TestReadVMUserDataTimeout(t *testing.T) {
	if !buildfeatures.HasAWS {
		t.Skip("AWS support omitted")
	}
	oldTransport, oldTimeout := http.DefaultClient.Transport, metadataTimeout
	t.Cleanup(func() {
		http.DefaultClient.Transport, metadataTimeout = oldTransport, oldTimeout
	})
	http.DefaultClient.Transport = blockingTransport{}
	metadataTimeout = 10 * time.Millisecond

	done := make(chan error, 1)
	go func() {
		_, err := readVMUserData()
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("readVMUserData error = %v; want %v", err, context.DeadlineExceeded)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readVMUserData did not return after the timeout")
	}
}
