// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
)

// TODO(bradfitz): add test where control doesn't send tailcfg.CapabilityFileSharing
// and verify that we get the "file sharing not enabled by Tailscale admin" error.

// TODO(bradfitz): add test between different users with the peercap to permit that?

func TestTaildropIntegration(t *testing.T) {
	testTaildropIntegration(t, false)
}

func TestTaildropIntegration_Fresh(t *testing.T) {
	testTaildropIntegration(t, true)
}

// freshProfiles is whether to start the test right away
// with a fresh profile. If false, tailscaled is started, stopped,
// and restarted again to simulate a real-world scenario where
// the first profile already existed.
//
// This exercises an ipnext hook ordering issue we hit earlier.
func testTaildropIntegration(t *testing.T, freshProfiles bool) {
	tstest.Parallel(t)
	controlOpt := integration.ConfigureControl(func(s *testcontrol.Server) {
		s.AllNodesSameUser = true // required for Taildrop
	})
	env := integration.NewTestEnv(t, controlOpt)

	// Create two nodes:
	n1 := integration.NewTestNode(t, env)
	d1 := n1.StartDaemon()

	n2 := integration.NewTestNode(t, env)
	d2 := n2.StartDaemon()

	awaitUp := func() {
		t.Helper()
		n1.AwaitListening()
		t.Logf("n1 is listening")
		n2.AwaitListening()
		t.Logf("n2 is listening")
		n1.MustUp()
		t.Logf("n1 is up")
		n2.MustUp()
		t.Logf("n2 is up")
		n1.AwaitRunning()
		t.Logf("n1 is running")
		n2.AwaitRunning()
		t.Logf("n2 is running")
	}
	awaitUp()

	if !freshProfiles {
		d1.MustCleanShutdown(t)
		d2.MustCleanShutdown(t)
		d1 = n1.StartDaemon()
		d2 = n2.StartDaemon()
		awaitUp()
	}

	var peerStableID tailcfg.StableNodeID

	if err := tstest.WaitFor(5*time.Second, func() error {
		st := n1.MustStatus()
		if len(st.Peer) == 0 {
			return errors.New("no peers")
		}
		if len(st.Peer) > 1 {
			return fmt.Errorf("got %d peers; want 1", len(st.Peer))
		}
		peer := st.Peer[st.Peers()[0]]
		peerStableID = peer.ID
		if peer.ID == st.Self.ID {
			return errors.New("peer is self")
		}

		if len(st.TailscaleIPs) == 0 {
			return errors.New("no Tailscale IPs")
		}

		return nil
	}); err != nil {
		t.Fatal(err)
	}

	const timeout = 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	c1 := n1.LocalClient()
	c2 := n2.LocalClient()

	wantNoWaitingFiles := func(c *local.Client) {
		t.Helper()
		files, err := c.WaitingFiles(ctx)
		if err != nil {
			t.Fatalf("WaitingFiles: %v", err)
		}
		if len(files) != 0 {
			t.Fatalf("WaitingFiles: got %d files; want 0", len(files))
		}
	}

	// Verify c2 has no files.
	wantNoWaitingFiles(c2)

	gotFile := make(chan bool, 1)
	go func() {
		v, err := c2.AwaitWaitingFiles(t.Context(), timeout)
		if err != nil {
			return
		}
		if len(v) != 0 {
			gotFile <- true
		}
	}()

	fileContents := []byte("hello world this is a file")

	n2ID := n2.MustStatus().Self.ID
	t.Logf("n2 self.ID = %q; n1's peer[0].ID = %q", n2ID, peerStableID)
	t.Logf("Doing PushFile ...")
	err := c1.PushFile(ctx, n2.MustStatus().Self.ID, int64(len(fileContents)), "test.txt", bytes.NewReader(fileContents))
	if err != nil {
		t.Fatalf("PushFile from n1->n2: %v", err)
	}
	t.Logf("PushFile done")

	select {
	case <-gotFile:
		t.Logf("n2 saw AwaitWaitingFiles wake up")
	case <-ctx.Done():
		t.Fatalf("n2 timeout waiting for AwaitWaitingFiles")
	}

	files, err := c2.WaitingFiles(ctx)
	if err != nil {
		t.Fatalf("c2.WaitingFiles: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("c2.WaitingFiles: got %d files; want 1", len(files))
	}
	got := files[0]
	want := apitype.WaitingFile{
		Name: "test.txt",
		Size: int64(len(fileContents)),
	}
	if got != want {
		t.Fatalf("c2.WaitingFiles: got %+v; want %+v", got, want)
	}

	// Download the file.
	rc, size, err := c2.GetWaitingFile(ctx, got.Name)
	if err != nil {
		t.Fatalf("c2.GetWaitingFile: %v", err)
	}
	if size != int64(len(fileContents)) {
		t.Fatalf("c2.GetWaitingFile: got size %d; want %d", size, len(fileContents))
	}
	gotBytes, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("c2.GetWaitingFile: %v", err)
	}
	if !bytes.Equal(gotBytes, fileContents) {
		t.Fatalf("c2.GetWaitingFile: got %q; want %q", gotBytes, fileContents)
	}

	// Now delete it.
	if err := c2.DeleteWaitingFile(ctx, got.Name); err != nil {
		t.Fatalf("c2.DeleteWaitingFile: %v", err)
	}
	wantNoWaitingFiles(c2)

	d1.MustCleanShutdown(t)
	d2.MustCleanShutdown(t)
}
