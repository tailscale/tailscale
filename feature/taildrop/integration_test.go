// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
)

// TODO(bradfitz): add test where control doesn't send tailcfg.CapabilityFileSharing
// and verify that we get the "file sharing not enabled by Tailscale admin" error.

// TODO(bradfitz): add test between different users with the peercap to permit that?

// TestTaildropIntegration verifies that real daemons exercise file delivery
// across fresh and restarted profiles, preserving same-user transfers and
// requiring opt-in and approval across users.
func TestTaildropIntegration(t *testing.T) {
	tests := []struct {
		name                            string
		freshProfiles, crossUser, optIn bool
	}{
		{name: "same_user_restarted"},
		{name: "same_user_fresh", freshProfiles: true},
		{name: "cross_user_opted_in", freshProfiles: true, crossUser: true, optIn: true},
		{name: "same_user_opted_in", freshProfiles: true, optIn: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testTaildropIntegration(t, tt.freshProfiles, tt.crossUser, tt.optIn)
		})
	}
}

// freshProfiles is whether to start the test right away
// with a fresh profile. If false, tailscaled is started, stopped,
// and restarted again to simulate a real-world scenario where
// the first profile already existed.
//
// This exercises an ipnext hook ordering issue we hit earlier.
func testTaildropIntegration(t *testing.T, freshProfiles, crossUser, optIn bool) {
	if runtime.GOOS == "windows" {
		t.Skip("multiple nodes need the userspace-peer harness; see #20711")
	}
	if crossUser && runtime.GOOS == "darwin" {
		t.Skip("cross-user Taildrop is disabled until Apple consent UI support is enabled")
	}
	tstest.Parallel(t)
	controlOpt := integration.ConfigureControl(func(s *testcontrol.Server) {
		s.AllNodesSameUser = !crossUser
		// Enable file sharing. Backend support is reported by the nodes' capability versions.
		s.DefaultNodeCapabilities = &tailcfg.NodeCapMap{
			nodecap.FileSharing: nil,
		}
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
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	c1 := n1.LocalClient()
	c2 := n2.LocalClient()
	if crossUser {
		if err := c1.PushFile(ctx, peerStableID, 5, "denied.txt", strings.NewReader("hello")); err == nil || !strings.Contains(err.Error(), "has not enabled Taildrop") {
			t.Fatalf("default-deny send: %v", err)
		}
		pending, err := c2.TaildropConsentRequests(ctx)
		if err != nil || len(pending) != 0 {
			t.Fatalf("opt-out generated consent: %v, %v", pending, err)
		}
	}
	if optIn {
		for _, c := range []*local.Client{c1, c2} {
			if _, err := c.EditPrefs(ctx, &ipn.MaskedPrefs{Prefs: ipn.Prefs{AllowExternalTaildrop: true}, AllowExternalTaildropSet: true}); err != nil {
				t.Fatal(err)
			}
		}
	}

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
	if optIn && crossUser {
		if !t.Run("preflight", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()
			testConsentPreflight(t, ctx, c1, c2, peerStableID)
		}) {
			t.FailNow()
		}
		testConsentBatch(t, n1, c2, peerStableID, n2.MustStatus().TailscaleIPs[0].String())
		// Each batch waits for per-file consent polls. Give the remaining
		// transfers their own deadline instead of sharing the setup budget.
		cancel()
		ctx, cancel = context.WithTimeout(t.Context(), timeout)
		defer cancel()
	}
	if !crossUser {
		testConsentNotRequired(t, ctx, c1, peerStableID)
	}

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

	// Stand in for the receiving device's owner, approving anything n1 asks to
	// send. Driven through the CLI rather than the client library, because a
	// headless node has nothing else to answer with, and that is the path most
	// likely to break unnoticed.
	//
	// This is a no-op unless n2 requires consent, so the test covers the
	// consent flow when it's on and behaves as before when it's off.
	approverDone := make(chan struct{})
	approved := make(chan struct{}, 1)
	go func() {
		defer close(approverDone)
		// Only opted-in external sends require consent.
		if !optIn || !crossUser {
			return
		}
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for ctx.Err() == nil {
			for _, id := range pendingConsentIDs(t, n2) {
				t.Logf("approving consent request %s via CLI", id)
				if out, err := n2.TailscaleForOutput("file", "consent", "accept", id).CombinedOutput(); err != nil {
					t.Logf("file consent accept %s: %v: %s", id, err, out)
				} else {
					select {
					case approved <- struct{}{}:
					default:
					}
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-approverDone
	})

	fileContents := []byte("hello world this is a file")

	n2ID := n2.MustStatus().Self.ID
	t.Logf("n2 self.ID = %q; n1's peer[0].ID = %q", n2ID, peerStableID)
	t.Logf("Doing PushFile ...")
	err := c1.PushFile(ctx, n2.MustStatus().Self.ID, int64(len(fileContents)), "test.txt", bytes.NewReader(fileContents))
	if err != nil {
		t.Fatalf("PushFile from n1->n2: %v", err)
	}
	t.Logf("PushFile done")
	if optIn && crossUser {
		select {
		case <-approved:
		case <-ctx.Done():
			t.Fatal("transfer completed without exercising consent approval")
		}
	}

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

	// Identical names and sizes are independent transactions; empty files
	// must also carry a known zero length on the wire.
	for _, content := range []string{string(fileContents), ""} {
		if err := c1.PushFile(ctx, peerStableID, int64(len(content)), "test.txt", strings.NewReader(content)); err != nil {
			t.Fatalf("repeat/empty PushFile: %v", err)
		}
		if err := c2.DeleteWaitingFile(ctx, "test.txt"); err != nil {
			t.Fatal(err)
		}
	}
	// Preserve streaming sends whose size is unknown to the LocalAPI client.
	if err := c1.PushFile(ctx, peerStableID, -1, "stream.txt", io.LimitReader(strings.NewReader("stream"), 6)); err != nil {
		t.Fatalf("streaming PushFile: %v", err)
	}
	if err := c2.DeleteWaitingFile(ctx, "stream.txt"); err != nil {
		t.Fatal(err)
	}

	if optIn {
		// Stopped -> up takes the full Start/UpdatePrefs path, just like
		// reauthentication, rather than an EditPrefs of selected flags.
		if out, err := n2.TailscaleForOutput("down").CombinedOutput(); err != nil {
			t.Fatalf("down: %v: %s", err, out)
		}
		n2.MustUp()
		prefs, err := c2.GetPrefs(ctx)
		if err != nil || !prefs.AllowExternalTaildrop {
			t.Fatalf("up lost Taildrop opt-in: %v, %v", prefs, err)
		}
	}
	d1.MustCleanShutdown(t)
	d2.MustCleanShutdown(t)
}

// Both sender paths must request consent per file and continue after a decline.
func testConsentBatch(t *testing.T, sender *integration.TestNode, receiver *local.Client, peer tailcfg.StableNodeID, ip string) {
	t.Helper()
	for _, mode := range []string{"cli", "multipart", "cli-denied", "multipart-denied"} {
		if !t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			denied := strings.HasSuffix(mode, "-denied")
			contents := map[string]string{"a file%.txt": "first", "b.txt": "second", "empty.txt": ""}
			names := []string{"a file%.txt", "b.txt", "empty.txt"}
			result := make(chan error, 1)
			if strings.HasPrefix(mode, "cli") {
				args := []string{"file", "cp"}
				for _, name := range names {
					p := filepath.Join(t.TempDir(), name)
					if err := os.WriteFile(p, []byte(contents[name]), 0600); err != nil {
						t.Fatal(err)
					}
					args = append(args, p)
				}
				args = append(args, ip+":")
				cmd := sender.TailscaleForOutput(args...)
				go func() {
					out, err := cmd.CombinedOutput()
					if denied {
						if !strings.Contains(string(out), fmt.Sprintf("%q: declined", names[0])) || strings.Contains(string(out), "403 Forbidden") {
							t.Errorf("CLI should report the decline once, per file: %s", out)
						}
						if !strings.Contains(string(out), "elapsed") || !strings.Contains(string(out), " / ") {
							t.Errorf("CLI omitted transfer bytes or timing: %s", out)
						}
					}
					if err != nil {
						err = fmt.Errorf("cli: %w: %s", err, out)
					}
					result <- err
				}()
			} else {
				var body bytes.Buffer
				mw := multipart.NewWriter(&body)
				var manifest []ipn.OutgoingFile
				for _, name := range names {
					manifest = append(manifest, ipn.OutgoingFile{ID: mode + name, Name: url.PathEscape(name), DeclaredSize: int64(len(contents[name]))})
				}
				part, err := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"application/json"}})
				if err != nil {
					t.Fatal(err)
				}
				if err := json.NewEncoder(part).Encode(manifest); err != nil {
					t.Fatal(err)
				}
				for _, f := range manifest {
					part, err := mw.CreateFormFile("file", f.Name)
					if err != nil {
						t.Fatal(err)
					}
					name, _ := url.PathUnescape(f.Name)
					io.WriteString(part, contents[name])
				}
				mw.Close()
				req, err := http.NewRequestWithContext(ctx, "POST", "http://local-tailscaled.sock/localapi/v0/file-put/"+string(peer), &body)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", mw.FormDataContentType())
				go func() {
					resp, err := sender.LocalClient().DoLocalRequest(req)
					if err == nil {
						defer resp.Body.Close()
						data, readErr := io.ReadAll(resp.Body)
						err = readErr
						if resp.StatusCode != http.StatusOK {
							err = fmt.Errorf("multipart: %s: %s", resp.Status, data)
						}
					}
					result <- err
				}()
			}
			for _, name := range names {
				var requestID string
				if err := tstest.WaitFor(5*time.Second, func() error {
					pending, err := receiver.TaildropConsentRequests(ctx)
					if err != nil {
						return err
					}
					if len(pending) != 1 || len(pending[0].Files) != 1 || pending[0].Files[0].Name != name {
						return fmt.Errorf("%s waiting for %q: pending=%v", mode, name, pending)
					}
					requestID = pending[0].RequestID
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err := receiver.RespondToTaildropConsent(ctx, requestID, !denied || name != names[0]); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-result:
				if denied {
					if err == nil || !strings.Contains(err.Error(), "declined") || !strings.Contains(err.Error(), names[0]) {
						t.Fatalf("%s: expected decline, got %v", mode, err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if denied {
				files, err := receiver.WaitingFiles(ctx)
				if err != nil || len(files) != len(names)-1 {
					t.Fatalf("batch did not deliver the remaining files: %v, %v", files, err)
				}
				for _, file := range files {
					if file.Name == names[0] {
						t.Fatalf("declined file was delivered: %s", file.Name)
					}
				}
			}
			for _, name := range names {
				if denied && name == names[0] {
					continue
				}
				r, _, err := receiver.GetWaitingFile(ctx, name)
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(r)
				r.Close()
				if err != nil || string(data) != contents[name] {
					t.Fatalf("%s: %q, %v", name, data, err)
				}
				if err := receiver.DeleteWaitingFile(ctx, name); err != nil {
					t.Fatal(err)
				}
			}
		}) {
			t.FailNow()
		}
	}
}

// pendingConsentIDs returns the request IDs that "tailscale file consent list"
// reports on n, which is how a headless node discovers what's waiting.
//
// The listing is one tab-separated row per request, ID first.
func pendingConsentIDs(t *testing.T, n *integration.TestNode) []string {
	t.Helper()
	out, err := n.TailscaleForOutput("file", "consent", "list").CombinedOutput()
	if err != nil {
		// The daemon may not be up yet, or may have gone away; the caller
		// polls, so this isn't fatal.
		return nil
	}
	var ids []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		id, _, ok := strings.Cut(line, "\t")
		if !ok {
			continue // the "nothing awaiting approval" message
		}
		if id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// testConsentNotRequired verifies that same-user transfers remain implicitly
// allowed, including when external Taildrop is enabled. Enabling the development
// override must fail this check rather than silently changing the test's policy.
func testConsentNotRequired(t *testing.T, ctx context.Context, sender *local.Client, peer tailcfg.StableNodeID) {
	t.Helper()
	// requesting consent for a same-user transfer should return "notRequired" rather than "approved" or "pending".
	const metadata = `{"size":3,"txid":"same-user-preflight","hash":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}`
	req, err := http.NewRequestWithContext(ctx, "POST", "http://local-tailscaled.sock/localapi/v0/file-put-request/"+string(peer)+"/preflight.txt", strings.NewReader(metadata))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := sender.DoLocalRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("same-user preflight: status=%d body=%s err=%v", resp.StatusCode, data, err)
	}
	var result struct{ State string }
	if err := json.Unmarshal(data, &result); err != nil || result.State != "notRequired" {
		t.Fatalf("same-user preflight state=%s, want notRequired (check Taildrop consent override): %v", data, err)
	}
}

// testConsentPreflight exercises the two-step flow: request approval
// before uploading, then reuse that transaction ID without a second prompt.
func testConsentPreflight(t *testing.T, ctx context.Context, sender, receiver *local.Client, peer tailcfg.StableNodeID) {
	t.Helper()
	call := func(method, endpoint, body, txid string, wantStatus int) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, "http://local-tailscaled.sock/localapi/v0/"+endpoint+"/"+string(peer)+"/preflight.txt", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if txid != "" {
			req.Header.Set("X-Taildrop-Txid", txid)
		}
		resp, err := sender.DoLocalRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != wantStatus {
			t.Fatalf("%s %s: status=%d body=%s err=%v", method, endpoint, resp.StatusCode, data, err)
		}
		return data
	}

	// The former payload is rejected before any prompt is created.
	call("POST", "file-put-request", `{"size":3}`, "", http.StatusBadRequest)
	const txid = "preflight"
	const metadata = `{"size":3,"txid":"preflight","hash":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}`
	checkState := func(want string) {
		t.Helper()
		data := call("POST", "file-put-request", metadata, "", http.StatusOK)
		var result struct{ State string }
		if err := json.Unmarshal(data, &result); err != nil || result.State != want {
			t.Fatalf("preflight state=%s, want %s: %v", data, want, err)
		}
	}
	checkState("pending")
	pending, err := receiver.TaildropConsentRequests(ctx)
	if err != nil || len(pending) != 1 {
		t.Fatalf("preflight pending=%v: %v", pending, err)
	}
	if err := receiver.RespondToTaildropConsent(ctx, pending[0].RequestID, true); err != nil {
		t.Fatal(err)
	}
	checkState("approved")

	// There is no auto-approver running here. A different upload transaction
	// would require another prompt and could not complete.
	call("PUT", "file-put", "abc", txid, http.StatusOK)
	pending, err = receiver.TaildropConsentRequests(ctx)
	if err != nil || len(pending) != 0 {
		t.Fatalf("upload requested approval again: %v, %v", pending, err)
	}
	if err := receiver.DeleteWaitingFile(ctx, "preflight.txt"); err != nil {
		t.Fatal(err)
	}
}
