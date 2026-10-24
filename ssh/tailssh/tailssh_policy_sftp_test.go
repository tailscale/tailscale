// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package tailssh

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

// TestSSHSFTPOnRevokedConn pins the ordering between the
// recheck-on-new-session gate and the sftp recording path. A conn whose
// policy was revoked mid-conn refuses a new sftp session channel with
// the revocation notice at exit 255 and never reaches recording setup.
func TestSSHSFTPOnRevokedConn(t *testing.T) {
	lu := sessionTestUser(t)
	// The standing action carries recorders, none of them reachable, so
	// recording setup fails for any session that reaches it. The gate
	// under test must refuse the session before that.
	p := &policyFlipper{localState: &localState{sshEnabled: true, varRoot: t.TempDir()},
		rule: newPolicyRule(&tailcfg.SSHAction{
			Accept:    true,
			Recorders: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1")},
			OnRecordingFailure: &tailcfg.SSHRecorderFailureAction{
				RejectSessionWithMessage: "session rejected",
			},
		}, lu)}
	_, client, _ := dialPolicyConn(t, p)

	// Revoke with the rule flipping to Reject and no OnPolicyChange kick.
	// The conn stays open. The recheck-on-new-session gate is what
	// refuses the next session channel.
	p.setRule(newPolicyRule(&tailcfg.SSHAction{Reject: true}, lu))

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session channel: %v", err)
	}
	sess.Close()

	status, out := sftpSubsystemSession(t, client)
	if status != 255 {
		t.Errorf("exit status = %d; want 255 (access revoked). output %q", status, out)
	}
	if !strings.Contains(out, "access revoked") {
		t.Errorf("refusal output = %q; want access-revoked notice", out)
	}
	if strings.Contains(out, "session rejected") {
		t.Errorf("refusal output %q: recording policy ran before the revocation gate", out)
	}
	eventually(t, 10*time.Second, "connection not closed after revocation", func() bool {
		return sessionFails(client)
	})
}
