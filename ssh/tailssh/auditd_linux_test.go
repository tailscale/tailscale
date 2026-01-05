// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package tailssh

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// maybeWithSudo returns a command with context that may be prefixed with sudo if not running as root.
func maybeWithSudo(ctx context.Context, name string, args ...string) *exec.Cmd {
	if os.Geteuid() == 0 {
		return exec.CommandContext(ctx, name, args...)
	}
	sudoArgs := append([]string{name}, args...)
	return exec.CommandContext(ctx, "sudo", sudoArgs...)
}

func TestBuildAuditNetlinkMessage(t *testing.T) {
	testCases := []struct {
		name     string
		msgType  uint16
		message  string
		wantType uint16
	}{
		{
			name:     "simple-message",
			msgType:  auditUserLogin,
			message:  "op=login acct=test",
			wantType: auditUserLogin,
		},
		{
			name:     "message-with-quoted-fields",
			msgType:  auditUserLogin,
			message:  `op=login hostname="test-host" exe="/usr/bin/tailscaled" ts_user="user@example.com" ts_node="node.tail-scale.ts.net"`,
			wantType: auditUserLogin,
		},
		{
			name:     "message-with-special-chars",
			msgType:  auditUserLogin,
			message:  `op=login hostname="host with spaces" ts_user="user name@example.com" ts_display_name="User \"Quote\" Name"`,
			wantType: auditUserLogin,
		},
		{
			name:     "long-message-truncated",
			msgType:  auditUserLogin,
			message:  string(make([]byte, 2000)),
			wantType: auditUserLogin,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := buildAuditNetlinkMessage(tc.msgType, tc.message)
			if err != nil {
				t.Fatalf("buildAuditNetlinkMessage failed: %v", err)
			}

			if len(msg) < syscall.NLMSG_HDRLEN {
				t.Fatalf("message too short: got %d bytes, want at least %d", len(msg), syscall.NLMSG_HDRLEN)
			}

			var nlh syscall.NlMsghdr
			buf := bytes.NewReader(msg[:syscall.NLMSG_HDRLEN])
			if err := binary.Read(buf, binary.NativeEndian, &nlh); err != nil {
				t.Fatalf("failed to parse netlink header: %v", err)
			}

			if nlh.Type != tc.wantType {
				t.Errorf("message type: got %d, want %d", nlh.Type, tc.wantType)
			}

			if nlh.Flags != nlmFRequest {
				t.Errorf("flags: got 0x%x, want 0x%x", nlh.Flags, nlmFRequest)
			}

			if len(msg)%syscall.NLMSG_ALIGNTO != 0 {
				t.Errorf("message not aligned: len=%d, alignment=%d", len(msg), syscall.NLMSG_ALIGNTO)
			}

			payloadLen := int(nlh.Len) - syscall.NLMSG_HDRLEN
			if payloadLen < 0 {
				t.Fatalf("invalid payload length: %d", payloadLen)
			}

			payload := msg[syscall.NLMSG_HDRLEN : syscall.NLMSG_HDRLEN+payloadLen]

			expectedMsg := tc.message
			if len(expectedMsg) > maxAuditMessageLength {
				expectedMsg = expectedMsg[:maxAuditMessageLength]
			}
			if string(payload) != expectedMsg {
				t.Errorf("payload mismatch:\ngot:  %q\nwant: %q", string(payload), expectedMsg)
			}

			expectedLen := syscall.NLMSG_HDRLEN + len(payload)
			if int(nlh.Len) != expectedLen {
				t.Errorf("length field: got %d, want %d", nlh.Len, expectedLen)
			}
		})
	}
}

func TestAuditIntegration(t *testing.T) {
	if !hasAuditWriteCap() {
		t.Skip("skipping: CAP_AUDIT_WRITE not in effective capability set")
	}

	if _, err := exec.LookPath("journalctl"); err != nil {
		t.Skip("skipping: journalctl not available")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	checkCmd := maybeWithSudo(ctx, "journalctl", "--field", "_TRANSPORT")
	var out bytes.Buffer
	checkCmd.Stdout = &out
	if err := checkCmd.Run(); err != nil {
		t.Skipf("skipping: cannot query journalctl transports: %v", err)
	}
	if !strings.Contains(out.String(), "audit") {
		t.Skip("skipping: journald not configured for audit messages, try: systemctl enable systemd-journald-audit.socket && systemctl restart systemd-journald")
	}

	testID := fmt.Sprintf("tailscale-test-%d", time.Now().UnixNano())
	testMsg := fmt.Sprintf("op=test-audit test_id=%s res=success", testID)

	followCmd := maybeWithSudo(ctx, "journalctl", "-f", "_TRANSPORT=audit", "--no-pager")

	stdout, err := followCmd.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to get stdout pipe: %v", err)
	}

	if err := followCmd.Start(); err != nil {
		t.Fatalf("failed to start journalctl: %v", err)
	}
	defer followCmd.Process.Kill()

	testLogf := func(format string, args ...any) {
		t.Logf(format, args...)
	}
	sendAuditMessage(testLogf, auditUserLogin, testMsg)

	bs := bufio.NewScanner(stdout)
	found := false
	for bs.Scan() {
		line := bs.Text()
		if strings.Contains(line, testID) {
			t.Logf("found audit log entry: %s", line)
			found = true
			break
		}
	}

	if err := bs.Err(); err != nil && ctx.Err() == nil {
		t.Fatalf("error reading journalctl output: %v", err)
	}

	if !found {
		if ctx.Err() == context.DeadlineExceeded {
			t.Errorf("timeout waiting for audit message with test_id=%s", testID)
		} else {
			t.Errorf("audit message with test_id=%s not found in journald audit log", testID)
		}
	}
}
