// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package tailssh

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
	"tailscale.com/types/logger"
)

const (
	auditUserLogin = 1112 // audit message type for user login (from linux/audit.h)
	netlinkAudit   = 9    // AF_NETLINK protocol number for audit (from linux/netlink.h)
	nlmFRequest    = 0x01 // netlink message flag: request (from linux/netlink.h)

	// maxAuditMessageLength is the maximum length of an audit message payload.
	// This is derived from MAX_AUDIT_MESSAGE_LENGTH (8970) in the Linux kernel
	// (linux/audit.h), minus overhead for the netlink header and safety margin.
	maxAuditMessageLength = 8192
)

// hasAuditWriteCap checks if the process has CAP_AUDIT_WRITE in its effective capability set.
func hasAuditWriteCap() bool {
	var hdr unix.CapUserHeader
	var data [2]unix.CapUserData

	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	hdr.Pid = int32(os.Getpid())

	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false
	}

	const capBit = uint32(1 << (unix.CAP_AUDIT_WRITE % 32))
	const capIdx = unix.CAP_AUDIT_WRITE / 32
	return (data[capIdx].Effective & capBit) != 0
}

// buildAuditNetlinkMessage constructs a netlink audit message.
// This is separated from sendAuditMessage to allow testing the message format
// without requiring CAP_AUDIT_WRITE or a netlink socket.
func buildAuditNetlinkMessage(msgType uint16, message string) ([]byte, error) {
	msgBytes := []byte(message)
	if len(msgBytes) > maxAuditMessageLength {
		msgBytes = msgBytes[:maxAuditMessageLength]
	}
	msgLen := len(msgBytes)

	totalLen := syscall.NLMSG_HDRLEN + msgLen
	alignedLen := (totalLen + syscall.NLMSG_ALIGNTO - 1) & ^(syscall.NLMSG_ALIGNTO - 1)

	nlh := syscall.NlMsghdr{
		Len:   uint32(totalLen),
		Type:  msgType,
		Flags: nlmFRequest,
		Seq:   1,
		Pid:   uint32(os.Getpid()),
	}

	buf := bytes.NewBuffer(make([]byte, 0, alignedLen))
	if err := binary.Write(buf, binary.NativeEndian, nlh); err != nil {
		return nil, err
	}
	buf.Write(msgBytes)

	for buf.Len() < alignedLen {
		buf.WriteByte(0)
	}

	return buf.Bytes(), nil
}

// sendAuditMessage sends a message to the audit subsystem using raw netlink.
// It logs errors but does not return them.
func sendAuditMessage(logf logger.Logf, msgType uint16, message string) {
	if !hasAuditWriteCap() {
		return
	}

	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, netlinkAudit)
	if err != nil {
		logf("auditd: failed to create netlink socket: %v", err)
		return
	}
	defer syscall.Close(fd)

	bindAddr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pid:    uint32(os.Getpid()),
		Groups: 0,
	}

	if err := syscall.Bind(fd, bindAddr); err != nil {
		logf("auditd: failed to bind netlink socket: %v", err)
		return
	}

	kernelAddr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pid:    0,
		Groups: 0,
	}

	msgBytes, err := buildAuditNetlinkMessage(msgType, message)
	if err != nil {
		logf("auditd: failed to build audit message: %v", err)
		return
	}

	if err := syscall.Sendto(fd, msgBytes, 0, kernelAddr); err != nil {
		logf("auditd: failed to send audit message: %v", err)
		return
	}
}

// logSSHLogin logs an SSH login event to auditd with whois information.
func logSSHLogin(logf logger.Logf, c *conn) {
	if c == nil || c.info == nil || c.localUser == nil {
		return
	}

	exePath := c.srv.tailscaledPath
	if exePath == "" {
		exePath = "tailscaled"
	}

	srcIP := c.info.src.Addr().String()
	srcPort := c.info.src.Port()
	dstIP := c.info.dst.Addr().String()
	dstPort := c.info.dst.Port()

	tailscaleUser := c.info.uprof.LoginName
	tailscaleUserID := c.info.uprof.ID
	tailscaleDisplayName := c.info.uprof.DisplayName
	nodeName := c.info.node.Name()
	nodeID := c.info.node.ID()

	localUser := c.localUser.Username
	localUID := c.localUser.Uid
	localGID := c.localUser.Gid

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// use principally the same format as ssh / PAM, which come from the audit userspace, i.e.
	// https://github.com/linux-audit/audit-userspace/blob/b6f8c208435038df113a9795e3e202720aee6b70/lib/audit_logging.c#L515
	msg := fmt.Sprintf(
		"op=login acct=%s uid=%s gid=%s "+
			"src=%s src_port=%d dst=%s dst_port=%d "+
			"hostname=%q exe=%q terminal=ssh res=success "+
			"ts_user=%q ts_user_id=%d ts_display_name=%q ts_node=%q ts_node_id=%d",
		localUser, localUID, localGID,
		srcIP, srcPort, dstIP, dstPort,
		hostname, exePath,
		tailscaleUser, tailscaleUserID, tailscaleDisplayName, nodeName, nodeID,
	)

	sendAuditMessage(logf, auditUserLogin, msg)

	logf("audit: SSH login: user=%s uid=%s from=%s ts_user=%s node=%s",
		localUser, localUID, srcIP, tailscaleUser, nodeName)
}

func init() {
	hookSSHLoginSuccess.Set(logSSHLogin)
}
