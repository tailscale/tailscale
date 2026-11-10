// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package sockopts

import (
	"net"
	"time"

	"tailscale.com/net/ktimeout"
)

// TCPConfig specifies transport settings for a TCP socket. The zero value
// leaves all settings unchanged. It does not select service-specific defaults.
//
// Apply these settings to the actual TCP connection before TLS/Noise wrapping,
// either after dialing or after accepting a connection. For a TCP-terminating
// proxy, they govern the connection to the proxy, not the end-to-end service.
type TCPConfig struct {
	// KeepAlive, if non-nil, enables or disables TCP keepalive. When enabled,
	// timing fields have the semantics of net.KeepAliveConfig. When disabled,
	// timing fields are ignored. Success does not imply hardware offload.
	KeepAlive *net.KeepAliveConfig

	// UserTimeout, if non-nil, sets the maximum age of outstanding data via
	// ktimeout.SetUserTimeoutChecked. A pointer to zero restores the kernel's
	// default behavior; nil leaves it unchanged. This is not an RTO setting.
	UserTimeout *time.Duration
}

// TCPConfigResult reports each requested setting independently. For a requested
// setting, nil means its application succeeded. Unrequested settings have nil
// results as well. KeepAlive retains the errors from net.TCPConn's setters;
// UserTimeout reports errors.ErrUnsupported for an unsupported platform or
// socket. Other errors, such as invalid values or a closed socket, are failures
// to apply the setting.
//
// There is no rollback: a setting may partially apply before returning an error.
// Callers must not infer that the requested policy is active when an error is
// returned, and decide whether to close the connection or use a fallback.
type TCPConfigResult struct {
	KeepAlive   error
	UserTimeout error
}

// Apply attempts all requested settings, even if one fails, and reports their
// results. It does not log, select fallbacks, or close c. The caller must apply
// configuration before handing the connection to other goroutines.
func (cfg TCPConfig) Apply(c *net.TCPConn) (result TCPConfigResult) {
	if ka := cfg.KeepAlive; ka != nil {
		if ka.Enable {
			result.KeepAlive = c.SetKeepAliveConfig(*ka)
		} else {
			result.KeepAlive = c.SetKeepAlive(false)
		}
	}
	if timeout := cfg.UserTimeout; timeout != nil {
		rc, err := c.SyscallConn()
		if err == nil {
			err = rc.Control(func(fd uintptr) {
				result.UserTimeout = ktimeout.SetUserTimeoutChecked(fd, *timeout)
			})
		}
		if err != nil {
			result.UserTimeout = err
		}
	}
	return result
}
