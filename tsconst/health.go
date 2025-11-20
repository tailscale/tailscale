// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsconst

const (
	HealthWarnableUpdateAvailable           = "update-available"
	HealthWarnableSecurityUpdateAvailable   = "security-update-available"
	HealthWarnableIsUsingUnstableVersion    = "is-using-unstable-version"
	HealthWarnableNetworkStatus             = "network-status"
	HealthWarnableWantRunningFalse          = "wantrunning-false"
	HealthWarnableLocalLogConfigError       = "local-log-config-error"
	HealthWarnableLoginState                = "login-state"
	HealthWarnableNotInMapPoll              = "not-in-map-poll"
	HealthWarnableNoDERPHome                = "no-derp-home"
	HealthWarnableNoDERPConnection          = "no-derp-connection"
	HealthWarnableDERPTimedOut              = "derp-timed-out"
	HealthWarnableDERPRegionError           = "derp-region-error"
	HealthWarnableNoUDP4Bind                = "no-udp4-bind"
	HealthWarnableMapResponseTimeout        = "mapresponse-timeout"
	HealthWarnableTLSConnectionFailed       = "tls-connection-failed"
	HealthWarnableMagicsockReceiveFuncError = "magicsock-receive-func-error"
	HealthWarnableTestWarnable              = "test-warnable"
	HealthWarnableApplyDiskConfig           = "apply-disk-config"
	HealthWarnableWarmingUp                 = "warming-up"
)
