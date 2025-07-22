// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package conf contains code to load, manipulate, and access config file
// settings for k8s-proxy.
package conf

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/tailscale/hujson"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
)

const v1Alpha1 = "v1alpha1"

// Config describes a config file.
type Config struct {
	Raw     []byte // raw bytes, in HuJSON form
	Std     []byte // standardized JSON form
	Version string // "v1alpha1"

	// Parsed is the parsed config, converted from its raw bytes version to the
	// latest known format.
	Parsed ConfigV1Alpha1
}

// VersionedConfig allows specifying config at the root of the object, or in
// a versioned sub-object.
// e.g. {"version": "v1alpha1", "authKey": "abc123"}
// or {"version": "v1beta1", "a-beta-config": "a-beta-value", "v1alpha1": {"authKey": "abc123"}}
type VersionedConfig struct {
	Version string `json:",omitempty"` // "v1alpha1"

	// Latest version of the config.
	*ConfigV1Alpha1

	// Backwards compatibility version(s) of the config. Fields and sub-fields
	// from here should only be added to, never changed in place.
	V1Alpha1 *ConfigV1Alpha1 `json:",omitempty"`
	// V1Beta1 *ConfigV1Beta1 `json:",omitempty"` // Not yet used.
}

type ConfigV1Alpha1 struct {
	AuthKey            *string  `json:",omitempty"` // Tailscale auth key to use.
	State              *string  `json:",omitempty"` // Path to the Tailscale state.
	LogLevel           *string  `json:",omitempty"` // "debug", "info". Defaults to "info".
	App                *string  `json:",omitempty"` // e.g. kubetypes.AppProxyGroupKubeAPIServer
	ServerURL          *string  `json:",omitempty"` // URL of the Tailscale coordination server.
	LocalAddr          *string  `json:",omitempty"` // The address to use for serving HTTP health checks and metrics (defaults to all interfaces).
	LocalPort          *uint16  `json:",omitempty"` // The port to use for serving HTTP health checks and metrics (defaults to 9002).
	MetricsEnabled     opt.Bool `json:",omitempty"` // Serve metrics on <LocalAddr>:<LocalPort>/metrics.
	HealthCheckEnabled opt.Bool `json:",omitempty"` // Serve health check on <LocalAddr>:<LocalPort>/metrics.

	// TODO(tomhjp): The remaining fields should all be reloadable during
	// runtime, but currently missing most of the APIServerProxy fields.
	Hostname          *string               `json:",omitempty"` // Tailscale device hostname.
	AcceptRoutes      opt.Bool              `json:",omitempty"` // Accepts routes advertised by other Tailscale nodes.
	AdvertiseServices []string              `json:",omitempty"` // Tailscale Services to advertise.
	APIServerProxy    *APIServerProxyConfig `json:",omitempty"` // Config specific to the API Server proxy.
	StaticEndpoints   []netip.AddrPort      `json:",omitempty"` // StaticEndpoints are additional, user-defined endpoints that this node should advertise amongst its wireguard endpoints.
}

type APIServerProxyConfig struct {
	Enabled     opt.Bool                      `json:",omitempty"` // Whether to enable the API Server proxy.
	Mode        *kubetypes.APIServerProxyMode `json:",omitempty"` // "auth" or "noauth" mode.
	ServiceName *tailcfg.ServiceName          `json:",omitempty"` // Name of the Tailscale Service to advertise.
	IssueCerts  opt.Bool                      `json:",omitempty"` // Whether this replica should issue TLS certs for the Tailscale Service.
}

// Load reads and parses the config file at the provided path on disk.
func Load(raw []byte) (c Config, err error) {
	c.Raw = raw
	c.Std, err = hujson.Standardize(c.Raw)
	if err != nil {
		return c, fmt.Errorf("error parsing config as HuJSON/JSON: %w", err)
	}
	var ver VersionedConfig
	if err := json.Unmarshal(c.Std, &ver); err != nil {
		return c, fmt.Errorf("error parsing config: %w", err)
	}
	rootV1Alpha1 := (ver.Version == v1Alpha1)
	backCompatV1Alpha1 := (ver.V1Alpha1 != nil)
	switch {
	case ver.Version == "":
		return c, errors.New("error parsing config: no \"version\" field provided")
	case rootV1Alpha1 && backCompatV1Alpha1:
		// Exactly one of these should be set.
		return c, errors.New("error parsing config: both root and v1alpha1 config provided")
	case rootV1Alpha1 != backCompatV1Alpha1:
		c.Version = v1Alpha1
		switch {
		case rootV1Alpha1 && ver.ConfigV1Alpha1 != nil:
			c.Parsed = *ver.ConfigV1Alpha1
		case backCompatV1Alpha1:
			c.Parsed = *ver.V1Alpha1
		default:
			c.Parsed = ConfigV1Alpha1{}
		}
	default:
		return c, fmt.Errorf("error parsing config: unsupported \"version\" value %q; want \"%s\"", ver.Version, v1Alpha1)
	}

	return c, nil
}

func (c *Config) GetLocalAddr() string {
	if c.Parsed.LocalAddr == nil {
		return "[::]"
	}

	return *c.Parsed.LocalAddr
}

func (c *Config) GetLocalPort() uint16 {
	if c.Parsed.LocalPort == nil {
		return uint16(9002)
	}

	return *c.Parsed.LocalPort
}
