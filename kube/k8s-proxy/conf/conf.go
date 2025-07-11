// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package conf contains code to load, manipulate, and access config file
// settings for k8s-proxy.
package conf

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"

	"github.com/tailscale/hujson"
	"tailscale.com/types/opt"
)

const v1Alpha1 = "v1alpha1"

// Config describes a config file.
type Config struct {
	Path    string // disk path of HuJSON
	Raw     []byte // raw bytes from disk, in HuJSON form
	Std     []byte // standardized JSON form
	Version string // "v1alpha1"

	// Parsed is the parsed config, converted from its on-disk version to the
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
	AuthKey       *string        `json:",omitempty"` // Tailscale auth key to use.
	Hostname      *string        `json:",omitempty"` // Tailscale device hostname.
	State         *string        `json:",omitempty"` // Path to the Tailscale state.
	LogLevel      *string        `json:",omitempty"` // "debug", "info". Defaults to "info".
	App           *string        `json:",omitempty"` // e.g. kubetypes.AppProxyGroupKubeAPIServer
	KubeAPIServer *KubeAPIServer `json:",omitempty"` // Config specific to the API Server proxy.
	ServerURL     *string        `json:",omitempty"` // URL of the Tailscale coordination server.
	AcceptRoutes  *bool          `json:",omitempty"` // Accepts routes advertised by other Tailscale nodes.
	// StaticEndpoints are additional, user-defined endpoints that this node
	// should advertise amongst its wireguard endpoints.
	StaticEndpoints []netip.AddrPort `json:",omitempty"`
}

type KubeAPIServer struct {
	AuthMode opt.Bool `json:",omitempty"`
}

// Load reads and parses the config file at the provided path on disk.
func Load(path string) (c Config, err error) {
	c.Path = path

	c.Raw, err = os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("error reading config file %q: %w", path, err)
	}
	c.Std, err = hujson.Standardize(c.Raw)
	if err != nil {
		return c, fmt.Errorf("error parsing config file %q HuJSON/JSON: %w", path, err)
	}
	var ver VersionedConfig
	if err := json.Unmarshal(c.Std, &ver); err != nil {
		return c, fmt.Errorf("error parsing config file %q: %w", path, err)
	}
	rootV1Alpha1 := (ver.Version == v1Alpha1)
	backCompatV1Alpha1 := (ver.V1Alpha1 != nil)
	switch {
	case ver.Version == "":
		return c, fmt.Errorf("error parsing config file %q: no \"version\" field provided", path)
	case rootV1Alpha1 && backCompatV1Alpha1:
		// Exactly one of these should be set.
		return c, fmt.Errorf("error parsing config file %q: both root and v1alpha1 config provided", path)
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
		return c, fmt.Errorf("error parsing config file %q: unsupported \"version\" value %q; want \"%s\"", path, ver.Version, v1Alpha1)
	}

	return c, nil
}
