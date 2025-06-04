// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package conf contains code to load, manipulate, and access config file
// settings for k8s-proxy.
package conf

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/tailscale/hujson"
	"tailscale.com/types/opt"
)

// Config describes a config file.
type Config struct {
	Path    string // disk path of HuJSON
	Raw     []byte // raw bytes from disk, in HuJSON form
	Std     []byte // standardized JSON form
	Version string // "v1alpha1"

	// Parsed is the parsed config, converted from its on-disk version to the
	// latest known format.
	//
	// As of 2023-10-15 there is exactly one format ("alpha0") so this is both
	// the on-disk format and the in-memory upgraded format.
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

	// Backwards compatibility version(s) of the config.
	V1Alpha1 *ConfigV1Alpha1 `json:",omitempty"`
}

type ConfigV1Alpha1 struct {
	AuthKey       *string        `json:",omitempty"`
	Hostname      *string        `json:",omitempty"`
	LogLevel      *string        `json:",omitempty"` // "debug", "info", "warn", "error"
	App           *string        `json:",omitempty"` // "k8s-proxy-api-server-proxy"
	KubeAPIServer *KubeAPIServer `json:",omitempty"` // Config specific to the API Server proxy.
}

type KubeAPIServer struct {
	AuthMode opt.Bool `json:",omitempty"`
}

// Load reads and parses the config file at the provided path on disk.
func Load(path string) (*Config, error) {
	var c Config
	c.Path = path
	var err error

	c.Raw, err = os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c.Std, err = hujson.Standardize(c.Raw)
	if err != nil {
		return nil, fmt.Errorf("error parsing config file %s HuJSON/JSON: %w", path, err)
	}
	var ver VersionedConfig
	if err := json.Unmarshal(c.Std, &ver); err != nil {
		return nil, fmt.Errorf("error parsing config file %s: %w", path, err)
	}
	rootV1Alpha1 := (ver.Version == "v1alpha1")
	backCompatV1Alpha1 := (ver.V1Alpha1 != nil)
	switch {
	case ver.Version == "":
		return nil, fmt.Errorf("error parsing config file %s: no \"version\" field provided", path)
	case rootV1Alpha1 && backCompatV1Alpha1:
		// Exactly one of these should be set.
		return nil, fmt.Errorf("error parsing config file %s: both root and v1alpha1 config provided", path)
	case rootV1Alpha1 != backCompatV1Alpha1:
		c.Version = "v1alpha1"
		switch {
		case rootV1Alpha1 && ver.ConfigV1Alpha1 != nil:
			c.Parsed = *ver.ConfigV1Alpha1
		case backCompatV1Alpha1:
			c.Parsed = *ver.V1Alpha1
		default:
			c.Parsed = ConfigV1Alpha1{}
		}
	default:
		return nil, fmt.Errorf("error parsing config file %s: unsupported \"version\" value %q; want \"v1alpha1\"", path, ver.Version)
	}

	return &c, nil
}
