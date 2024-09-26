// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package conffile contains code to load, manipulate, and access config file
// settings.
package conffile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/tailscale/hujson"
	"tailscale.com/ipn"
)

// Config describes a config file.
type Config struct {
	Path    string // disk path of HuJSON, or [VMUserDataPath], or kube:<secret-name>
	Raw     []byte // raw bytes from disk, in HuJSON form
	Std     []byte // standardized JSON form
	Version string // "alpha0" for now

	// Parsed is the parsed config, converted from its on-disk version to the
	// latest known format.
	//
	// As of 2023-10-15 there is exactly one format ("alpha0") so this is both
	// the on-disk format and the in-memory upgraded format.
	Parsed ipn.ConfigVAlpha
}

// WantRunning reports whether c is non-nil and it's configured to be running.
func (c *Config) WantRunning() bool {
	return c != nil && !c.Parsed.Enabled.EqualBool(false)
}

const (
	// VMUserDataPath is a sentinel value for Load to use to get the data
	// from the VM's metadata service's user-data field.
	VMUserDataPath = "vm:user-data"

	// kubePrefix indicates the config should be read from a Kubernetes Secret.
	// The remaining string should be the name of the Secret within the same
	// namespace as tailscaled's own pod.
	kubePrefix = "kube:"
)

// Load reads and parses the config file at the provided path on disk.
func Load(path string) (*Config, error) {
	var c Config
	c.Path = path
	var err error

	switch {
	case path == VMUserDataPath:
		c.Raw, err = readVMUserData()
	case strings.HasPrefix(path, "kube:"):
		c.Raw, err = readKubeSecret(strings.TrimPrefix(path, "kube:"))
	default:
		c.Raw, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	c.Std, err = hujson.Standardize(c.Raw)
	if err != nil {
		return nil, fmt.Errorf("error parsing config file %s HuJSON/JSON: %w", path, err)
	}
	var ver struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(c.Std, &ver); err != nil {
		return nil, fmt.Errorf("error parsing config file %s: %w", path, err)
	}
	switch ver.Version {
	case "":
		return nil, fmt.Errorf("error parsing config file %s: no \"version\" field defined", path)
	case "alpha0":
	default:
		return nil, fmt.Errorf("error parsing config file %s: unsupported \"version\" value %q; want \"alpha0\" for now", path, ver.Version)
	}
	c.Version = ver.Version

	jd := json.NewDecoder(bytes.NewReader(c.Std))
	// Not not disallow unknown fields. Older clients need to be able to read
	// newer configs to support version tearing between the creator and
	// consumer of config files.
	err = jd.Decode(&c.Parsed)
	if err != nil {
		return nil, fmt.Errorf("error parsing config file %s: %w", path, err)
	}
	if jd.More() {
		return nil, fmt.Errorf("error parsing config file %s: trailing data after JSON object", path)
	}
	return &c, nil
}
