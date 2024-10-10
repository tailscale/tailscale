// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package conffile contains code to load, manipulate, and access config file
// settings.
package conffile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"

	"tailscale.com/ipn"
)

// Config describes a config file.
type Config struct {
	Path    string // disk path of HuJSON, or VMUserDataPath
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

// VMUserDataPath is a sentinel value for Load to use to get the data
// from the VM's metadata service's user-data field.
const VMUserDataPath = "vm:user-data"

// hujsonStandardize is set to hujson.Standardize by conffile_hujson.go on
// platforms that support config files.
var hujsonStandardize func([]byte) ([]byte, error)

// Load reads and parses the config file at the provided path on disk.
func Load(path string) (*Config, error) {
	switch runtime.GOOS {
	case "ios", "android":
		// compile-time for deadcode elimination
		return nil, fmt.Errorf("config file loading not supported on %q", runtime.GOOS)
	}
	if hujsonStandardize == nil {
		// Build tags are wrong in conffile_hujson.go
		return nil, errors.New("[unexpected] config file loading not wired up")
	}
	var c Config
	c.Path = path
	var err error

	switch path {
	case VMUserDataPath:
		c.Raw, err = readVMUserData()
	default:
		c.Raw, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	c.Std, err = hujsonStandardize(c.Raw)
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
	jd.DisallowUnknownFields()
	err = jd.Decode(&c.Parsed)
	if err != nil {
		return nil, fmt.Errorf("error parsing config file %s: %w", path, err)
	}
	if jd.More() {
		return nil, fmt.Errorf("error parsing config file %s: trailing data after JSON object", path)
	}
	return &c, nil
}
