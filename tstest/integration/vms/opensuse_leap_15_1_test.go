// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

package vms

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

/*
   The images that we use for OpenSUSE Leap 15.1 have an issue that makes the
   nocloud backend[1] for cloud-init just not work. As a distro-specific
   workaround, we're gonna pretend to be OpenStack.

   TODO(Xe): delete once we no longer need to support OpenSUSE Leap 15.1.

   [1]: https://cloudinit.readthedocs.io/en/latest/topics/datasources/nocloud.html
*/

type openSUSELeap151MetaData struct {
	Zone        string                      `json:"availability_zone"` // nova
	Hostname    string                      `json:"hostname"`          // opensuse-leap-15-1
	LaunchIndex string                      `json:"launch_index"`      // 0
	Meta        openSUSELeap151MetaDataMeta `json:"meta"`              // some openstack metadata we don't need to care about
	Name        string                      `json:"name"`              // opensuse-leap-15-1
	UUID        string                      `json:"uuid"`              // e9c664cd-b116-433b-aa61-7ff420163dcd
}

type openSUSELeap151MetaDataMeta struct {
	Role      string `json:"role"`      // server
	DSMode    string `json:"dsmode"`    // local
	Essential string `json:"essential"` // essential
}

func hackOpenSUSE151UserData(t *testing.T, d Distro, dir string) bool {
	if d.Name != "opensuse-leap-15-1" {
		return false
	}

	t.Log("doing OpenSUSE Leap 15.1 hack")
	osDir := filepath.Join(dir, "openstack", "latest")
	err := os.MkdirAll(osDir, 0755)
	if err != nil {
		t.Fatalf("can't make metadata home: %v", err)
	}

	metadata, err := json.Marshal(openSUSELeap151MetaData{
		Zone:        "nova",
		Hostname:    d.Name,
		LaunchIndex: "0",
		Meta: openSUSELeap151MetaDataMeta{
			Role:      "server",
			DSMode:    "local",
			Essential: "false",
		},
		Name: d.Name,
		UUID: uuid.New().String(),
	})
	if err != nil {
		t.Fatalf("can't encode metadata: %v", err)
	}
	err = os.WriteFile(filepath.Join(osDir, "meta_data.json"), metadata, 0666)
	if err != nil {
		t.Fatalf("can't write to meta_data.json: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "user-data"))
	if err != nil {
		t.Fatalf("can't read user_data: %v", err)
	}

	err = os.WriteFile(filepath.Join(osDir, "user_data"), data, 0666)
	if err != nil {
		t.Fatalf("can't create output user_data: %v", err)
	}

	return true
}
