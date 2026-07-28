// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_flashappliance

package cli

import "testing"

const diskutilListSample = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AllDisks</key>
	<array>
		<string>disk4</string>
		<string>disk4s1</string>
	</array>
	<key>WholeDisks</key>
	<array>
		<string>disk4</string>
	</array>
</dict>
</plist>`

const diskutilInfoSample = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>DeviceIdentifier</key>
	<string>disk4</string>
	<key>DeviceModel</key>
	<string>Generic STORAGE DEVICE</string>
	<key>MediaName</key>
	<string>Generic STORAGE DEVICE Media</string>
	<key>Size</key>
	<integer>62512365568</integer>
	<key>Removable</key>
	<true/>
</dict>
</plist>`

const diskutilInfoRootSample = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>DeviceIdentifier</key>
	<string>disk3s1s1</string>
	<key>ParentWholeDisk</key>
	<string>disk3</string>
	<key>APFSPhysicalStores</key>
	<array>
		<dict>
			<key>APFSPhysicalStore</key>
			<string>disk0s2</string>
		</dict>
	</array>
</dict>
</plist>`

func TestParseDiskutilListPlist(t *testing.T) {
	ids, err := parseDiskutilListPlist([]byte(diskutilListSample))
	if err != nil {
		t.Fatalf("parseDiskutilListPlist: %v", err)
	}
	if len(ids) != 1 || ids[0] != "disk4" {
		t.Errorf("ids = %v; want [disk4]", ids)
	}
}

func TestParseDiskutilInfoPlist(t *testing.T) {
	info, err := parseDiskutilInfoPlist([]byte(diskutilInfoSample))
	if err != nil {
		t.Fatalf("parseDiskutilInfoPlist: %v", err)
	}
	if info.Model != "Generic STORAGE DEVICE" {
		t.Errorf("Model = %q; want %q", info.Model, "Generic STORAGE DEVICE")
	}
	if info.MediaName != "Generic STORAGE DEVICE Media" {
		t.Errorf("MediaName = %q", info.MediaName)
	}
	if info.Size != 62512365568 {
		t.Errorf("Size = %d; want 62512365568", info.Size)
	}
}

func TestParseDiskutilInfoPlistRoot(t *testing.T) {
	info, err := parseDiskutilInfoPlist([]byte(diskutilInfoRootSample))
	if err != nil {
		t.Fatalf("parseDiskutilInfoPlist: %v", err)
	}
	if info.ParentWholeDisk != "disk3" {
		t.Errorf("ParentWholeDisk = %q; want disk3", info.ParentWholeDisk)
	}
	if len(info.APFSPhysicalStores) != 1 || info.APFSPhysicalStores[0] != "disk0s2" {
		t.Errorf("APFSPhysicalStores = %v; want [disk0s2]", info.APFSPhysicalStores)
	}
}
