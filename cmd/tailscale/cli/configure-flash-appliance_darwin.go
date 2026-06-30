// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_flashappliance

package cli

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

// maxAutoDetectDiskBytes is the upper size limit for a disk that
// flash-appliance auto-discovers. Anything larger is reported to the
// user but skipped from the candidate list, so it's harder to wipe an
// unmounted internal SSD or a backup drive by accident; the user can
// still target it with --disk explicitly.
const maxAutoDetectDiskBytes = 256 << 30

// discoverExternalDisks returns the physical disks suitable for flashing.
// We pass just "physical" (not "external physical") to diskutil because
// macOS reports built-in SD card readers as internal; instead we exclude
// whichever whole disks back the running root.
func discoverExternalDisks(ctx context.Context) ([]diskCandidate, error) {
	out, err := exec.CommandContext(ctx, "diskutil", "list", "-plist", "physical").Output()
	if err != nil {
		return nil, fmt.Errorf("diskutil list: %w", err)
	}
	ids, err := parseDiskutilListPlist(out)
	if err != nil {
		return nil, fmt.Errorf("parse diskutil list output: %w", err)
	}
	boot, err := bootWholeDisks(ctx)
	if err != nil {
		return nil, fmt.Errorf("locating boot disk: %w", err)
	}
	disks := make([]diskCandidate, 0, len(ids))
	for _, id := range ids {
		if boot[id] {
			continue
		}
		d, err := diskutilInfo(ctx, id)
		if err != nil {
			return nil, err
		}
		if d.SizeBytes > maxAutoDetectDiskBytes {
			printf("Skipping %s (%s) from auto-detection: looks suspiciously large.\n", d.Path, humanBytes(d.SizeBytes))
			printf("  To flash it anyway, pass --disk=%s explicitly.\n", d.Path)
			continue
		}
		disks = append(disks, d)
	}
	return disks, nil
}

var darwinWholeDiskRe = regexp.MustCompile(`^(disk\d+)`)

// bootWholeDisks returns the set of whole-disk identifiers (e.g. "disk0")
// that back the running root filesystem. It seeds the walk from `df -P /`
// (which on Apple Silicon points to the sealed snapshot, e.g.
// disk3s1s1) and follows ParentWholeDisk and APFSPhysicalStores so that
// both the synthesized APFS container (disk3) and the physical disk
// behind it (disk0) get excluded from flash candidates.
func bootWholeDisks(ctx context.Context) (map[string]bool, error) {
	rootDev, err := dfRootDevice(ctx)
	if err != nil {
		return nil, fmt.Errorf("locating root device: %w", err)
	}

	boot := map[string]bool{}
	seen := map[string]bool{}
	queue := []string{rootDev}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
			continue
		}
		seen[id] = true

		if m := darwinWholeDiskRe.FindString(id); m != "" {
			boot[m] = true
		}

		out, err := exec.CommandContext(ctx, "diskutil", "info", "-plist", id).Output()
		if err != nil {
			// Skip identifiers diskutil can't resolve (e.g. a physical
			// store on a disk that was unplugged); anything already
			// collected stays excluded.
			continue
		}
		info, err := parseDiskutilInfoPlist(out)
		if err != nil {
			continue
		}
		if d := info.ParentWholeDisk; d != "" {
			queue = append(queue, d)
		}
		queue = append(queue, info.APFSPhysicalStores...)
	}
	return boot, nil
}

// dfRootDevice returns the device identifier (e.g. "disk3s1s1") that
// backs the root mount, by parsing the second line of `df -P /`.
func dfRootDevice(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "df", "-P", "/").Output()
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return "", fmt.Errorf("unexpected df output: %q", out)
	}
	fields := strings.Fields(lines[1])
	if len(fields) == 0 {
		return "", fmt.Errorf("unexpected df line: %q", lines[1])
	}
	return strings.TrimPrefix(fields[0], "/dev/"), nil
}

func diskutilInfo(ctx context.Context, id string) (diskCandidate, error) {
	out, err := exec.CommandContext(ctx, "diskutil", "info", "-plist", id).Output()
	if err != nil {
		return diskCandidate{}, fmt.Errorf("diskutil info %s: %w", id, err)
	}
	info, err := parseDiskutilInfoPlist(out)
	if err != nil {
		return diskCandidate{}, fmt.Errorf("parse diskutil info %s: %w", id, err)
	}
	desc := info.Model
	if desc == "" {
		desc = info.MediaName
	}
	if info.Size > 0 {
		desc = strings.TrimSpace(fmt.Sprintf("%s (%s)", desc, humanBytes(info.Size)))
	}
	return diskCandidate{
		Path:        "/dev/" + id,
		SizeBytes:   info.Size,
		Description: desc,
	}, nil
}

// validateDiskPath checks that the user-provided disk path looks sane to
// flash on macOS. We trust the user more than on Linux since they had to
// type a /dev/disk path explicitly.
func validateDiskPath(path string) error {
	if !strings.HasPrefix(path, "/dev/disk") {
		return fmt.Errorf("disk path %q does not look like a macOS whole-disk device (/dev/diskN)", path)
	}
	if strings.Contains(path, "s") && strings.IndexByte(path, 's') > len("/dev/disk") {
		return fmt.Errorf("disk path %q looks like a partition (/dev/diskNsP); pass the whole disk", path)
	}
	return nil
}

// unmountDisk uses `diskutil unmountDisk` to release all partitions on the
// target disk.
func unmountDisk(ctx context.Context, path string) error {
	cmd := exec.CommandContext(ctx, "diskutil", "unmountDisk", path)
	cmd.Stdout = Stderr
	cmd.Stderr = Stderr
	return cmd.Run()
}

// ejectDisk runs `diskutil eject` so the user can pull the SD card or
// USB drive without macOS complaining about an improper eject. Returns
// true if the eject command ran successfully.
func ejectDisk(ctx context.Context, path string) (bool, error) {
	cmd := exec.CommandContext(ctx, "diskutil", "eject", path)
	cmd.Stdout = Stderr
	cmd.Stderr = Stderr
	if err := cmd.Run(); err != nil {
		return false, err
	}
	return true, nil
}

// openBlockDevice opens the whole-disk device for writing. On macOS we use
// the raw "rdiskN" alias because the buffered "diskN" path is much slower
// for large writes.
func openBlockDevice(path string) (*os.File, error) {
	raw := strings.Replace(path, "/dev/disk", "/dev/rdisk", 1)
	return os.OpenFile(raw, os.O_WRONLY, 0)
}

// rereadPartitionTable is a no-op on macOS; diskutil and the kernel pick up
// partition changes when the device is closed and re-opened.
func rereadPartitionTable(_ *os.File) error { return nil }

// macOS ioctls from <sys/disk.h>. lseek(SEEK_END) returns 0 on raw
// (/dev/rdiskN) devices, so we have to compute the size from the block
// size and block count.
const (
	dkiocGetBlockSize  = 0x40046418 // _IOR('d', 24, uint32_t)
	dkiocGetBlockCount = 0x40086419 // _IOR('d', 25, uint64_t)
)

// syncBlockDevice asks the kernel to flush in-flight writes to disk. On
// macOS, /dev/rdiskN is the unbuffered raw device, so its writes are
// already synchronous and fsync returns ENOTTY ("inappropriate ioctl
// for device"). We try F_FULLFSYNC for completeness and tolerate the
// same ENOTTY there.
func syncBlockDevice(f *os.File) error {
	_, err := unix.FcntlInt(f.Fd(), unix.F_FULLFSYNC, 0)
	if err == nil || err == unix.ENOTTY {
		return nil
	}
	return err
}

// blockDeviceSize returns the size in bytes of the open block device f.
// On little-endian darwin, IoctlGetInt's 8-byte int safely receives
// both a 4-byte uint32 (block size) and an 8-byte uint64 (block count).
func blockDeviceSize(f *os.File) (int64, error) {
	blockSize, err := unix.IoctlGetInt(int(f.Fd()), dkiocGetBlockSize)
	if err != nil {
		return 0, fmt.Errorf("DKIOCGETBLOCKSIZE: %w", err)
	}
	blockCount, err := unix.IoctlGetInt(int(f.Fd()), dkiocGetBlockCount)
	if err != nil {
		return 0, fmt.Errorf("DKIOCGETBLOCKCOUNT: %w", err)
	}
	return int64(blockSize) * int64(blockCount), nil
}

// diskutilInfoFields are the fields we care about from `diskutil info -plist`.
type diskutilInfoFields struct {
	Model              string
	MediaName          string
	Size               int64
	ParentWholeDisk    string   // e.g. "disk3" for "/" on APFS
	APFSPhysicalStores []string // e.g. ["disk0s2"] for "/" on APFS
}

// parseDiskutilListPlist returns the WholeDisk device identifiers from the
// output of `diskutil list -plist external physical`.
func parseDiskutilListPlist(data []byte) ([]string, error) {
	type listPlist struct {
		Dict plistDict `xml:"dict"`
	}
	var p listPlist
	if err := xml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	arr, ok := p.Dict.Get("WholeDisks").(plistArray)
	if !ok {
		return nil, nil
	}
	var out []string
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out, nil
}

// parseDiskutilInfoPlist returns the fields we care about from `diskutil
// info -plist <id>`.
func parseDiskutilInfoPlist(data []byte) (diskutilInfoFields, error) {
	type infoPlist struct {
		Dict plistDict `xml:"dict"`
	}
	var p infoPlist
	if err := xml.Unmarshal(data, &p); err != nil {
		return diskutilInfoFields{}, err
	}
	var out diskutilInfoFields
	if s, ok := p.Dict.Get("MediaName").(string); ok {
		out.MediaName = s
	}
	if s, ok := p.Dict.Get("DeviceModel").(string); ok {
		out.Model = s
	} else if s, ok := p.Dict.Get("IORegistryEntryName").(string); ok {
		out.Model = s
	}
	if i, ok := p.Dict.Get("Size").(int64); ok {
		out.Size = i
	} else if i, ok := p.Dict.Get("TotalSize").(int64); ok {
		out.Size = i
	}
	if s, ok := p.Dict.Get("ParentWholeDisk").(string); ok {
		out.ParentWholeDisk = s
	}
	if arr, ok := p.Dict.Get("APFSPhysicalStores").(plistArray); ok {
		// The key inside each entry is APFSPhysicalStore (singular) on
		// macOS 14+; older releases may use DeviceIdentifier. Accept
		// either.
		for _, v := range arr {
			d, ok := v.(plistDict)
			if !ok {
				continue
			}
			if id, ok := d.Get("APFSPhysicalStore").(string); ok {
				out.APFSPhysicalStores = append(out.APFSPhysicalStores, id)
			} else if id, ok := d.Get("DeviceIdentifier").(string); ok {
				out.APFSPhysicalStores = append(out.APFSPhysicalStores, id)
			}
		}
	}
	return out, nil
}

// plistDict and plistArray support unmarshaling a small subset of Apple
// XML plists. They preserve key order and decode <string>, <integer>,
// <true>, <false>, <array>, and nested <dict> elements.
type plistDict []plistEntry

type plistEntry struct {
	Key   string
	Value any
}

type plistArray []any

// Get returns the value for a top-level key, or nil if absent.
func (d plistDict) Get(key string) any {
	for _, e := range d {
		if e.Key == key {
			return e.Value
		}
	}
	return nil
}

// UnmarshalXML decodes the children of a <dict> element as alternating
// <key>...</key> and value elements.
func (d *plistDict) UnmarshalXML(dec *xml.Decoder, start xml.StartElement) error {
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.EndElement:
			if t.Name == start.Name {
				return nil
			}
		case xml.StartElement:
			if t.Name.Local != "key" {
				return fmt.Errorf("dict child %q is not <key>", t.Name.Local)
			}
			var key string
			if err := dec.DecodeElement(&key, &t); err != nil {
				return err
			}
			vtok, err := nextStart(dec)
			if err != nil {
				return err
			}
			v, err := decodePlistValue(dec, vtok)
			if err != nil {
				return err
			}
			*d = append(*d, plistEntry{Key: key, Value: v})
		}
	}
}

func nextStart(dec *xml.Decoder) (xml.StartElement, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return xml.StartElement{}, err
		}
		if s, ok := tok.(xml.StartElement); ok {
			return s, nil
		}
	}
}

func decodePlistValue(dec *xml.Decoder, start xml.StartElement) (any, error) {
	switch start.Name.Local {
	case "string":
		var s string
		if err := dec.DecodeElement(&s, &start); err != nil {
			return nil, err
		}
		return s, nil
	case "integer":
		var s string
		if err := dec.DecodeElement(&s, &start); err != nil {
			return nil, err
		}
		var i int64
		fmt.Sscan(strings.TrimSpace(s), &i)
		return i, nil
	case "true":
		return true, dec.Skip()
	case "false":
		return false, dec.Skip()
	case "array":
		var arr plistArray
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.EndElement:
				if t.Name == start.Name {
					return arr, nil
				}
			case xml.StartElement:
				v, err := decodePlistValue(dec, t)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
		}
	case "dict":
		var d plistDict
		if err := d.UnmarshalXML(dec, start); err != nil {
			return nil, err
		}
		return d, nil
	default:
		return nil, dec.Skip()
	}
}
