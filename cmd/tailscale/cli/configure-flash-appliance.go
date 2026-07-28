// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_flashappliance

package cli

import (
	"archive/zip"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/bradfitz/monogok/disklayout"
	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/clientupdate"
	"tailscale.com/clientupdate/distsign"
	"tailscale.com/gokrazy/mkfs"
	"tailscale.com/util/progresstracking"
	"tailscale.com/util/prompt"
)

var flashApplianceArgs struct {
	variant              string
	disk                 string
	track                string
	yes                  bool
	gaf                  string
	addSSHAuthorizedKeys string
}

func flashApplianceCmd() *ffcli.Command {
	return &ffcli.Command{
		Name:       "flash-appliance",
		ShortUsage: "tailscale configure flash-appliance [flags]",
		ShortHelp:  "Download a signed Tailscale appliance image and write it to a local disk [experimental]",
		LongHelp: hidden + strings.TrimSpace(`
This experimental command downloads a signed Tailscale appliance image (Gokrazy archive
format, "GAF") from pkgs.tailscale.com, verifies its signature, and writes
it to a local block device (SD card, USB drive, virtual disk).

On macOS, the target disk is auto-discovered from 'diskutil list physical',
excluding whichever disks back the running root. On Linux, you must pass
--disk=/dev/sdX explicitly.

This command requires mkfs.ext4 in $PATH to format the writable /perm
partition. On macOS, 'brew install e2fsprogs' provides it.
`),
		FlagSet: (func() *flag.FlagSet {
			fs := newFlagSet("flash-appliance")
			fs.StringVar(&flashApplianceArgs.variant, "variant", "", `appliance variant: "pi-arm64", "vm-amd64", or "vm-arm64". Empty prompts interactively.`)
			fs.StringVar(&flashApplianceArgs.disk, "disk", "", "target block device (e.g. /dev/sdb or /dev/disk4)")
			fs.StringVar(&flashApplianceArgs.track, "track", "", `which track to download from; defaults to "`+clientupdate.CurrentTrack+`"`)
			fs.BoolVar(&flashApplianceArgs.yes, "yes", false, "skip the destructive-write confirmation prompt")
			fs.StringVar(&flashApplianceArgs.gaf, "gaf", "", "use a local GAF file instead of downloading (skips signature verification)")
			fs.StringVar(&flashApplianceArgs.addSSHAuthorizedKeys, "add-ssh-authorized-keys", "", "path to an authorized_keys file to include on the appliance for breakglass SSH access")
			return fs
		})(),
		Exec: runFlashAppliance,
	}
}

func runFlashAppliance(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unknown arguments")
	}
	if runtime.GOOS == "windows" {
		return errors.New("flash-appliance is not supported on Windows yet; consider running under WSL")
	}
	if os.Geteuid() != 0 {
		return errors.New("writing to a raw block device requires root; re-run with sudo")
	}

	disk, err := resolveTargetDisk(ctx, flashApplianceArgs.disk)
	if err != nil {
		return err
	}

	gafPath, gafLabel, variant, cleanup, err := obtainGAF(ctx, gafDownloadArgs{
		localGAF: flashApplianceArgs.gaf,
		track:    flashApplianceArgs.track,
		variant:  flashApplianceArgs.variant,
	})
	if err != nil {
		return err
	}
	defer cleanup()

	zr, err := zip.OpenReader(gafPath)
	if err != nil {
		return fmt.Errorf("open GAF: %w", err)
	}
	defer zr.Close()

	bootCode, err := readGAFMember(zr.File, "mbr.img", 1<<20)
	if err != nil {
		return err
	}

	if !flashApplianceArgs.yes {
		msg := fmt.Sprintf("This will ERASE %s. Flash %s?", disk.Path, gafLabel)
		if !prompt.YesNo(msg, false) {
			return errors.New("aborted")
		}
	}

	printf("Unmounting %s...\n", disk.Path)
	if err := unmountDisk(ctx, disk.Path); err != nil {
		return fmt.Errorf("unmount %s: %w", disk.Path, err)
	}

	if err := writeGAFToDisk(zr.File, disk.Path, bootCode, variant); err != nil {
		return err
	}

	var permFiles []mkfs.PermFile
	if flashApplianceArgs.addSSHAuthorizedKeys != "" {
		keys, err := os.ReadFile(flashApplianceArgs.addSSHAuthorizedKeys)
		if err != nil {
			return fmt.Errorf("reading --add-ssh-authorized-keys: %w", err)
		}
		permFiles = append(permFiles, mkfs.PermFile{
			Path:    "breakglass.authorized_keys",
			Content: keys,
		})
		printf("Including SSH authorized_keys for breakglass access.\n")
	}
	if err := formatPermExt4(disk.Path, permFiles); err != nil {
		return fmt.Errorf("formatting perm: %w", err)
	}

	ejected, err := ejectDisk(ctx, disk.Path)
	if err != nil {
		// Non-fatal: the user can eject manually.
		fmt.Fprintf(Stderr, "ejecting %s: %v\n", disk.Path, err)
	}

	printf("Done. %s\n", flashSuccessHint(disk.Path, variant, ejected))
	return nil
}

// formatPermExt4 creates an ext4 filesystem inside the gokrazy perm
// partition of the disk at diskPath, delegating to gokrazy/mkfs.Perm.
//
// On macOS we open the buffered /dev/diskN path (not /dev/rdiskN)
// because go-diskfs writes ext4 metadata in small unaligned chunks
// that the raw character device rejects.
func formatPermExt4(diskPath string, files []mkfs.PermFile) error {
	f, err := os.OpenFile(diskPath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	devsize, err := blockDeviceSize(f)
	if err != nil {
		return fmt.Errorf("sizing %s: %w", diskPath, err)
	}
	return mkfs.Perm(f, devsize, files...)
}

// flashSuccessHint returns a per-variant next-step hint shown after a
// successful flash. variant is empty when the user passed --gaf
// directly. ejected reports whether we already released the disk (true
// on macOS after diskutil eject); when false, the message tells the
// user to eject it themselves.
func flashSuccessHint(diskPath, variant string, ejected bool) string {
	verb := "Eject"
	if ejected {
		verb = "Pull"
	}
	switch variant {
	case "pi-arm64":
		return fmt.Sprintf("%s %s and boot your Raspberry Pi.", verb, diskPath)
	case "vm-amd64":
		return fmt.Sprintf("%s %s and boot an x86_64 VM from it.", verb, diskPath)
	case "vm-arm64":
		return fmt.Sprintf("%s %s and boot an arm64 VM from it.", verb, diskPath)
	default:
		return fmt.Sprintf("%s %s and boot the target device.", verb, diskPath)
	}
}

// diskCandidate describes a flashable disk on the host.
type diskCandidate struct {
	Path        string // e.g. /dev/disk4 or /dev/sdb
	SizeBytes   int64
	Description string // human-readable model + size, e.g. "Generic MassStorage (62.5 GB)"
}

func (d diskCandidate) String() string {
	if d.Description != "" {
		return fmt.Sprintf("%s: %s", d.Path, d.Description)
	}
	return d.Path
}

// resolveTargetDisk returns the disk the user wants to flash. On macOS, an
// empty userDisk triggers auto-discovery. On Linux, userDisk is required and
// validated.
func resolveTargetDisk(ctx context.Context, userDisk string) (diskCandidate, error) {
	if userDisk != "" {
		if err := validateDiskPath(userDisk); err != nil {
			return diskCandidate{}, err
		}
		return diskCandidate{Path: userDisk}, nil
	}

	disks, err := discoverExternalDisks(ctx)
	if err != nil {
		return diskCandidate{}, err
	}
	switch len(disks) {
	case 0:
		return diskCandidate{}, errors.New("no candidate disks found; insert an SD card or USB drive, or pass --disk")
	case 1:
		printf("Found 1 candidate disk: %s\n", disks[0])
		return disks[0], nil
	default:
		printf("Multiple candidate disks found:\n")
		for i, d := range disks {
			printf("  %d) %s\n", i+1, d)
		}
		return diskCandidate{}, errors.New("pass --disk=/dev/... to pick one")
	}
}

// gafDownloadArgs are the inputs to [obtainGAF]. All fields are optional;
// zero values mean "download the latest and prompt/pick sensible defaults".
type gafDownloadArgs struct {
	localGAF string // if set, skip the network and use this local GAF path
	track    string // release track (empty → clientupdate.CurrentTrack)
	variant  string // GAF variant key (e.g. "vm-amd64"); empty prompts interactively
}

// obtainGAF returns a path to a local GAF file the caller can read,
// along with the appliance variant it corresponds to (empty for the
// --gaf path). If args.localGAF is set, the local file is returned
// directly. Otherwise the latest appliance GAF is fetched from
// pkgs.tailscale.com (with signature verification) into a temp file.
// cleanup removes any temp file it created.
func obtainGAF(ctx context.Context, args gafDownloadArgs) (path, label, variant string, cleanup func(), err error) {
	cleanup = func() {}
	if args.localGAF != "" {
		// With a local GAF there's no manifest to learn the variant
		// from, so we trust whatever variant the caller passed (may be
		// empty). rootArchForVariant defaults to arm64 when empty.
		return args.localGAF, args.localGAF, args.variant, cleanup, nil
	}

	track := args.track
	if track == "" {
		track = clientupdate.CurrentTrack
	}
	latest, err := clientupdate.LatestPackages(track)
	if err != nil {
		return "", "", "", cleanup, fmt.Errorf("fetching package manifest: %w", err)
	}
	if len(latest.GAFs) == 0 {
		return "", "", "", cleanup, fmt.Errorf("no appliance GAFs published on %q track", track)
	}

	variant, err = pickVariant(latest.GAFs, args.variant)
	if err != nil {
		return "", "", "", cleanup, err
	}
	gafName := latest.GAFs[variant]

	gafURL, err := url.JoinPath("https://pkgs.tailscale.com", track, gafName)
	if err != nil {
		return "", "", "", cleanup, err
	}

	tmp, err := os.CreateTemp("", "tailscale-flash-*.gaf")
	if err != nil {
		return "", "", "", cleanup, err
	}
	tmpName := tmp.Name()
	tmp.Close()
	cleanup = func() { os.Remove(tmpName) }

	printf("Downloading %s (version %s)\n", gafURL, latest.GAFsVersion)
	logf := func(format string, args ...any) { fmt.Fprintf(Stderr, format+"\n", args...) }
	if err := distsign.DownloadVerified(ctx, logf, gafURL, tmpName); err != nil {
		cleanup()
		return "", "", "", func() {}, fmt.Errorf("download GAF: %w", err)
	}
	return tmpName, fmt.Sprintf("%s (%s)", gafName, latest.GAFsVersion), variant, cleanup, nil
}

// pickVariant returns the variant key from gafs the user wants. If
// chosen is non-empty, it's validated against the available keys.
// Otherwise the caller is prompted to choose one on the next invocation.
func pickVariant(gafs map[string]string, chosen string) (string, error) {
	variants := make([]string, 0, len(gafs))
	for k := range gafs {
		variants = append(variants, k)
	}
	sort.Strings(variants)

	if chosen != "" {
		if !slices.Contains(variants, chosen) {
			return "", fmt.Errorf("variant %q not published; available: %s", chosen, strings.Join(variants, ", "))
		}
		return chosen, nil
	}

	printf("Available appliance variants:\n")
	for i, v := range variants {
		printf("  %d) %s\n", i+1, v)
	}
	return "", fmt.Errorf("pass --variant=<one of %s>", strings.Join(variants, "|"))
}

// readGAFMember returns the contents of a named member of the GAF zip.
// It returns an error if the member is missing or larger than maxBytes.
func readGAFMember(files []*zip.File, name string, maxBytes int64) ([]byte, error) {
	for _, f := range files {
		if f.Name != name {
			continue
		}
		if int64(f.UncompressedSize64) > maxBytes {
			return nil, fmt.Errorf("%s is %d bytes; refusing to read more than %d", name, f.UncompressedSize64, maxBytes)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}
	return nil, fmt.Errorf("GAF is missing %s", name)
}

// writeGAFToDisk writes a fresh gokrazy install to diskPath: the
// protective MBR (with bootCode in the first 446 bytes), the primary
// and secondary GPT, then boot.img at the boot partition's offset and
// root.img at root A's offset. Root B and perm are left untouched — the
// appliance populates root B on first boot, and the caller formats
// perm with mkfs.ext4.
func writeGAFToDisk(files []*zip.File, diskPath string, bootCode []byte, variant string) error {
	f, err := openBlockDevice(diskPath)
	if err != nil {
		return err
	}
	defer f.Close()

	devsize, err := blockDeviceSize(f)
	if err != nil {
		return fmt.Errorf("sizing %s: %w", diskPath, err)
	}
	if devsize <= 0 {
		return fmt.Errorf("could not determine size of %s", diskPath)
	}

	if err := writeApplianceImage(f, devsize, files, bootCode, variant); err != nil {
		return err
	}

	if err := syncBlockDevice(f); err != nil {
		return fmt.Errorf("fsync %s: %w", diskPath, err)
	}
	if err := rereadPartitionTable(f); err != nil {
		return fmt.Errorf("reread partition table: %w", err)
	}
	return nil
}

// writeApplianceImage writes the gokrazy install (protective MBR + GPT,
// boot.img, root.img) to f, whose usable size is devsize bytes. It does
// not fsync or reread the partition table; those are the caller's
// responsibility if targeting a block device.
//
// f is used for random-access seeks and writes and must already be sized
// to devsize (a fresh block device, or a regular file that the caller
// has truncated to devsize).
func writeApplianceImage(f *os.File, devsize int64, files []*zip.File, bootCode []byte, variant string) error {
	if len(bootCode) > 446 {
		return fmt.Errorf("mbr.img is %d bytes; expected at most 446", len(bootCode))
	}

	if err := checkPartitionFits(files, "boot.img", int64(disklayout.BootPartitionSizeMB)<<20); err != nil {
		return err
	}
	if err := checkPartitionFits(files, "root.img", int64(disklayout.RootPartitionSizeMB)<<20); err != nil {
		return err
	}

	bootImg, err := readGAFMember(files, "boot.img", int64(disklayout.BootPartitionSizeMB)<<20)
	if err != nil {
		return err
	}
	partUUID, err := partUUIDFromBootImg(bootImg)
	if err != nil {
		return fmt.Errorf("locating gokrazy partuuid in boot.img: %w", err)
	}

	printf("Writing protective MBR + GPT (partuuid=%08x, arch=%s)\n", partUUID, rootArchForVariant(variant))
	if err := disklayout.WriteGPT(f, uint64(devsize), disklayout.DefaultBootPartitionStartLBA, bootCode, partUUID, rootArchForVariant(variant)); err != nil {
		return fmt.Errorf("writing GPT: %w", err)
	}

	writes := []struct {
		member    string
		offsetLBA uint32
	}{
		{"boot.img", disklayout.BootStartLBA(disklayout.DefaultBootPartitionStartLBA)},
		{"root.img", disklayout.RootAStartLBA(disklayout.DefaultBootPartitionStartLBA)},
	}
	for _, w := range writes {
		zf := findZipMember(files, w.member)
		if zf == nil {
			return fmt.Errorf("GAF is missing %s", w.member)
		}
		printf("Writing %s (%d bytes) at sector %d\n", w.member, zf.UncompressedSize64, w.offsetLBA)
		if err := writeZipMemberAt(f, zf, int64(w.offsetLBA)*512); err != nil {
			return fmt.Errorf("writing %s: %w", w.member, err)
		}
	}
	return nil
}

// rootArchForVariant picks the GPT root partition type architecture
// based on the GAF variant key (e.g. "pi-arm64" → arm64).
func rootArchForVariant(variant string) disklayout.RootArch {
	switch {
	case strings.HasSuffix(variant, "-amd64"):
		return disklayout.ArchAMD64
	default:
		// pi-arm64, vm-arm64, or empty (--gaf path): arm64 is the
		// default for tailscale appliance images.
		return disklayout.ArchARM64
	}
}

// partUUIDFromBootImg returns the gokrazy per-disk partuuid embedded in
// boot.img's cmdline.txt. We byte-search the FAT image for the
// "PARTUUID=60c24cc1-..." pattern rather than parsing FAT, which is
// good enough since the only thing on disk with that prefix is
// cmdline.txt.
func partUUIDFromBootImg(boot []byte) (uint32, error) {
	return disklayout.ParseCmdlinePartUUID(string(boot))
}

// checkPartitionFits returns an error if the named GAF member is too
// large to fit in a partition of maxBytes.
func checkPartitionFits(files []*zip.File, name string, maxBytes int64) error {
	zf := findZipMember(files, name)
	if zf == nil {
		return fmt.Errorf("GAF is missing %s", name)
	}
	if got := int64(zf.UncompressedSize64); got > maxBytes {
		return fmt.Errorf("%s is %d bytes; gokrazy layout allows up to %d", name, got, maxBytes)
	}
	return nil
}

func findZipMember(files []*zip.File, name string) *zip.File {
	for _, f := range files {
		if f.Name == name {
			return f
		}
	}
	return nil
}

func writeZipMemberAt(f *os.File, zf *zip.File, offset int64) error {
	rc, err := zf.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return err
	}
	total := int64(zf.UncompressedSize64)
	cw := &progresstracking.CountingWriter{W: f}
	stop := progresstracking.Ticker(cw.Count, total, func(d, t int64) {
		pct := 0.0
		if t > 0 {
			pct = float64(d) * 100 / float64(t)
		}
		fmt.Fprintf(Stderr, "  %s: %s / %s (%.1f%%)\n", zf.Name, humanBytes(d), humanBytes(t), pct)
	})
	defer stop()
	_, err = io.Copy(cw, rc)
	return err
}

// humanBytes returns a friendly approximation of n bytes, e.g. "62.5 GB".
func humanBytes(n int64) string {
	const (
		gb = 1 << 30
		mb = 1 << 20
		kb = 1 << 10
	)
	switch {
	case n >= gb:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(gb))
	case n >= mb:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(mb))
	case n >= kb:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(kb))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
