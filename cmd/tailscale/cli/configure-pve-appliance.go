// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_flashappliance

package cli

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/clientupdate"
	"tailscale.com/gokrazy/mkfs"
	"tailscale.com/util/prompt"
)

var pveApplianceArgs struct {
	vmid                 int
	name                 string
	storage              string
	diskSize             string
	cores                int
	memory               int
	bridge               string
	variant              string
	track                string
	gaf                  string
	addSSHAuthorizedKeys string
	start                bool
	yes                  bool
}

func pveApplianceCmd() *ffcli.Command {
	return &ffcli.Command{
		Name:       "pve-appliance",
		ShortUsage: "tailscale configure pve-appliance --storage=<name> [flags]",
		ShortHelp:  "Create a Proxmox VE VM running the Tailscale appliance image [experimental]",
		LongHelp: hidden + strings.TrimSpace(`
This experimental command downloads a signed Tailscale appliance GAF from
pkgs.tailscale.com, builds a raw disk image in /var/tmp, then invokes
'qm create' / 'qm disk import' / 'qm set' on the local Proxmox VE host to
create a new VM backed by that image. It must be run on the PVE host
itself (where the 'qm' CLI is available).

The imported disk is attached as scsi0 on a virtio-scsi-single controller
with iothread, the network attaches to the given bridge (default vmbr0),
and the guest agent is enabled — pair with the appliance's built-in
qemu-guest-kragent so PVE can see the guest's IPs.

The VM is created with a virtio-serial console (--serial0 socket). Once
the VM is running, 'qm terminal <vmid>' on the PVE host — then press
Enter — drops you into a busybox shell inside the appliance without
needing an SSH key.

Defaults are chosen so a bare invocation like:

    tailscale configure pve-appliance --storage=local-lvm

is enough to produce a bootable Tailscale appliance VM.
`),
		FlagSet: (func() *flag.FlagSet {
			fs := newFlagSet("pve-appliance")
			fs.IntVar(&pveApplianceArgs.vmid, "vmid", 0, "target VM ID; 0 asks Proxmox for the next available ID")
			fs.StringVar(&pveApplianceArgs.name, "name", "", `VM name; defaults to "tsapp-<vmid>"`)
			fs.StringVar(&pveApplianceArgs.storage, "storage", "", "PVE storage to import the disk into (e.g. local-lvm, ssd2); required")
			fs.StringVar(&pveApplianceArgs.diskSize, "disk-size", "4G", "raw image size (accepts K/M/G suffixes, e.g. 4G, 8192M)")
			fs.IntVar(&pveApplianceArgs.cores, "cores", 2, "vCPU cores")
			fs.IntVar(&pveApplianceArgs.memory, "memory", 1024, "memory in MiB")
			fs.StringVar(&pveApplianceArgs.bridge, "bridge", "vmbr0", "network bridge to attach virtio net0 to")
			fs.StringVar(&pveApplianceArgs.variant, "variant", "vm-amd64", `appliance variant: "vm-amd64" or "vm-arm64"`)
			fs.StringVar(&pveApplianceArgs.track, "track", "", `which track to download from; defaults to "`+clientupdate.CurrentTrack+`"`)
			fs.StringVar(&pveApplianceArgs.gaf, "gaf", "", "use a local GAF file instead of downloading (skips signature verification)")
			fs.StringVar(&pveApplianceArgs.addSSHAuthorizedKeys, "add-ssh-authorized-keys", "", "path to an authorized_keys file to include on the appliance for breakglass SSH access")
			fs.BoolVar(&pveApplianceArgs.start, "start", true, "start the VM after import")
			fs.BoolVar(&pveApplianceArgs.yes, "yes", false, "skip the confirmation prompt")
			return fs
		})(),
		Exec: runPVEAppliance,
	}
}

func runPVEAppliance(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unknown arguments")
	}
	if runtime.GOOS != "linux" {
		return errors.New("the pve-appliance subcommand is only available on Linux; for use on Proxmox PVE hosts")
	}
	if fi, err := os.Stat("/etc/pve"); err != nil || !fi.IsDir() {
		return errors.New("/etc/pve is not a directory: run this on a Proxmox VE host")
	}
	if _, err := exec.LookPath("qm"); err != nil {
		return errors.New("`qm` not found in $PATH: run this on the Proxmox VE host")
	}
	if pveApplianceArgs.storage == "" {
		return errors.New("--storage is required (e.g. --storage=local-lvm)")
	}

	diskBytes, err := parseSizeBytes(pveApplianceArgs.diskSize)
	if err != nil {
		return fmt.Errorf("parsing --disk-size: %w", err)
	}

	vmid := pveApplianceArgs.vmid
	if vmid == 0 {
		vmid, err = pveNextID(ctx)
		if err != nil {
			return fmt.Errorf("fetching next VMID: %w", err)
		}
	}
	name := pveApplianceArgs.name
	if name == "" {
		name = fmt.Sprintf("tsapp-%d", vmid)
	}

	gafPath, gafLabel, variant, cleanup, err := obtainGAF(ctx, gafDownloadArgs{
		localGAF: pveApplianceArgs.gaf,
		track:    pveApplianceArgs.track,
		variant:  pveApplianceArgs.variant,
	})
	if err != nil {
		return err
	}
	defer cleanup()

	if !pveApplianceArgs.yes {
		printf("About to create Proxmox VM %d (%q) on storage %q from %s\n",
			vmid, name, pveApplianceArgs.storage, gafLabel)
		printf("  cores=%d memory=%dMiB bridge=%s disk=%s start=%v\n",
			pveApplianceArgs.cores, pveApplianceArgs.memory,
			pveApplianceArgs.bridge, pveApplianceArgs.diskSize, pveApplianceArgs.start)
		if !prompt.YesNo("Proceed?", false) {
			return errors.New("aborted")
		}
	}

	imgPath, err := buildPVERawImage(gafPath, diskBytes, variant)
	if err != nil {
		return err
	}
	defer os.Remove(imgPath)

	if err := createPVEVM(ctx, vmid, name); err != nil {
		return fmt.Errorf("qm create: %w", err)
	}
	diskRef, err := importPVEDisk(ctx, vmid, pveApplianceArgs.storage, imgPath)
	if err != nil {
		return fmt.Errorf("qm disk import: %w", err)
	}
	if err := attachPVEDisk(ctx, vmid, diskRef); err != nil {
		return fmt.Errorf("qm set: %w", err)
	}

	if pveApplianceArgs.start {
		if err := runQM(ctx, "start", strconv.Itoa(vmid)); err != nil {
			return fmt.Errorf("qm start: %w", err)
		}
		printf("VM %d started.\n", vmid)
	} else {
		printf("VM %d created; not started (pass --start to auto-start).\n", vmid)
	}
	return nil
}

// buildPVERawImage creates a sparse raw disk image in /var/tmp and
// writes the GAF's boot + root images to it plus a fresh /perm ext4
// filesystem. The returned path is the caller's to remove.
func buildPVERawImage(gafPath string, devsize int64, variant string) (string, error) {
	zr, err := zip.OpenReader(gafPath)
	if err != nil {
		return "", fmt.Errorf("open GAF: %w", err)
	}
	defer zr.Close()

	bootCode, err := readGAFMember(zr.File, "mbr.img", 1<<20)
	if err != nil {
		return "", err
	}

	tmp, err := os.CreateTemp("/var/tmp", "tsapp-pve-*.raw")
	if err != nil {
		return "", err
	}
	imgPath := tmp.Name()
	if err := tmp.Truncate(devsize); err != nil {
		tmp.Close()
		os.Remove(imgPath)
		return "", fmt.Errorf("truncate: %w", err)
	}

	if err := writeApplianceImage(tmp, devsize, zr.File, bootCode, variant); err != nil {
		tmp.Close()
		os.Remove(imgPath)
		return "", err
	}

	var permFiles []mkfs.PermFile
	if k := pveApplianceArgs.addSSHAuthorizedKeys; k != "" {
		keys, err := os.ReadFile(k)
		if err != nil {
			tmp.Close()
			os.Remove(imgPath)
			return "", fmt.Errorf("reading --add-ssh-authorized-keys: %w", err)
		}
		permFiles = append(permFiles, mkfs.PermFile{
			Path:    "breakglass.authorized_keys",
			Content: keys,
		})
		printf("Including SSH authorized_keys for breakglass access.\n")
	}
	if err := mkfs.Perm(tmp, devsize, permFiles...); err != nil {
		tmp.Close()
		os.Remove(imgPath)
		return "", fmt.Errorf("formatting perm: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(imgPath)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(imgPath)
		return "", err
	}
	return imgPath, nil
}

// pveNextID asks Proxmox for the next unused VMID via pvesh.
func pveNextID(ctx context.Context) (int, error) {
	out, err := exec.CommandContext(ctx, "pvesh", "get", "/cluster/nextid").Output()
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(out))
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("parsing pvesh output %q: %w", s, err)
	}
	return n, nil
}

func createPVEVM(ctx context.Context, vmid int, name string) error {
	return runQM(ctx, "create", strconv.Itoa(vmid),
		"--name", name,
		"--memory", strconv.Itoa(pveApplianceArgs.memory),
		"--cores", strconv.Itoa(pveApplianceArgs.cores),
		"--net0", "virtio,bridge="+pveApplianceArgs.bridge,
		"--scsihw", "virtio-scsi-single",
		"--serial0", "socket",
		"--agent", "1",
		"--ostype", "l26",
		"--tablet", "0",
		"--vga", "virtio",
		"--description", vmNotes(vmid),
	)
}

// vmNotes is the description shown in the PVE web UI's "Notes" panel
// for VMs we create. It tells admins the two ways to get into the
// appliance without needing an SSH key: the framebuffer console (press
// Esc for a shell) and the serial console (qm terminal).
func vmNotes(vmid int) string {
	return fmt.Sprintf(`# Tailscale appliance [experimental]

Admin access to this VM (no SSH key required):

- **Framebuffer / NoVNC console**: press **Esc** on the enrollment screen
  to drop into a busybox shell. Type `+"`exit`"+` to return to the
  Tailscale status display.

- **Serial console**: on this Proxmox host, run

      qm terminal %d

  then press **Enter** to get a busybox shell. Press **Ctrl+O** to
  detach from `+"`qm terminal`"+` (leaves the guest shell alive).

Inside either shell, run `+"`tailscale`"+` commands as usual
(`+"`tailscale up`"+`, `+"`tailscale status`"+`, etc.).
`, vmid)
}

// importPVEDisk imports src into storage on vmid and returns the
// Proxmox volume reference of the newly-imported disk (e.g.
// "local-lvm:vm-102-disk-0").
//
// The stdout of "qm disk import" isn't a stable API across Proxmox
// versions — historically it has printed variants like
// "vm-<vmid>-disk-<N>" and "importing disk … as <volid>", and the
// allocated volume name isn't always vm-<vmid>-disk-0 (e.g. if a
// stale volume with that name exists on the storage from a prior
// VM). We instead diff the VM config before and after the import
// and pick out the newly-added unusedN entry, which holds the real
// volume ref.
func importPVEDisk(ctx context.Context, vmid int, storage, src string) (volume string, err error) {
	before, err := pveVMConfig(ctx, vmid)
	if err != nil {
		return "", fmt.Errorf("reading VM %d config: %w", vmid, err)
	}
	if err := runQM(ctx, "disk", "import", strconv.Itoa(vmid), src, storage, "--format", "raw"); err != nil {
		return "", err
	}
	after, err := pveVMConfig(ctx, vmid)
	if err != nil {
		return "", fmt.Errorf("reading VM %d config after import: %w", vmid, err)
	}
	for k, v := range after {
		if !strings.HasPrefix(k, "unused") {
			continue
		}
		if before[k] == v {
			continue
		}
		return v, nil
	}
	return "", fmt.Errorf("qm disk import didn't add an unusedN entry to VM %d config", vmid)
}

// pveVMConfig returns the current runtime config for vmid on the local
// PVE node, as a flat key → string map. We ask pvesh for JSON since
// "qm config" text output has evolved over releases.
func pveVMConfig(ctx context.Context, vmid int) (map[string]string, error) {
	node, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	out, err := exec.CommandContext(ctx, "pvesh", "get",
		fmt.Sprintf("/nodes/%s/qemu/%d/config", node, vmid),
		"--output-format", "json").Output()
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("parsing pvesh JSON: %w", err)
	}
	m := make(map[string]string, len(raw))
	for k, v := range raw {
		switch v := v.(type) {
		case string:
			m[k] = v
		case float64:
			m[k] = strconv.FormatFloat(v, 'f', -1, 64)
		case bool:
			m[k] = strconv.FormatBool(v)
		}
	}
	return m, nil
}

func attachPVEDisk(ctx context.Context, vmid int, diskRef string) error {
	return runQM(ctx, "set", strconv.Itoa(vmid),
		"--scsi0", diskRef+",iothread=1",
		"--boot", "order=scsi0",
	)
}

// runQM invokes `qm` with args, streaming its output to Stderr so the
// caller can see disk-import progress and any error messages.
func runQM(ctx context.Context, args ...string) error {
	printf("$ qm %s\n", strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, "qm", args...)
	cmd.Stdout = Stderr
	cmd.Stderr = Stderr
	return cmd.Run()
}

// parseSizeBytes parses a size string like "4G", "8192M", "1024K", or
// "12345" (bytes) into a byte count. Empty string returns an error.
func parseSizeBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty size")
	}
	mult := int64(1)
	switch last := s[len(s)-1]; {
	case last >= '0' && last <= '9':
		// no suffix
	default:
		switch last {
		case 'K', 'k':
			mult = 1 << 10
		case 'M', 'm':
			mult = 1 << 20
		case 'G', 'g':
			mult = 1 << 30
		case 'T', 't':
			mult = 1 << 40
		default:
			return 0, fmt.Errorf("unknown size suffix %q", string(last))
		}
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if n <= 0 {
		return 0, fmt.Errorf("size %d must be positive", n)
	}
	return n * mult, nil
}
