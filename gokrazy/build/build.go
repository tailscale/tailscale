// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package build builds the Tailscale Appliance Gokrazy image and,
// optionally, an AWS AMI from it.
//
// It is the reusable core behind the gokrazy/build.go command: a
// [Builder] runs monogok to produce a disk image (or GAF), formats the
// ext4 /perm filesystem via gokrazy/mkfs, and can then upload the image
// to S3 and register an AMI by shelling out to the "aws" CLI. Callers
// that only want the image (e.g. flash-appliance tooling) can call
// [Builder.BuildImage] alone.
//
// Tracking issue is https://github.com/tailscale/tailscale/issues/1866
package build

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"tailscale.com/gokrazy/mkfs"
	"tailscale.com/types/logger"
)

// Result is the machine-readable outcome of a build. Fields are
// populated as the run progresses; per docs/cli.md, existing fields
// keep their meaning and consumers must tolerate new ones.
type Result struct {
	App      string `json:"app"`
	Arch     string `json:"arch"`
	Name     string `json:"name,omitempty"`
	Image    string `json:"image,omitempty"`
	GAF      string `json:"gaf,omitempty"`
	Region   string `json:"region,omitempty"`
	Snapshot string `json:"snapshot,omitempty"`
	AMI      string `json:"ami,omitempty"`
	// Error is the error that ended the build, if any. It lets --json
	// consumers see why a run failed rather than only its exit code.
	Error string `json:"error,omitempty"`
}

// Config configures a [Builder]. Only App is required; New fills in the
// rest with defaults. It holds build inputs only; what to produce is
// chosen by which build method you call ([Builder.BuildImage],
// [Builder.BuildGAF], or [Builder.BuildAMI]).
type Config struct {
	// App is the appliance name, e.g. "tsapp". It must be a
	// subdirectory of Dir containing a config.json.
	App string
	// Dir is the directory holding the appliance subdirectories.
	// Empty means the current working directory.
	Dir string
	// Bucket is the S3 bucket that BuildAMI uploads the disk image to
	// while registering the AMI. Unused by BuildImage and BuildGAF.
	Bucket string
	// Region is the AWS region BuildAMI imports and registers in. Empty
	// means ResolveRegion("", $AWS_REGION).
	Region string

	// Logf receives human-readable progress. If nil, log.Printf is used.
	Logf logger.Logf
	// Stderr receives the output of subprocesses (monogok, aws). If nil,
	// os.Stderr is used. Keeping this off stdout lets callers reserve
	// stdout for machine-readable output.
	Stderr io.Writer
}

// Builder builds one appliance image, GAF, or AMI per its Config.
// Create one with [New]; it is not safe for concurrent use.
type Builder struct {
	Config

	conf gokrazyConfig // parsed <Dir>/<App>/config.json
	res  Result
}

// baseImageSizeBytes is the size of the disk image we ask monogok to
// produce (and that the AWS AMI import expects). It has to be large
// enough to fit gokrazy's standard partition layout (see
// github.com/bradfitz/monogok/disklayout):
//
//	  4 MiB gap before the first partition
//	100 MiB boot      (FAT)
//	500 MiB root A    (squashfs; the partition OTA updates write into)
//	500 MiB root B    (squashfs)
//	 ~96 MiB /perm    (ext4; rest of the disk minus the secondary GPT)
//
// Bump this to give /perm more room (and to make the produced .img
// file larger). The same value is passed to monogok via
// --target_storage_bytes and to mkfs.Perm so the GPT and the ext4
// inside it agree on the disk's size.
//
// imageSizeBytesFor may round this up; callers should use that helper
// instead of this constant.
const baseImageSizeBytes = 1258299392

// gokrazyConfig is the subset of gokrazy/internal/config.Struct
// that we care about.
type gokrazyConfig struct {
	// Environment is os.Environment pairs to use when
	// building userspace.
	// See https://gokrazy.org/userguide/instance-config/#environment
	Environment []string
}

func (c *gokrazyConfig) GOARCH() string {
	for _, e := range c.Environment {
		if v, ok := strings.CutPrefix(e, "GOARCH="); ok {
			return v
		}
	}
	return ""
}

// New validates cfg, fills in defaults, reads and parses
// <Dir>/<App>/config.json, and validates its GOARCH.
func New(cfg Config) (*Builder, error) {
	if cfg.App == "" || strings.Contains(cfg.App, "/") {
		return nil, fmt.Errorf("App must be a non-empty name such as 'tsapp' or 'natlabapp'; got %q", cfg.App)
	}
	if cfg.Dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		cfg.Dir = wd
	}
	if cfg.Region == "" {
		cfg.Region = ResolveRegion("", os.Getenv("AWS_REGION"))
	}
	if cfg.Stderr == nil {
		cfg.Stderr = os.Stderr
	}

	b := &Builder{Config: cfg}

	confJSON, err := os.ReadFile(filepath.Join(cfg.Dir, cfg.App, "config.json"))
	if err != nil {
		return nil, fmt.Errorf("reading config.json: %w", err)
	}
	if err := json.Unmarshal(confJSON, &b.conf); err != nil {
		return nil, fmt.Errorf("unmarshaling config.json: %w", err)
	}
	switch b.conf.GOARCH() {
	case "amd64", "arm64":
	default:
		return nil, fmt.Errorf("config.json GOARCH %q must be amd64 or arm64", b.conf.GOARCH())
	}

	b.res.App = cfg.App
	b.res.Arch = awsArch(b.conf.GOARCH())
	return b, nil
}

// Result returns the current result. It is fully populated after a
// successful Build; individual steps fill in their fields as they run,
// and Result.Error records the error that ended a failed run.
func (b *Builder) Result() Result { return b.res }

// fail records err in the result and returns it, so callers that read
// Result() after a failed step (e.g. to emit --json) see why it failed.
func (b *Builder) fail(err error) error {
	b.res.Error = err.Error()
	return err
}

// logf logs progress via b.Logf, or log.Printf if unset.
func (b *Builder) logf(format string, args ...any) {
	if b.Logf != nil {
		b.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// BuildImage runs monogok to produce a full disk image (.img) and
// formats its ext4 /perm filesystem. It returns the image path and sets
// Result.Image. This is the local artifact that BuildAMI publishes and
// that flash-appliance tooling writes to disk.
func (b *Builder) BuildImage(ctx context.Context) (string, error) {
	if err := b.buildImage(ctx, false); err != nil {
		return "", b.fail(fmt.Errorf("build image: %w", err))
	}
	return b.res.Image, nil
}

// BuildGAF runs monogok to produce a gokrazy archive format file (.gaf),
// the OTA update artifact. It returns the GAF path and sets Result.GAF.
// A GAF is an update archive, not a full disk, so it cannot be turned
// into an AMI.
func (b *Builder) BuildGAF(ctx context.Context) (string, error) {
	if err := b.buildImage(ctx, true); err != nil {
		return "", b.fail(fmt.Errorf("build GAF: %w", err))
	}
	return b.res.GAF, nil
}

// BuildAMI builds a full disk image and publishes it as an AWS AMI:
// upload to S3, import an EBS snapshot, and register the image. It
// returns the populated Result. Config.Bucket and Config.Region select
// where the AMI is built.
func (b *Builder) BuildAMI(ctx context.Context) (Result, error) {
	if _, err := b.BuildImage(ctx); err != nil {
		return b.res, err // BuildImage already wrapped+recorded it
	}

	if err := b.uploadToS3(ctx); err != nil {
		return b.res, b.fail(fmt.Errorf("copy to S3: %w", err))
	}
	snapID, err := b.importSnapshot(ctx)
	if err != nil {
		return b.res, b.fail(fmt.Errorf("import snapshot: %w", err))
	}
	b.logf("snap ID: %v", snapID)

	if err := b.registerAMI(ctx, snapID); err != nil {
		return b.res, b.fail(fmt.Errorf("register AMI: %w", err))
	}
	b.logf("made AMI: %v", b.res.AMI)
	return b.res, nil
}

// buildImage runs monogok to produce the disk image (or GAF when gaf is
// set) and, for a full image, formats the ext4 /perm filesystem. It sets
// res.Image or res.GAF.
func (b *Builder) buildImage(ctx context.Context, gaf bool) error {
	appDir := filepath.Join(b.Dir, b.App)
	if fi, err := os.Stat(appDir); err != nil || !fi.IsDir() {
		return fmt.Errorf("in wrong directory %v; no %q subdirectory found", b.Dir, b.App)
	}

	args := []string{"run", "github.com/bradfitz/monogok/cmd/monogok"}
	if gaf {
		args = append(args,
			"overwrite",
			"--gaf", filepath.Join(b.Dir, b.App+".gaf"),
		)
	} else {
		args = append(args,
			"overwrite",
			"--full", filepath.Join(b.Dir, b.App+".img"),
			fmt.Sprintf("--target_storage_bytes=%d", imageSizeBytesFor(b.App)),
		)
	}

	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = appDir
	cmd.Stdout = b.Stderr
	cmd.Stderr = b.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	if gaf {
		b.res.GAF = filepath.Join(b.Dir, b.App+".gaf")
		return nil
	}

	imgPath := filepath.Join(b.Dir, b.App+".img")
	f, err := os.OpenFile(imgPath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", imgPath, err)
	}
	defer f.Close()
	if err := mkfs.Perm(f, imageSizeBytesFor(b.App)); err != nil {
		return fmt.Errorf("formatting /perm in %s: %v", imgPath, err)
	}
	b.logf("Wrote ext4 /perm filesystem to %s.", imgPath)
	b.res.Image = imgPath
	return nil
}

// uploadToS3 uploads the built .img to s3://<Bucket>/.
func (b *Builder) uploadToS3(ctx context.Context) error {
	cmd := b.awsCmd(ctx, "s3", "cp", b.App+".img", "s3://"+b.Bucket+"/")
	cmd.Dir = b.Dir
	cmd.Stdout = b.Stderr
	cmd.Stderr = b.Stderr
	return cmd.Run()
}

// importSnapshot starts an EC2 import-snapshot task from the uploaded
// image and waits for it to complete, returning the EBS snapshot ID. It
// sets res.Snapshot and res.Region.
func (b *Builder) importSnapshot(ctx context.Context) (string, error) {
	taskID, err := b.startImportSnapshot(ctx)
	if err != nil {
		return "", err
	}
	snapID, err := b.waitForImportSnapshot(ctx, taskID)
	if err != nil {
		return "", fmt.Errorf("waitForImportSnapshot(%v): %w", taskID, err)
	}
	b.res.Snapshot = snapID
	b.res.Region = b.Region
	return snapID, nil
}

func (b *Builder) startImportSnapshot(ctx context.Context) (importTaskID string, err error) {
	out, err := b.awsCmd(ctx, "ec2", "import-snapshot", "--disk-container", "Url=s3://"+b.Bucket+"/"+b.App+".img").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("import snapshot: %v: %s", err, out)
	}
	var resp struct {
		ImportTaskID string `json:"ImportTaskId"`
	}
	/*
		{
			"ImportTaskId": "import-snap-0d2d72622b4359567",
			"SnapshotTaskDetail": {
				"DiskImageSize": 0.0,
				"Progress": "0",
				"Status": "active",
				"StatusMessage": "pending",
				"Url": "s3://tskrazy-import/tskrazy.img"
			},
			"Tags": []
		}
	*/
	if err := json.Unmarshal(out, &resp); err != nil {
		return "", fmt.Errorf("unmarshal response: %v: %s", err, out)
	}
	return resp.ImportTaskID, nil
}

/*
% aws ec2 describe-import-snapshot-tasks --import-task-ids import-snap-0d2d72622b4359567
{
    "ImportSnapshotTasks": [
        {
            "ImportTaskId": "import-snap-0d2d72622b4359567",
            "SnapshotTaskDetail": {
                "DiskImageSize": 1258299392.0,
                "Format": "RAW",
                "SnapshotId": "snap-053efd3539d787927",
                "Status": "completed",
                "Url": "s3://tskrazy-import/tskrazy.img",
                "UserBucket": {
                    "S3Bucket": "tskrazy-import",
                    "S3Key": "tskrazy.img"
                }
            },
            "Tags": []
        }
    ]
}
*/

func (b *Builder) waitForImportSnapshot(ctx context.Context, importTaskID string) (snapID string, err error) {
	interactive := isTerminal(b.Stderr)
	var lastPhase string // last (status/message) reported in non-interactive mode
	for {
		out, err := b.awsCmd(ctx, "ec2", "describe-import-snapshot-tasks", "--import-task-ids", importTaskID).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("describe import snapshot tasks: %v: %s", err, out)
		}

		var resp struct {
			ImportSnapshotTasks []struct {
				SnapshotTaskDetail struct {
					SnapshotID    string `json:"SnapshotId"`
					Status        string `json:"Status"`
					StatusMessage string `json:"StatusMessage"`
					Progress      string `json:"Progress"`
				} `json:"SnapshotTaskDetail"`
			} `json:"ImportSnapshotTasks"`
		}
		if err := json.Unmarshal(out, &resp); err != nil {
			return "", fmt.Errorf("unmarshal response: %v: %s", err, out)
		}
		var d struct {
			SnapshotID    string `json:"SnapshotId"`
			Status        string `json:"Status"`
			StatusMessage string `json:"StatusMessage"`
			Progress      string `json:"Progress"`
		}
		if len(resp.ImportSnapshotTasks) > 0 {
			d = resp.ImportSnapshotTasks[0].SnapshotTaskDetail
		}
		if d.Status == "completed" {
			if interactive {
				fmt.Fprintln(b.Stderr) // move off the live progress line
			}
			return d.SnapshotID, nil
		}

		if interactive {
			// Repaint one line in place each poll.
			fmt.Fprintf(b.Stderr, "\r\x1b[K%s", importProgressLine(d.Status, d.StatusMessage, d.Progress))
		} else if phase := d.Status + "/" + d.StatusMessage; phase != lastPhase {
			// Non-interactive (CI, pipe): one line per phase change only,
			// not a fresh line every poll.
			lastPhase = phase
			b.logf("%s", importProgressLine(d.Status, d.StatusMessage, d.Progress))
		}

		select {
		case <-ctx.Done():
			if interactive {
				fmt.Fprintln(b.Stderr)
			}
			return "", ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// registerAMI registers an AMI from the given EBS snapshot. The AMI name
// is derived from git via AMIName. It sets res.Name and res.AMI.
func (b *Builder) registerAMI(ctx context.Context, ebsSnapID string) error {
	b.res.Name = AMIName(b.App, b.Dir)

	var arch, bootMode string
	switch b.conf.GOARCH() {
	case "arm64":
		// arm64 instances boot UEFI-only; "uefi-preferred" is rejected.
		arch, bootMode = "arm64", "uefi"
	case "amd64":
		arch, bootMode = "x86_64", "uefi-preferred"
	default:
		return fmt.Errorf("unknown arch %q", b.conf.GOARCH())
	}
	out, err := b.awsCmd(ctx, "ec2", "register-image",
		"--name", b.res.Name,
		"--architecture", arch,
		// register-image defaults to paravirtual; arm64 rejects that
		// ("supports HVM AMIs only") and amd64 would produce an image that
		// won't boot on Nitro. Both need HVM.
		"--virtualization-type", "hvm",
		"--root-device-name", "/dev/sda1",
		"--ena-support",
		"--imds-support", "v2.0",
		"--boot-mode", bootMode,
		"--block-device-mappings", "DeviceName=/dev/sda1,Ebs={SnapshotId="+ebsSnapID+"}").CombinedOutput()
	if err != nil {
		return fmt.Errorf("register image: %v: %s", err, out)
	}
	/*
		On success:
		{
		    "ImageId": "ami-052e1538166886ad2"
		}
	*/
	var resp struct {
		ImageID string `json:"ImageId"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return fmt.Errorf("unmarshal response: %v: %s", err, out)
	}
	if resp.ImageID == "" {
		return fmt.Errorf("empty image ID in response: %s", out)
	}
	b.res.AMI = resp.ImageID
	return nil
}

// awsCmd builds an aws command with the resolved --region prepended so
// every call targets the same region deterministically.
func (b *Builder) awsCmd(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "aws", append([]string{"--region", b.Region}, args...)...)
}

// imageSizeBytesFor returns the disk image size to use for app. For Raspberry
// Pi appliances the size is rounded up to the next power of two because
// qemu-system-aarch64's raspi3b machine rejects SD card images whose size
// isn't a power of two.
func imageSizeBytesFor(app string) int64 {
	if !strings.HasPrefix(app, "tsapp-pi.") {
		return baseImageSizeBytes
	}
	n := int64(1)
	for n < baseImageSizeBytes {
		n <<= 1
	}
	return n
}

// importProgressLine formats a one-line status for an in-progress EC2
// import-snapshot task from its Status, StatusMessage, and Progress (a
// percentage string like "32") fields, any of which may be empty early on.
func importProgressLine(status, statusMessage, progress string) string {
	msg := statusMessage
	if msg == "" {
		msg = status
	}
	if msg == "" {
		msg = "pending"
	}
	if progress == "" {
		return "importing snapshot: " + msg
	}
	return fmt.Sprintf("importing snapshot: %s%% (%s)", progress, msg)
}

// isTerminal reports whether w writes to an interactive terminal, so
// callers can show a live-updating progress line instead of a stream of
// separate log lines.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && isatty.IsTerminal(f.Fd())
}

// awsArch maps a Go GOARCH to the AWS EC2 --architecture value.
func awsArch(goarch string) string {
	switch goarch {
	case "arm64":
		return "arm64"
	case "amd64":
		return "x86_64"
	}
	return ""
}

// ResolveRegion picks the AWS region: an explicit flagVal wins, then
// env ($AWS_REGION), then us-east-1 (where the Marketplace Catalog API
// and its source AMI live).
func ResolveRegion(flagVal, env string) string {
	if flagVal != "" {
		return flagVal
	}
	if env != "" {
		return env
	}
	return "us-east-1"
}

// AMIName returns a deterministic AMI name derived from git, running git
// in dir: on a tagged commit it's <app>-<tag> (releases); otherwise
// <app>-<git describe>-<unixtime> for ad-hoc builds. If git is
// unavailable it falls back to <app>-<unixtime>.
func AMIName(app, dir string) string {
	exact, _ := gitOutput(dir, "describe", "--exact-match", "--tags", "HEAD")
	describe, _ := gitOutput(dir, "describe", "--tags", "--always", "--dirty")
	return amiNameFrom(app, exact, describe, time.Now().Unix())
}

// amiNameFrom is the pure decision behind AMIName, split out for testing.
func amiNameFrom(app, exactTag, describe string, now int64) string {
	if exactTag != "" {
		return app + "-" + exactTag
	}
	if describe != "" {
		return fmt.Sprintf("%s-%s-%d", app, describe, now)
	}
	return fmt.Sprintf("%s-%d", app, now)
}

// gitOutput runs git with args in dir and returns trimmed stdout, or an
// error (e.g. no git, not a repo, or the ref doesn't match).
func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
