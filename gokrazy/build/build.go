// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package build builds the Tailscale Appliance Gokrazy image and,
// optionally, an AWS AMI from it.
//
// It is the reusable core behind the gokrazy/build.go command: a
// [Builder] runs monogok to produce a disk image (or GAF), formats the
// ext4 /perm filesystem via gokrazy/mkfs, and can then upload the image
// to S3 and register an AMI using the AWS SDK for Go v2. Credentials are
// resolved via the SDK's default chain (the same sources the "aws" CLI
// uses: env vars, ~/.aws, SSO cache, IMDS). Callers that only want the
// image (e.g. flash-appliance tooling) can call [Builder.BuildImage]
// alone.
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/mattn/go-isatty"
	"tailscale.com/gokrazy/mkfs"
	tsrate "tailscale.com/tstime/rate"
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
	S3       string `json:"s3,omitempty"` // s3:// URI of the uploaded image
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
// [Builder.BuildGAF], or [Builder.BuildAndImportAMI]).
type Config struct {
	// App is the appliance name, e.g. "tsapp". It must be a
	// subdirectory of Dir containing a config.json.
	App string
	// Dir is the directory holding the appliance subdirectories.
	// Empty means the current working directory.
	Dir string
	// Bucket is the S3 bucket that BuildAndImportAMI uploads the disk
	// image to while registering the AMI. Unused by BuildImage and
	// BuildGAF.
	Bucket string
	// Region is the AWS region BuildAndImportAMI imports and registers
	// in. Empty means ResolveRegion("", $AWS_REGION).
	Region string

	// Logf receives human-readable progress. If nil, log.Printf is used.
	Logf logger.Logf
	// Stderr receives the output of subprocesses (monogok). If nil,
	// os.Stderr is used. Keeping this off stdout lets callers reserve
	// stdout for machine-readable output.
	Stderr io.Writer
}

// Builder builds one appliance image, GAF, or AMI per its Config.
// Create one with [New]; it is not safe for concurrent use.
//
// The build steps are stateful and ordered: each records its output into
// the Result (read with [Builder.Result]) and the AWS steps verify their
// predecessor ran — by checking the Result field it populated — erroring
// clearly if called out of order. The order is BuildImage → UploadToS3 →
// ImportSnapshot → RegisterAMI.
type Builder struct {
	Config

	conf gokrazyConfig // parsed <Dir>/<App>/config.json
	res  Result

	// s3c and ec2c are lazily created by awsClients on first use and
	// cached; they're nil until then.
	s3c  *s3.Client
	ec2c *ec2.Client
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

// New validates cfg, applies defaults, and loads <Dir>/<App>/config.json.
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

// Result returns the result so far: each step fills its fields as it
// runs, and Result.Error holds the error that ended a failed run.
func (b *Builder) Result() Result { return b.res }

// fail records err in Result.Error so a caller reading Result() after a
// failed step (e.g. to emit --json) still sees why it failed.
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

// BuildImage runs monogok to produce a full disk image (.img) with a
// formatted ext4 /perm, returning its path (also in Result.Image). It's
// the artifact BuildAndImportAMI publishes and flash-appliance flashes.
func (b *Builder) BuildImage(ctx context.Context) (imagePath string, err error) {
	if err := b.buildImage(ctx, false); err != nil {
		return "", b.fail(fmt.Errorf("build image: %w", err))
	}
	return b.res.Image, nil
}

// BuildGAF runs monogok to produce a GAF (gokrazy archive format) OTA
// update file, returning its path (also in Result.GAF). A GAF is an
// update archive, not a full disk, so it can't be turned into an AMI.
func (b *Builder) BuildGAF(ctx context.Context) (gafPath string, err error) {
	if err := b.buildImage(ctx, true); err != nil {
		return "", b.fail(fmt.Errorf("build GAF: %w", err))
	}
	return b.res.GAF, nil
}

// BuildAndImportAMI runs the whole pipeline (build image, upload, import
// snapshot, register AMI) and returns the populated Result.
//
// It's a convenience orchestrator over the public steps; a caller that
// needs to interleave its own work (Marketplace publishing, multi-region
// registration) can call [Builder.CheckAWSAuth], [Builder.BuildImage],
// [Builder.UploadToS3], [Builder.ImportSnapshot], and [Builder.RegisterAMI]
// directly in that order.
func (b *Builder) BuildAndImportAMI(ctx context.Context) (Result, error) {
	// Preflight auth before the slow image build so a logged-out user
	// fails in seconds, not minutes.
	if err := b.CheckAWSAuth(ctx); err != nil {
		return b.res, b.fail(err)
	}

	b.logf("[1/4] building image (%s)", b.App)
	if _, err := b.BuildImage(ctx); err != nil {
		return b.res, err // BuildImage already wrapped+recorded it
	}

	b.logf("[2/4] uploading to s3://%s/%s.img", b.Bucket, b.App)
	if _, err := b.UploadToS3(ctx); err != nil {
		return b.res, b.fail(fmt.Errorf("copy to S3: %w", err))
	}

	b.logf("[3/4] importing EBS snapshot")
	if _, err := b.ImportSnapshot(ctx); err != nil {
		return b.res, b.fail(fmt.Errorf("import snapshot: %w", err))
	}
	b.logf("snap ID: %v", b.res.Snapshot)

	b.logf("[4/4] registering AMI")
	if _, err := b.RegisterAMI(ctx); err != nil {
		return b.res, b.fail(fmt.Errorf("register AMI: %w", err))
	}
	b.logf("made AMI: %v", b.res.AMI)
	return b.res, nil
}

// awsClients lazily builds and caches the S3 and EC2 clients from the
// SDK default credential chain and resolved region.
func (b *Builder) awsClients(ctx context.Context) (*s3.Client, *ec2.Client, error) {
	if b.s3c != nil && b.ec2c != nil {
		return b.s3c, b.ec2c, nil
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(b.Region))
	if err != nil {
		return nil, nil, fmt.Errorf("loading AWS config (check AWS_PROFILE / ~/.aws, or run `aws sso login`): %w", err)
	}
	b.s3c = s3.NewFromConfig(cfg)
	b.ec2c = ec2.NewFromConfig(cfg)
	return b.s3c, b.ec2c, nil
}

// CheckAWSAuth verifies usable AWS credentials via sts:GetCallerIdentity.
// BuildAndImportAMI runs it as a preflight so a missing or expired login
// fails early and actionably instead of deep in the pipeline; it also logs
// the account so the user can confirm they're publishing to the right one.
func (b *Builder) CheckAWSAuth(ctx context.Context) error {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(b.Region))
	if err != nil {
		return fmt.Errorf("loading AWS config (check AWS_PROFILE / ~/.aws, or run `aws sso login`): %w", err)
	}
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("AWS credentials invalid or expired — run `aws sso login` or `aws configure`, or set AWS_PROFILE / AWS_ACCESS_KEY_ID: %w", err)
	}
	b.logf("AWS account %s (%s), region %s", aws.ToString(out.Account), aws.ToString(out.Arn), b.Region)
	return nil
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

// UploadToS3 uploads the built image to s3://<Bucket>/<App>.img (a
// concurrent multipart upload, progress on b.Stderr) and returns the URI
// (also in Result.S3). Requires BuildImage first.
func (b *Builder) UploadToS3(ctx context.Context) (s3URI string, err error) {
	if b.res.Image == "" {
		return "", fmt.Errorf("UploadToS3: no image built yet; call BuildImage first")
	}
	s3c, _, err := b.awsClients(ctx)
	if err != nil {
		return "", err
	}
	imgPath := filepath.Join(b.Dir, b.App+".img")
	f, err := os.Open(imgPath)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", imgPath, err)
	}
	defer f.Close()

	var size int64 = -1
	if fi, err := f.Stat(); err == nil {
		size = fi.Size()
	}

	pr := b.newProgressReader(f, "uploading", size)
	defer pr.done()

	up := manager.NewUploader(s3c, func(u *manager.Uploader) {
		u.PartSize = 16 * 1024 * 1024 // 16 MiB parts
		u.Concurrency = 8             // upload up to 8 parts at once
	})
	_, err = up.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(b.Bucket),
		Key:    aws.String(b.App + ".img"),
		Body:   pr,
	})
	if err != nil {
		return "", fmt.Errorf("uploading %s: %w", imgPath, err)
	}
	b.res.S3 = "s3://" + b.Bucket + "/" + b.App + ".img"
	return b.res.S3, nil
}

// ImportSnapshot imports the uploaded image as an EBS snapshot, waiting
// for completion, and returns the snapshot ID (also in Result.Snapshot,
// region in Result.Region). Requires UploadToS3 first.
func (b *Builder) ImportSnapshot(ctx context.Context) (snapshotID string, err error) {
	if b.res.S3 == "" {
		return "", fmt.Errorf("ImportSnapshot: image not uploaded yet; call UploadToS3 first")
	}
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
	_, ec2c, err := b.awsClients(ctx)
	if err != nil {
		return "", err
	}
	out, err := ec2c.ImportSnapshot(ctx, &ec2.ImportSnapshotInput{
		DiskContainer: &ec2types.SnapshotDiskContainer{
			Url: aws.String("s3://" + b.Bucket + "/" + b.App + ".img"),
		},
	})
	if err != nil {
		return "", fmt.Errorf("import snapshot: %w", err)
	}
	if out.ImportTaskId == nil {
		return "", fmt.Errorf("import snapshot: empty ImportTaskId in response")
	}
	return *out.ImportTaskId, nil
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
	_, ec2c, err := b.awsClients(ctx)
	if err != nil {
		return "", err
	}
	interactive := isTerminal(b.Stderr)
	var lastPhase string // last (status/message) reported in non-interactive mode
	for {
		out, err := ec2c.DescribeImportSnapshotTasks(ctx, &ec2.DescribeImportSnapshotTasksInput{
			ImportTaskIds: []string{importTaskID},
		})
		if err != nil {
			return "", fmt.Errorf("describe import snapshot tasks: %w", err)
		}

		var status, statusMessage, progress string
		if len(out.ImportSnapshotTasks) > 0 {
			if d := out.ImportSnapshotTasks[0].SnapshotTaskDetail; d != nil {
				snapID = aws.ToString(d.SnapshotId)
				status = aws.ToString(d.Status)
				statusMessage = aws.ToString(d.StatusMessage)
				progress = aws.ToString(d.Progress)
			}
		}
		if status == "completed" {
			if interactive {
				fmt.Fprintln(b.Stderr) // move off the live progress line
			}
			return snapID, nil
		}
		// A failed import stays out of "completed" forever; stop instead of
		// polling until the context is cancelled.
		if importFailed(status) {
			if interactive {
				fmt.Fprintln(b.Stderr)
			}
			msg := statusMessage
			if msg == "" {
				msg = status
			}
			return "", fmt.Errorf("import snapshot task %s failed: %s", importTaskID, msg)
		}

		if interactive {
			// Repaint one line in place each poll.
			fmt.Fprintf(b.Stderr, "\r\x1b[K%s", importProgressLine(status, statusMessage, progress))
		} else if phase := status + "/" + statusMessage; phase != lastPhase {
			// Non-interactive (pipe/redirect): one line per phase change
			// only, not a fresh line every poll.
			lastPhase = phase
			b.logf("%s", importProgressLine(status, statusMessage, progress))
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

// importFailed reports whether an import-snapshot task Status is a
// terminal failure state (as opposed to "active"/"completed"). AWS uses
// "deleting"/"deleted" when an import is cancelled or fails, and may
// report "error"; treat any status mentioning "error" as failed too.
func importFailed(status string) bool {
	switch status {
	case "deleting", "deleted", "error":
		return true
	}
	return strings.Contains(strings.ToLower(status), "error")
}

// RegisterAMI registers an AMI from the imported snapshot, naming it via
// AMIName, and returns the AMI ID (also in Result.AMI, name in
// Result.Name). Requires ImportSnapshot first.
func (b *Builder) RegisterAMI(ctx context.Context) (amiID string, err error) {
	if b.res.Snapshot == "" {
		return "", fmt.Errorf("RegisterAMI: no snapshot imported yet; call ImportSnapshot first")
	}
	b.res.Name = AMIName(b.App, b.Dir)

	var arch, bootMode string
	switch b.conf.GOARCH() {
	case "arm64":
		// arm64 instances boot UEFI-only; "uefi-preferred" is rejected.
		arch, bootMode = "arm64", "uefi"
	case "amd64":
		arch, bootMode = "x86_64", "uefi-preferred"
	default:
		return "", fmt.Errorf("unknown arch %q", b.conf.GOARCH())
	}
	_, ec2c, err := b.awsClients(ctx)
	if err != nil {
		return "", err
	}
	out, err := ec2c.RegisterImage(ctx, &ec2.RegisterImageInput{
		Name:         aws.String(b.res.Name),
		Architecture: ec2types.ArchitectureValues(arch),
		// register-image defaults to paravirtual; arm64 rejects that
		// ("supports HVM AMIs only") and amd64 would produce an image that
		// won't boot on Nitro. Both need HVM.
		VirtualizationType: aws.String("hvm"),
		RootDeviceName:     aws.String("/dev/sda1"),
		EnaSupport:         aws.Bool(true),
		ImdsSupport:        ec2types.ImdsSupportValuesV20,
		BootMode:           ec2types.BootModeValues(bootMode),
		BlockDeviceMappings: []ec2types.BlockDeviceMapping{{
			DeviceName: aws.String("/dev/sda1"),
			Ebs:        &ec2types.EbsBlockDevice{SnapshotId: aws.String(b.res.Snapshot)},
		}},
	})
	if err != nil {
		return "", fmt.Errorf("register image: %w", err)
	}
	if aws.ToString(out.ImageId) == "" {
		return "", fmt.Errorf("empty image ID in register-image response")
	}
	b.res.AMI = *out.ImageId
	return b.res.AMI, nil
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

// progressReader reports read progress against total (-1 if unknown): a
// live repainted line on a terminal, else a log line per 10%. It exists
// because the S3 uploader gives no progress callback of its own, so we
// count bytes as they pass through Read.
type progressReader struct {
	r     io.Reader
	b     *Builder
	verb  string // e.g. "uploading"
	total int64  // -1 if unknown

	read atomic.Int64 // cumulative bytes read so far

	interactive bool
	stop        chan struct{}
	wg          sync.WaitGroup
}

// newProgressReader wraps r and starts a goroutine displaying progress;
// total is the expected size in bytes, or -1 if unknown. Call done().
func (b *Builder) newProgressReader(r io.Reader, verb string, total int64) *progressReader {
	pr := &progressReader{
		r:           r,
		b:           b,
		verb:        verb,
		total:       total,
		interactive: isTerminal(b.Stderr),
		stop:        make(chan struct{}),
	}
	pr.wg.Add(1)
	go pr.run()
	return pr
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)
	pr.read.Add(int64(n))
	return n, err
}

func (pr *progressReader) run() {
	defer pr.wg.Done()
	var rate tsrate.Value
	rate.HalfLife = 5 * time.Second
	var prev int64
	interval := time.Second
	if !pr.interactive {
		interval = 2 * time.Second
	}
	tc := time.NewTicker(interval)
	defer tc.Stop()

	lastBucket := -1 // last 10%-bucket logged in non-interactive mode
	for {
		select {
		case <-pr.stop:
			return
		case <-tc.C:
			cur := pr.read.Load()
			rate.Add(float64(max(cur-prev, 0)))
			prev = cur
			if pr.interactive {
				fmt.Fprintf(pr.b.Stderr, "\r\x1b[K%s", progressLine(pr.verb, cur, pr.total, rate.Rate()))
			} else if pr.total > 0 {
				if bucket := int(cur * 10 / pr.total); bucket > lastBucket {
					lastBucket = bucket
					pr.b.logf("%s", progressLine(pr.verb, cur, pr.total, rate.Rate()))
				}
			}
		}
	}
}

// done stops the background display and prints a final line.
func (pr *progressReader) done() {
	close(pr.stop)
	pr.wg.Wait()
	cur := pr.read.Load()
	if pr.interactive {
		fmt.Fprintf(pr.b.Stderr, "\r\x1b[K%s\n", progressLine(pr.verb, cur, pr.total, 0))
	} else {
		pr.b.logf("%s: done (%s)", pr.verb, humanBytes(float64(cur)))
	}
}

// progressLine formats a one-line byte-progress status. rate is bytes/sec
// (0 to omit). total may be -1 (unknown), in which case percent is omitted.
func progressLine(verb string, cur, total int64, rate float64) string {
	if total > 0 {
		pct := 100 * float64(cur) / float64(total)
		s := fmt.Sprintf("%s: %.1f%% (%s / %s)", verb, pct, humanBytes(float64(cur)), humanBytes(float64(total)))
		if rate > 0 {
			s += fmt.Sprintf(" %s/s", humanBytes(rate))
		}
		return s
	}
	s := fmt.Sprintf("%s: %s", verb, humanBytes(float64(cur)))
	if rate > 0 {
		s += fmt.Sprintf(" %s/s", humanBytes(rate))
	}
	return s
}

// humanBytes formats n bytes with an IEC (binary) unit.
func humanBytes(n float64) string {
	switch {
	case n < 1<<10:
		return fmt.Sprintf("%.0fB", n)
	case n < 1<<20:
		return fmt.Sprintf("%.2fKiB", n/(1<<10))
	case n < 1<<30:
		return fmt.Sprintf("%.2fMiB", n/(1<<20))
	case n < 1<<40:
		return fmt.Sprintf("%.2fGiB", n/(1<<30))
	default:
		return fmt.Sprintf("%.2fTiB", n/(1<<40))
	}
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

// AMIName derives a deterministic AMI name from git in dir: <app>-<tag>
// on a tagged commit (releases), else a unixtime-suffixed ad-hoc name so
// repeated dev builds don't collide.
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
