// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// This program builds the Tailscale Appliance Gokrazy image.
//
// As of 2024-06-02 this is a exploratory work in progress and is
// not intended for serious use.
//
// Tracking issue is https://github.com/tailscale/tailscale/issues/1866
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"tailscale.com/gokrazy/mkfs"
)

var (
	app     = flag.String("app", "tsapp", "appliance name; one of the subdirectories of gokrazy/")
	bucket  = flag.String("bucket", "tskrazy-import", "S3 bucket to upload disk image to while making AMI")
	build   = flag.Bool("build", false, "if true, just build locally and stop, without uploading")
	gaf     = flag.Bool("gaf", false, "if true, build a gokrazy archive format file instead of a full disk image")
	jsonOut = flag.Bool("json", false, "emit one machine-readable JSON result line to stdout")
	region  = flag.String("region", "", "AWS region for import+register; default us-east-1 (honors $AWS_REGION)")
)

// awsRegion is the resolved AWS region used for every aws invocation. Set once
// in main from resolveRegion.
var awsRegion string

// result is the machine-readable output printed to stdout when --json is set.
// Fields are populated as the run progresses; per docs/cli.md, existing fields
// keep their meaning and consumers must tolerate new ones.
type result struct {
	App      string `json:"app"`
	Arch     string `json:"arch"`
	Name     string `json:"name,omitempty"`
	Image    string `json:"image,omitempty"`
	GAF      string `json:"gaf,omitempty"`
	Region   string `json:"region,omitempty"`
	Snapshot string `json:"snapshot,omitempty"`
	AMI      string `json:"ami,omitempty"`
}

var res result

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

var conf gokrazyConfig

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

func main() {
	flag.Parse()

	if *app == "" || strings.Contains(*app, "/") {
		log.Fatalf("--app must be non-empty name such as 'tsapp' or 'natlabapp'")
	}

	confJSON, err := os.ReadFile(filepath.Join(*app, "config.json"))
	if err != nil {
		log.Fatalf("reading config.json: %v", err)
	}
	if err := json.Unmarshal(confJSON, &conf); err != nil {
		log.Fatalf("unmarshaling config.json: %v", err)
	}
	switch conf.GOARCH() {
	case "amd64", "arm64":
	default:
		log.Fatalf("config.json GOARCH %q must be amd64 or arm64", conf.GOARCH())
	}

	awsRegion = resolveRegion(*region, os.Getenv("AWS_REGION"))
	res.App = *app
	res.Arch = awsArch(conf.GOARCH())

	if err := buildImage(); err != nil {
		log.Fatalf("build image: %v", err)
	}
	if *build || *gaf {
		log.Printf("built. stopping.")
		emitJSON()
		return
	}

	if err := copyToS3(); err != nil {
		log.Fatalf("copy to S3: %v", err)
	}

	importTask, err := startImportSnapshot()
	if err != nil {
		log.Fatalf("start import snapshot: %v", err)
	}
	snapID, err := waitForImportSnapshot(importTask)
	if err != nil {
		log.Fatalf("waitForImportSnapshot(%v): %v", importTask, err)
	}
	log.Printf("snap ID: %v", snapID)
	res.Snapshot = snapID
	res.Region = awsRegion

	res.Name = amiName(*app)
	ami, err := makeAMI(res.Name, snapID)
	if err != nil {
		log.Fatalf("makeAMI: %v", err)
	}
	log.Printf("made AMI: %v", ami)
	res.AMI = ami
	emitJSON()
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

// resolveRegion picks the AWS region: an explicit --region wins, then
// $AWS_REGION, then us-east-1 (where the Marketplace Catalog API and its
// source AMI live).
func resolveRegion(flagVal, env string) string {
	if flagVal != "" {
		return flagVal
	}
	if env != "" {
		return env
	}
	return "us-east-1"
}

// emitJSON writes the result as one JSON line to stdout when --json is set.
// Everything else in this program goes to stderr, so stdout is a clean data
// channel for scripts.
func emitJSON() {
	if !*jsonOut {
		return
	}
	if err := json.NewEncoder(os.Stdout).Encode(&res); err != nil {
		log.Fatalf("encoding json result: %v", err)
	}
}

func buildImage() error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	if fi, err := os.Stat(filepath.Join(dir, *app)); err != nil || !fi.IsDir() {
		return fmt.Errorf("in wrong directory %v; no %q subdirectory found", dir, *app)
	}

	args := []string{"run", "github.com/bradfitz/monogok/cmd/monogok"}
	if *gaf {
		args = append(args,
			"overwrite",
			"--gaf", filepath.Join(dir, *app+".gaf"),
		)
	} else {
		args = append(args,
			"overwrite",
			"--full", filepath.Join(dir, *app+".img"),
			fmt.Sprintf("--target_storage_bytes=%d", imageSizeBytesFor(*app)),
		)
	}

	cmd := exec.Command("go", args...)
	cmd.Dir = filepath.Join(dir, *app)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	if *gaf {
		res.GAF = filepath.Join(dir, *app+".gaf")
		return nil
	}

	imgPath := filepath.Join(dir, *app+".img")
	f, err := os.OpenFile(imgPath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", imgPath, err)
	}
	defer f.Close()
	if err := mkfs.Perm(f, imageSizeBytesFor(*app)); err != nil {
		return fmt.Errorf("formatting /perm in %s: %v", imgPath, err)
	}
	log.Printf("Wrote ext4 /perm filesystem to %s.", imgPath)
	res.Image = imgPath
	return nil
}

// amiName returns a deterministic AMI name derived from git: on a tagged commit
// it's <app>-<tag> (releases); otherwise <app>-<git describe>-<unixtime> for
// ad-hoc builds. If git is unavailable it falls back to <app>-<unixtime>.
func amiName(app string) string {
	exact, _ := gitOutput("describe", "--exact-match", "--tags", "HEAD")
	describe, _ := gitOutput("describe", "--tags", "--always", "--dirty")
	return amiNameFrom(app, exact, describe, time.Now().Unix())
}

// amiNameFrom is the pure decision behind amiName, split out for testing.
func amiNameFrom(app, exactTag, describe string, now int64) string {
	if exactTag != "" {
		return app + "-" + exactTag
	}
	if describe != "" {
		return fmt.Sprintf("%s-%s-%d", app, describe, now)
	}
	return fmt.Sprintf("%s-%d", app, now)
}

// gitOutput runs git with args and returns trimmed stdout, or an error (e.g. no
// git, not a repo, or the ref doesn't match).
func gitOutput(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// awsCmd builds an aws command with the resolved --region prepended so every
// call targets the same region deterministically.
func awsCmd(args ...string) *exec.Cmd {
	return exec.Command("aws", append([]string{"--region", awsRegion}, args...)...)
}

func copyToS3() error {
	cmd := awsCmd("s3", "cp", *app+".img", "s3://"+*bucket+"/")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func startImportSnapshot() (importTaskID string, err error) {
	out, err := awsCmd("ec2", "import-snapshot", "--disk-container", "Url=s3://"+*bucket+"/"+*app+".img").CombinedOutput()
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

func waitForImportSnapshot(importTaskID string) (snapID string, err error) {
	for {
		out, err := awsCmd("ec2", "describe-import-snapshot-tasks", "--import-task-ids", importTaskID).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("describe import snapshot tasks: %v: %s", err, out)
		}

		var resp struct {
			ImportSnapshotTasks []struct {
				SnapshotTaskDetail struct {
					SnapshotID string `json:"SnapshotId"`
					Status     string `json:"Status"`
				} `json:"SnapshotTaskDetail"`
			} `json:"ImportSnapshotTasks"`
		}
		if err := json.Unmarshal(out, &resp); err != nil {
			return "", fmt.Errorf("unmarshal response: %v: %s", err, out)
		}
		if len(resp.ImportSnapshotTasks) > 0 {
			first := &resp.ImportSnapshotTasks[0]
			if first.SnapshotTaskDetail.Status == "completed" {
				return first.SnapshotTaskDetail.SnapshotID, nil
			}
		}
		log.Printf("Still waiting; got: %s", out)
		time.Sleep(5 * time.Second)

		// TODO(bradfitz): percentage bar?
		// Looks like:
		/* 2024/05/14 13:03:21 Still waiting; got: {
		    "ImportSnapshotTasks": [
		        {
		            "ImportTaskId": "import-snap-0232251d0fbcb33fd",
		            "SnapshotTaskDetail": {
		                "DiskImageSize": 1258299392.0,
		                "Format": "RAW",
		                "Progress": "32",
		                "Status": "active",
		                "StatusMessage": "validated",
		                "Url": "s3://tskrazy-import/tskrazy.img",
		                "UserBucket": {
		                    "S3Bucket": "tskrazy-import",
		                    "S3Key": "tskrazy.img"
		                }
		            },
		            "Tags": []
		        }
		    ]
		}*/
	}
}

func makeAMI(name, ebsSnapID string) (ami string, err error) {
	var arch, bootMode string
	switch conf.GOARCH() {
	case "arm64":
		// arm64 instances boot UEFI-only; "uefi-preferred" is rejected.
		arch, bootMode = "arm64", "uefi"
	case "amd64":
		arch, bootMode = "x86_64", "uefi-preferred"
	default:
		return "", fmt.Errorf("unknown arch %q", conf.GOARCH())
	}
	out, err := awsCmd("ec2", "register-image",
		"--name", name,
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
		return "", fmt.Errorf("register image: %v: %s", err, out)
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
		return "", fmt.Errorf("unmarshal response: %v: %s", err, out)
	}
	if resp.ImageID == "" {
		return "", fmt.Errorf("empty image ID in response: %s", out)
	}
	return resp.ImageID, nil
}
