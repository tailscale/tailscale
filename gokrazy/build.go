// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This program builds the Tailscale Appliance Gokrazy image.
//
// As of 2024-06-02 this is a exploratory work in progress and is
// not intended for serious use.
//
// Tracking issue is https://github.com/tailscale/tailscale/issues/1866
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var (
	app    = flag.String("app", "tsapp", "appliance name; one of the subdirectories of gokrazy/")
	bucket = flag.String("bucket", "tskrazy-import", "S3 bucket to upload disk image to while making AMI")
	build  = flag.Bool("build", false, "if true, just build locally and stop, without uploading")
)

func findMkfsExt4() (string, error) {
	tries := []string{
		"/opt/homebrew/opt/e2fsprogs/sbin/mkfs.ext4",
		"/sbin/mkfs.ext4",
	}
	for _, p := range tries {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	p, err := exec.LookPath("mkfs.ext4")
	if err == nil {
		return p, nil
	}
	if runtime.GOOS == "darwin" {
		return "", errors.New("no mkfs.ext4 found; run `brew install e2fsprogs`")
	}
	return "", errors.New("No mkfs.ext4 found on system")
}

func main() {
	flag.Parse()

	if *app == "" || strings.Contains(*app, "/") {
		log.Fatalf("--app must be non-empty name such as 'tsapp' or 'natlabapp'")
	}

	if err := buildImage(); err != nil {
		log.Fatalf("build image: %v", err)
	}
	if *build {
		log.Printf("built. stopping.")
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

	ami, err := makeAMI(fmt.Sprintf(*app+"-%d", time.Now().Unix()), snapID)
	if err != nil {
		log.Fatalf("makeAMI: %v", err)
	}
	log.Printf("made AMI: %v", ami)
}

func buildImage() error {
	mkfs, err := findMkfsExt4()
	if err != nil {
		return err
	}

	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	if fi, err := os.Stat(filepath.Join(dir, *app)); err != nil || !fi.IsDir() {
		return fmt.Errorf("in wrong directorg %v; no %q subdirectory found", dir, *app)
	}
	// Build the tsapp.img
	var buf bytes.Buffer
	cmd := exec.Command("go", "run",
		"-exec=env GOOS=linux GOARCH=amd64 ",
		"github.com/gokrazy/tools/cmd/gok",
		"--parent_dir="+dir,
		"--instance="+*app,
		"overwrite",
		"--full", *app+".img",
		"--target_storage_bytes=1258299392")
	cmd.Stdout = io.MultiWriter(os.Stdout, &buf)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	// gok overwrite emits a line of text saying how to run mkfs.ext4
	// to create the ext4 /perm filesystem. Parse that and run it.
	// The regexp is tight to avoid matching if the command changes,
	// to force us to check it's still correct/safe. But it shouldn't
	// change on its own because we pin the gok version in our go.mod.
	//
	// TODO(bradfitz): emit this in a machine-readable way from gok.
	rx := regexp.MustCompile(`(?m)/mkfs.ext4 (-F) (-E) (offset=\d+) (\S+) (\d+)\s*?$`)
	m := rx.FindStringSubmatch(buf.String())
	if m == nil {
		return fmt.Errorf("found no ext4 instructions in output")
	}

	log.Printf("Running %s %q ...", mkfs, m[1:])
	out, err := exec.Command(mkfs, m[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error running %v: %v, %s", mkfs, err, out)
	}
	log.Printf("Success.")

	return nil
}

func copyToS3() error {
	cmd := exec.Command("aws", "s3", "cp", *app+".img", "s3://"+*bucket+"/")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func startImportSnapshot() (importTaskID string, err error) {
	out, err := exec.Command("aws", "ec2", "import-snapshot", "--disk-container", "Url=s3://"+*bucket+"/"+*app+".img").CombinedOutput()
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
		out, err := exec.Command("aws", "ec2", "describe-import-snapshot-tasks", "--import-task-ids", importTaskID).CombinedOutput()
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
	out, err := exec.Command("aws", "ec2", "register-image",
		"--name", name,
		"--architecture", "x86_64",
		"--root-device-name", "/dev/sda",
		"--ena-support",
		"--imds-support", "v2.0",
		"--boot-mode", "uefi-preferred",
		"--block-device-mappings", "DeviceName=/dev/sda,Ebs={SnapshotId="+ebsSnapID+"}").CombinedOutput()
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
