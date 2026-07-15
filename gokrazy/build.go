// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// This program builds the Tailscale Appliance Gokrazy image.
//
// As of 2024-06-02 this is a exploratory work in progress and is
// not intended for serious use.
//
// The build logic lives in tailscale.com/gokrazy/build; this is a thin
// CLI wrapper around it.
//
// Tracking issue is https://github.com/tailscale/tailscale/issues/1866
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"

	"tailscale.com/gokrazy/build"
)

var (
	app        = flag.String("app", "tsapp", "appliance name; one of the subdirectories of gokrazy/")
	bucket     = flag.String("bucket", "tskrazy-import", "S3 bucket to upload disk image to while making AMI")
	buildLocal = flag.Bool("build", false, "if true, just build locally and stop, without uploading")
	gaf        = flag.Bool("gaf", false, "if true, build a gokrazy archive format file instead of a full disk image")
	jsonOut    = flag.Bool("json", false, "emit one machine-readable JSON result line to stdout")
	region     = flag.String("region", "", "AWS region for import+register; default us-east-1 (honors $AWS_REGION)")
)

func main() {
	flag.Parse()

	res, err := run(context.Background())

	// With --json, print one machine-readable result line to stdout,
	// including any error, so consumers see the outcome on stdout rather
	// than only via the exit code. All logs/progress go to stderr.
	if *jsonOut {
		if encErr := json.NewEncoder(os.Stdout).Encode(&res); encErr != nil {
			log.Fatalf("encoding json result: %v", encErr)
		}
	}
	if err != nil {
		log.Fatalf("%v", err)
	}
}

// run builds the appliance and returns the machine-readable result. The
// artifact is a CLI choice mapped to the matching Builder method: --gaf →
// GAF, --build → local image only, otherwise the full AMI pipeline.
func run(ctx context.Context) (build.Result, error) {
	b, err := build.New(build.Config{
		App:    *app,
		Bucket: *bucket,
		Region: build.ResolveRegion(*region, os.Getenv("AWS_REGION")),
	})
	if err != nil {
		return build.Result{App: *app, Error: err.Error()}, err
	}

	switch {
	case *gaf:
		_, err = b.BuildGAF(ctx)
	case *buildLocal:
		_, err = b.BuildImage(ctx)
	default:
		_, err = b.BuildAndImportAMI(ctx)
	}
	return b.Result(), err
}
