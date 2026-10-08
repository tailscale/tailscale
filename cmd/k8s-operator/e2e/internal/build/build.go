// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package build builds and publishes the container images exercised by the
// k8s-operator e2e tests. It is shared by the e2e test harness and the
// tailscale.com/cmd/k8s-operator/e2e/build command so that CI can publish
// images once ahead of the test jobs that consume them.
package build

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

const (
	ImgOperator   = "k8s-operator"
	ImgTailscale  = "tailscale"
	ImgProxy      = "k8s-proxy"
	ImgNameserver = "k8s-nameserver"
)

// Targets maps each e2e image name to the make target that builds it. The
// image name doubles as the repository name under the target registry.
var Targets = map[string]string{
	ImgOperator:   "publishdevoperator",
	ImgTailscale:  "publishdevimage",
	ImgProxy:      "publishdevproxy",
	ImgNameserver: "publishdevnameserver",
}

// Opts are the parameters shared by all images in one build.
type Opts struct {
	// Dir is the root of the tailscale.com checkout to build from.
	Dir string
	// Registry is the registry to push to. Empty means don't push; images
	// are built into the local docker daemon instead.
	Registry string
	// Tag tags all built images.
	Tag string
	// Arch is the target node architecture, e.g. "amd64". Only used when
	// pushing to a registry; empty builds all platforms.
	Arch string
	// BaseImage overrides the default base image in build_docker.sh.
	BaseImage string
	// ExtraCACerts are paths of CA cert files to add to the images'
	// system cert pool.
	ExtraCACerts []string
	// Logf logs progress. Nil discards.
	Logf func(format string, args ...any)
}

func (o Opts) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

// RepoRoot returns the top-level directory of the current git repo. Expects
// to be run from inside a git repo.
func RepoRoot() (string, error) {
	top, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("failed to find git top level (not in a git checkout?): %w", err)
	}
	return strings.TrimSpace(string(top)), nil
}

// Tag returns an image tag derived from the git checkout at dir: the short
// hash of HEAD, plus a random suffix if the working tree is dirty so that
// successive dirty builds don't reuse a stale image. dirty reports whether
// the suffix was appended; the tag is only re-derivable from the commit when
// it's false.
func Tag(dir string) (tag string, dirty bool, err error) {
	cmd := exec.Command("git", "rev-parse", "--short", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", false, fmt.Errorf("failed to get HEAD commit for repo %q: %w", dir, err)
	}
	tag = strings.TrimSpace(string(out))

	cmd = exec.Command("git", "status", "--porcelain")
	cmd.Dir = dir
	out, err = cmd.Output()
	if err != nil {
		return "", false, fmt.Errorf("failed to check git status for repo %q: %w", dir, err)
	}
	if strings.TrimSpace(string(out)) != "" {
		tag += "-" + strings.ToLower(rand.Text())
		dirty = true
	}

	return tag, dirty, nil
}

// ImageRepo returns the image repository for name: <registry>/<name>, or
// local/<name> when no registry is configured.
func ImageRepo(registry, name string) string {
	if registry != "" {
		return strings.TrimSuffix(registry, "/") + "/" + name
	}
	return "local/" + name
}

// Build builds the named image via make, pushing it to opts.Registry if set
// or into the local docker daemon otherwise.
func Build(ctx context.Context, opts Opts, img string) error {
	target, ok := Targets[img]
	if !ok {
		return fmt.Errorf("unknown image %q", img)
	}
	var files []string
	for _, f := range opts.ExtraCACerts {
		files = append(files, fmt.Sprintf("%s:/etc/ssl/certs/%s", f, filepath.Base(f)))
	}
	args := []string{target,
		fmt.Sprintf("PLATFORM=%s", platform(opts.Registry, opts.Arch)),
		fmt.Sprintf("TAGS=%s", opts.Tag),
		fmt.Sprintf("REPO=%s", ImageRepo(opts.Registry, img)),
		fmt.Sprintf("FILES=%s", strings.Join(files, ",")),
	}
	if opts.BaseImage != "" {
		// make exports command line variables to recipes, so this reaches
		// build_docker.sh as the BASE env var.
		args = append(args, fmt.Sprintf("BASE=%s", opts.BaseImage))
	}
	cmd := exec.CommandContext(ctx, "make", args...)
	cmd.Dir = opts.Dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to build image %q: %w", img, err)
	}

	return nil
}

// Exists reports whether ref is already present in its remote registry. Only
// a 404 counts as missing; auth and network errors are returned rather than
// swallowed, because wrongly concluding "missing" turns into a doomed push
// against an immutable registry.
func Exists(ctx context.Context, ref string) (bool, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return false, fmt.Errorf("failed to parse image reference %q: %w", ref, err)
	}
	_, err = remote.Head(r, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
	if err == nil {
		return true, nil
	}
	var terr *transport.Error
	if errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return false, fmt.Errorf("failed to check for image %q: %w", ref, err)
}

// EnsurePushed builds and pushes any of the e2e images missing from
// opts.Registry at opts.Tag. It's idempotent, and safe to race with another
// EnsurePushed for the same registry and tag: if our push loses the race
// (immutable registries reject the second push), the winner's image is
// accepted as equivalent to ours.
func EnsurePushed(ctx context.Context, opts Opts) error {
	if opts.Registry == "" {
		return errors.New("EnsurePushed requires a registry")
	}
	for _, img := range slices.Sorted(maps.Keys(Targets)) {
		ref := ImageRepo(opts.Registry, img) + ":" + opts.Tag
		switch ok, err := Exists(ctx, ref); {
		case err != nil:
			return err
		case ok:
			opts.logf("image %s already exists, skipping build", ref)
			continue
		}
		if err := Build(ctx, opts, img); err != nil {
			if ok, err2 := Exists(ctx, ref); err2 == nil && ok {
				opts.logf("image %s exists after a failed push, assuming another job built it", ref)
				continue
			}
			return err
		}
	}
	return nil
}

// platform maps the target architecture to a mkctr platform preset. Without
// a registry we have to build via the local docker daemon so the image can
// be side-loaded into kind. Otherwise, build only the cluster's architecture
// when we know it (build time is significant), falling back to all
// platforms.
func platform(registry, arch string) string {
	if registry == "" {
		return "local"
	}
	switch arch {
	case "amd64":
		return "flyio" // flyio == linux/amd64
	default:
		return ""
	}
}
