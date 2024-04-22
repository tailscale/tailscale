// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package qnap contains dist Targets for building QNAP Tailscale packages.
//
// QNAP dev docs over at https://www.qnap.com/en/how-to/tutorial/article/qpkg-development-guidelines.
package qnap

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"tailscale.com/release/dist"
)

type target struct {
	goenv  map[string]string
	arch   string
	signer *signer
}

type signer struct {
	privateKeyPath  string
	certificatePath string
}

func (t *target) String() string {
	return fmt.Sprintf("qnap/%s", t.arch)
}

func (t *target) Build(b *dist.Build) ([]string, error) {
	// Stop early if we don't have docker running.
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, fmt.Errorf("docker not found, cannot build: %w", err)
	}

	if t.signer != nil {
		if err := t.setUpSignatureFiles(b); err != nil {
			return nil, err
		}
	}

	qnapBuilds := getQnapBuilds(b)
	inner, err := qnapBuilds.buildInnerPackage(b, t.goenv)
	if err != nil {
		return nil, err
	}

	return t.buildQPKG(b, qnapBuilds, inner)
}

const (
	qnapTag = "1" // currently static, we don't seem to bump this
)

func (t *target) buildQPKG(b *dist.Build, qnapBuilds *qnapBuilds, inner *innerPkg) ([]string, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, fmt.Errorf("docker not found, cannot build: %w", err)
	}

	if err := qnapBuilds.makeDockerImage(b); err != nil {
		return nil, fmt.Errorf("makeDockerImage: %w", err)
	}

	filename := fmt.Sprintf("Tailscale_%s-%s_%s.qpkg", b.Version.Short, qnapTag, t.arch)
	filePath := filepath.Join(b.Out, filename)

	cmd := b.Command(b.Repo, "docker", "run", "--rm",
		"-e", fmt.Sprintf("ARCH=%s", t.arch),
		"-e", fmt.Sprintf("TSTAG=%s", b.Version.Short),
		"-e", fmt.Sprintf("QNAPTAG=%s", qnapTag),
		"-v", fmt.Sprintf("%s:/tailscale", inner.tailscalePath),
		"-v", fmt.Sprintf("%s:/tailscaled", inner.tailscaledPath),
		// Tailscale folder has QNAP package setup files needed for building.
		"-v", fmt.Sprintf("%s:/Tailscale", filepath.Join(b.Repo, "release/dist/qnap/Tailscale")),
		"-v", fmt.Sprintf("%s:/build-qpkg.sh", filepath.Join(b.Repo, "release/dist/qnap/build-qpkg.sh")),
		"-v", fmt.Sprintf("%s:/out", b.Out),
		"build.tailscale.io/qdk:latest",
		"/build-qpkg.sh",
	)

	// dist.Build runs target builds in parallel goroutines by default.
	// For QNAP, this is an issue because the underlaying qbuild builder will
	// create tmp directories in the shared docker image that end up conflicting
	// with one another.
	// So we use a mutex to only allow one "docker run" at a time.
	qnapBuilds.dockerImageMu.Lock()
	defer qnapBuilds.dockerImageMu.Unlock()

	log.Printf("Building %s", filePath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker run %v: %s", err, out)
	}

	return []string{filePath, filePath + ".md5"}, nil
}

func (t *target) setUpSignatureFiles(b *dist.Build) error {
	return b.Once(fmt.Sprintf("qnap-signature-%s-%s", t.signer.privateKeyPath, t.signer.certificatePath), func() error {
		log.Print("Setting up qnap signature files")

		key, err := os.ReadFile(t.signer.privateKeyPath)
		if err != nil {
			return err
		}
		cert, err := os.ReadFile(t.signer.certificatePath)
		if err != nil {
			return err
		}

		// QNAP's qbuild command expects key and cert files to be in the root
		// of the project directory (in our case release/dist/qnap/Tailscale).
		// So here, we copy the key and cert over to the project folder for the
		// duration of qnap package building and then delete them on close.

		keyPath := filepath.Join(b.Repo, "release/dist/qnap/Tailscale/private_key")
		if err := os.WriteFile(keyPath, key, 0400); err != nil {
			return err
		}
		certPath := filepath.Join(b.Repo, "release/dist/qnap/Tailscale/certificate")
		if err := os.WriteFile(certPath, cert, 0400); err != nil {
			return err
		}

		b.AddOnCloseFunc(func() error {
			return errors.Join(os.Remove(keyPath), os.Remove(certPath))
		})
		return nil
	})
}

type qnapBuildsMemoizeKey struct{}

type innerPkg struct {
	tailscalePath  string
	tailscaledPath string
}

// qnapBuilds holds extra build context shared by all qnap builds.
type qnapBuilds struct {
	// innerPkgs contains per-goenv compiled binary paths.
	// It is used to avoid repeated compilations for the same architecture.
	innerPkgs     dist.Memoize[*innerPkg]
	dockerImageMu sync.Mutex
}

// getQnapBuilds returns the qnapBuilds for b, creating one if needed.
func getQnapBuilds(b *dist.Build) *qnapBuilds {
	return b.Extra(qnapBuildsMemoizeKey{}, func() any { return new(qnapBuilds) }).(*qnapBuilds)
}

// buildInnerPackage builds the go binaries used for qnap packages.
// These binaries get embedded with Tailscale package metadata to form qnap
// releases.
func (m *qnapBuilds) buildInnerPackage(b *dist.Build, goenv map[string]string) (*innerPkg, error) {
	return m.innerPkgs.Do(goenv, func() (*innerPkg, error) {
		if err := b.BuildWebClientAssets(); err != nil {
			return nil, err
		}
		ts, err := b.BuildGoBinary("tailscale.com/cmd/tailscale", goenv)
		if err != nil {
			return nil, err
		}
		tsd, err := b.BuildGoBinary("tailscale.com/cmd/tailscaled", goenv)
		if err != nil {
			return nil, err
		}

		// The go binaries above get built and put into a /tmp directory created
		// by b.TmpDir(). But, we build QNAP with docker, which doesn't always
		// allow for mounting tmp directories (seemingly dependent on docker
		// host).
		// https://stackoverflow.com/questions/65267251/docker-bind-mount-directory-in-tmp-not-working
		//
		// So here, we move the binaries into a directory within the b.Repo
		// path and clean it up when the builder closes.

		tmpDir := filepath.Join(b.Repo, fmt.Sprintf("/tmp-qnap-%s-%s-%s", b.Version.Short, goenv["GOOS"], goenv["GOARCH"]))
		if err = os.MkdirAll(tmpDir, 0755); err != nil {
			return nil, err
		}
		b.AddOnCloseFunc(func() error {
			return os.RemoveAll(tmpDir)
		})

		tsBytes, err := os.ReadFile(ts)
		if err != nil {
			return nil, err
		}
		tsdBytes, err := os.ReadFile(tsd)
		if err != nil {
			return nil, err
		}

		tsPath := filepath.Join(tmpDir, "tailscale")
		if err := os.WriteFile(tsPath, tsBytes, 0755); err != nil {
			return nil, err
		}
		tsdPath := filepath.Join(tmpDir, "tailscaled")
		if err := os.WriteFile(tsdPath, tsdBytes, 0755); err != nil {
			return nil, err
		}

		return &innerPkg{tailscalePath: tsPath, tailscaledPath: tsdPath}, nil
	})
}

func (m *qnapBuilds) makeDockerImage(b *dist.Build) error {
	return b.Once("make-qnap-docker-image", func() error {
		log.Printf("Building qnapbuilder docker image")

		cmd := b.Command(b.Repo, "docker", "build",
			"-f", filepath.Join(b.Repo, "release/dist/qnap/Dockerfile.qpkg"),
			"-t", "build.tailscale.io/qdk:latest",
			filepath.Join(b.Repo, "release/dist/qnap/"),
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("docker build %v: %s", err, out)
		}
		return nil
	})
}
