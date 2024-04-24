// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package qnap contains dist Targets for building QNAP Tailscale packages.
//
// QNAP dev docs over at https://www.qnap.com/en/how-to/tutorial/article/qpkg-development-guidelines.
package qnap

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

	qnapBuilds := getQnapBuilds(b, t.signer)
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
		"-v", fmt.Sprintf("%s:/Tailscale", filepath.Join(qnapBuilds.tmpDir, "files/Tailscale")),
		"-v", fmt.Sprintf("%s:/build-qpkg.sh", filepath.Join(qnapBuilds.tmpDir, "files/scripts/build-qpkg.sh")),
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
	// tmpDir is a temp directory used for building qpkgs.
	// It gets cleaned up when the dist.Build is closed.
	tmpDir string
}

// getQnapBuilds returns the qnapBuilds for b, creating one if needed.
func getQnapBuilds(b *dist.Build, signer *signer) *qnapBuilds {
	return b.Extra(qnapBuildsMemoizeKey{}, func() any {
		builds, err := newQNAPBuilds(b, signer)
		if err != nil {
			panic(fmt.Errorf("setUpTmpDir: %v", err))
		}
		return builds
	}).(*qnapBuilds)
}

//go:embed all:files
var buildFiles embed.FS

// newQNAPBuilds creates a new qnapBuilds instance to hold context shared by
// all qnap targets, and sets up its local temp directory used for building.
//
// The qnapBuilds.tmpDir is filled with the contents of the buildFiles embedded
// FS for building.
//
// We do this to allow for this tailscale.com/release/dist/qnap package to be
// used from both the corp and OSS repos. When built from OSS source directly,
// this is a superfluous extra step, but when imported as a go module to another
// repo (such as corp), we must do this to allow for the module's build files
// to be reachable and editable from docker.
//
// This runs only once per dist.Build instance, is shared by all qnap targets,
// and gets cleaned up upon close of the dist.Build.
//
// When a signer is provided, newQNAPBuilds also sets up the qpkg signature
// files in qbuild's expected location within m.tmpDir.
func newQNAPBuilds(b *dist.Build, signer *signer) (*qnapBuilds, error) {
	m := new(qnapBuilds)

	log.Print("Setting up qnap tmp build directory")
	m.tmpDir = filepath.Join(b.Repo, "tmp-qnap-build")
	b.AddOnCloseFunc(func() error {
		return os.RemoveAll(m.tmpDir)
	})

	if err := fs.WalkDir(buildFiles, "files", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		outPath := filepath.Join(m.tmpDir, path)
		if d.IsDir() {
			return os.MkdirAll(outPath, 0755)
		}
		file, err := fs.ReadFile(buildFiles, path)
		if err != nil {
			return err
		}
		perm := fs.FileMode(0644)
		if slices.Contains([]string{".sh", ".cgi"}, filepath.Ext(path)) {
			perm = 0755
		}
		return os.WriteFile(outPath, file, perm)
	}); err != nil {
		return nil, err
	}

	if signer != nil {
		log.Print("Setting up qnap signing files")

		key, err := os.ReadFile(signer.privateKeyPath)
		if err != nil {
			return nil, err
		}
		cert, err := os.ReadFile(signer.certificatePath)
		if err != nil {
			return nil, err
		}

		// QNAP's qbuild command expects key and cert files to be in the root
		// of the project directory (in our case release/dist/qnap/Tailscale).
		// So here, we copy the key and cert over to the project folder for the
		// duration of qnap package building and then delete them on close.

		keyPath := filepath.Join(m.tmpDir, "files/Tailscale/private_key")
		if err := os.WriteFile(keyPath, key, 0400); err != nil {
			return nil, err
		}
		certPath := filepath.Join(m.tmpDir, "files/Tailscale/certificate")
		if err := os.WriteFile(certPath, cert, 0400); err != nil {
			return nil, err
		}
	}
	return m, nil
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

		tmpDir := filepath.Join(m.tmpDir, fmt.Sprintf("/binaries-%s-%s-%s", b.Version.Short, goenv["GOOS"], goenv["GOARCH"]))
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
			"-f", filepath.Join(m.tmpDir, "files/scripts/Dockerfile.qpkg"),
			"-t", "build.tailscale.io/qdk:latest",
			filepath.Join(m.tmpDir, "files/scripts"),
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("docker build %v: %s", err, out)
		}
		return nil
	})
}
