// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package unixpkgs contains dist Targets for building unix Tailscale packages.
package unixpkgs

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/goreleaser/nfpm/v2"
	"github.com/goreleaser/nfpm/v2/files"
	"tailscale.com/release/dist"
)

type tgzTarget struct {
	filenameArch string // arch to use in filename instead of deriving from goEnv["GOARCH"]
	goEnv        map[string]string
	signer       dist.Signer
}

func (t *tgzTarget) arch() string {
	if t.filenameArch != "" {
		return t.filenameArch
	}
	return t.goEnv["GOARCH"]
}

func (t *tgzTarget) os() string {
	return t.goEnv["GOOS"]
}

func (t *tgzTarget) String() string {
	return fmt.Sprintf("%s/%s/tgz", t.os(), t.arch())
}

func (t *tgzTarget) Build(b *dist.Build) ([]string, error) {
	var filename string
	if t.goEnv["GOOS"] == "linux" {
		// Linux used to be the only tgz architecture, so we didn't put the OS
		// name in the filename.
		filename = fmt.Sprintf("tailscale_%s_%s.tgz", b.Version.Short, t.arch())
	} else {
		filename = fmt.Sprintf("tailscale_%s_%s_%s.tgz", b.Version.Short, t.os(), t.arch())
	}
	if err := b.BuildWebClientAssets(); err != nil {
		return nil, err
	}
	ts, err := b.BuildGoBinary("tailscale.com/cmd/tailscale", t.goEnv)
	if err != nil {
		return nil, err
	}
	tsd, err := b.BuildGoBinary("tailscale.com/cmd/tailscaled", t.goEnv)
	if err != nil {
		return nil, err
	}

	log.Printf("Building %s", filename)

	out := filepath.Join(b.Out, filename)
	f, err := os.Create(out)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	addFile := func(src, dst string, mode int64) error {
		f, err := os.Open(src)
		if err != nil {
			return err
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		hdr := &tar.Header{
			Name:    dst,
			Size:    fi.Size(),
			Mode:    mode,
			ModTime: b.Time,
			Uid:     0,
			Gid:     0,
			Uname:   "root",
			Gname:   "root",
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err = io.Copy(tw, f); err != nil {
			return err
		}
		return nil
	}
	addDir := func(name string) error {
		hdr := &tar.Header{
			Name:    name + "/",
			Mode:    0755,
			ModTime: b.Time,
			Uid:     0,
			Gid:     0,
			Uname:   "root",
			Gname:   "root",
		}
		return tw.WriteHeader(hdr)
	}
	dir := strings.TrimSuffix(filename, ".tgz")
	if err := addDir(dir); err != nil {
		return nil, err
	}
	if err := addFile(tsd, filepath.Join(dir, "tailscaled"), 0755); err != nil {
		return nil, err
	}
	if err := addFile(ts, filepath.Join(dir, "tailscale"), 0755); err != nil {
		return nil, err
	}
	if t.os() == "linux" {
		dir = filepath.Join(dir, "systemd")
		if err := addDir(dir); err != nil {
			return nil, err
		}
		tailscaledDir, err := b.GoPkg("tailscale.com/cmd/tailscaled")
		if err != nil {
			return nil, err
		}
		if err := addFile(filepath.Join(tailscaledDir, "tailscaled.service"), filepath.Join(dir, "tailscaled.service"), 0644); err != nil {
			return nil, err
		}
		if err := addFile(filepath.Join(tailscaledDir, "tailscaled.defaults"), filepath.Join(dir, "tailscaled.defaults"), 0644); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	files := []string{filename}

	if t.signer != nil {
		outSig := out + ".sig"
		if err := t.signer.SignFile(out, outSig); err != nil {
			return nil, err
		}
		files = append(files, filepath.Base(outSig))
	}

	return files, nil
}

type debTarget struct {
	goEnv map[string]string
}

func (t *debTarget) os() string {
	return t.goEnv["GOOS"]
}

func (t *debTarget) arch() string {
	return t.goEnv["GOARCH"]
}

func (t *debTarget) String() string {
	return fmt.Sprintf("linux/%s/deb", t.goEnv["GOARCH"])
}

func (t *debTarget) Build(b *dist.Build) ([]string, error) {
	if t.os() != "linux" {
		return nil, errors.New("deb only supported on linux")
	}

	if err := b.BuildWebClientAssets(); err != nil {
		return nil, err
	}
	ts, err := b.BuildGoBinary("tailscale.com/cmd/tailscale", t.goEnv)
	if err != nil {
		return nil, err
	}
	tsd, err := b.BuildGoBinary("tailscale.com/cmd/tailscaled", t.goEnv)
	if err != nil {
		return nil, err
	}

	tailscaledDir, err := b.GoPkg("tailscale.com/cmd/tailscaled")
	if err != nil {
		return nil, err
	}
	repoDir, err := b.GoPkg("tailscale.com")
	if err != nil {
		return nil, err
	}

	arch := debArch(t.arch())
	contents, err := files.PrepareForPackager(files.Contents{
		&files.Content{
			Type:        files.TypeFile,
			Source:      ts,
			Destination: "/usr/bin/tailscale",
		},
		&files.Content{
			Type:        files.TypeFile,
			Source:      tsd,
			Destination: "/usr/sbin/tailscaled",
		},
		&files.Content{
			Type:        files.TypeFile,
			Source:      filepath.Join(tailscaledDir, "tailscaled.service"),
			Destination: "/lib/systemd/system/tailscaled.service",
		},
		&files.Content{
			Type:        files.TypeConfigNoReplace,
			Source:      filepath.Join(tailscaledDir, "tailscaled.defaults"),
			Destination: "/etc/default/tailscaled",
		},
	}, 0, "deb", false)
	if err != nil {
		return nil, err
	}
	info := nfpm.WithDefaults(&nfpm.Info{
		Name:        "tailscale",
		Arch:        arch,
		Platform:    "linux",
		Version:     b.Version.Short,
		Maintainer:  "Tailscale Inc <info@tailscale.com>",
		Description: "The easiest, most secure, cross platform way to use WireGuard + oauth2 + 2FA/SSO",
		Homepage:    "https://www.tailscale.com",
		License:     "MIT",
		Section:     "net",
		Priority:    "extra",
		Overridables: nfpm.Overridables{
			Contents: contents,
			Scripts: nfpm.Scripts{
				PostInstall: filepath.Join(repoDir, "release/deb/debian.postinst.sh"),
				PreRemove:   filepath.Join(repoDir, "release/deb/debian.prerm.sh"),
				PostRemove:  filepath.Join(repoDir, "release/deb/debian.postrm.sh"),
			},
			Depends: []string{
				// iptables is almost always required but not strictly needed.
				// Even if you can technically run Tailscale without it (by
				// manually configuring nftables or userspace mode), we still
				// mark this as "Depends" because our previous experiment in
				// https://github.com/tailscale/tailscale/issues/9236 of making
				// it only Recommends caused too many problems. Until our
				// nftables table is more mature, we'd rather err on the side of
				// wasting a little disk by including iptables for people who
				// might not need it rather than handle reports of it being
				// missing.
				"iptables",
			},
			Recommends: []string{
				"tailscale-archive-keyring (>= 1.35.181)",
				// The "ip" command isn't needed since 2021-11-01 in
				// 408b0923a61972ed but kept as an option as of
				// 2021-11-18 in d24ed3f68e35e802d531371.  See
				// https://github.com/tailscale/tailscale/issues/391.
				// We keep it recommended because it's usually
				// installed anyway and it's useful for debugging. But
				// we can live without it, so it's not Depends.
				"iproute2",
			},
			Replaces:  []string{"tailscale-relay"},
			Conflicts: []string{"tailscale-relay"},
		},
	})
	pkg, err := nfpm.Get("deb")
	if err != nil {
		return nil, err
	}

	filename := fmt.Sprintf("tailscale_%s_%s.deb", b.Version.Short, arch)
	log.Printf("Building %s", filename)
	f, err := os.Create(filepath.Join(b.Out, filename))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := pkg.Package(info, f); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	return []string{filename}, nil
}

type rpmTarget struct {
	goEnv  map[string]string
	signer dist.Signer
}

func (t *rpmTarget) os() string {
	return t.goEnv["GOOS"]
}

func (t *rpmTarget) arch() string {
	return t.goEnv["GOARCH"]
}

func (t *rpmTarget) String() string {
	return fmt.Sprintf("linux/%s/rpm", t.arch())
}

func (t *rpmTarget) Build(b *dist.Build) ([]string, error) {
	if t.os() != "linux" {
		return nil, errors.New("rpm only supported on linux")
	}

	if err := b.BuildWebClientAssets(); err != nil {
		return nil, err
	}
	ts, err := b.BuildGoBinary("tailscale.com/cmd/tailscale", t.goEnv)
	if err != nil {
		return nil, err
	}
	tsd, err := b.BuildGoBinary("tailscale.com/cmd/tailscaled", t.goEnv)
	if err != nil {
		return nil, err
	}

	tailscaledDir, err := b.GoPkg("tailscale.com/cmd/tailscaled")
	if err != nil {
		return nil, err
	}
	repoDir, err := b.GoPkg("tailscale.com")
	if err != nil {
		return nil, err
	}

	arch := rpmArch(t.arch())
	contents, err := files.PrepareForPackager(files.Contents{
		&files.Content{
			Type:        files.TypeFile,
			Source:      ts,
			Destination: "/usr/bin/tailscale",
		},
		&files.Content{
			Type:        files.TypeFile,
			Source:      tsd,
			Destination: "/usr/sbin/tailscaled",
		},
		&files.Content{
			Type:        files.TypeFile,
			Source:      filepath.Join(tailscaledDir, "tailscaled.service"),
			Destination: "/lib/systemd/system/tailscaled.service",
		},
		&files.Content{
			Type:        files.TypeConfigNoReplace,
			Source:      filepath.Join(tailscaledDir, "tailscaled.defaults"),
			Destination: "/etc/default/tailscaled",
		},
		// SELinux policy on e.g. CentOS 8 forbids writing to /var/cache.
		// Creating an empty directory at install time resolves this issue.
		&files.Content{
			Type:        files.TypeDir,
			Destination: "/var/cache/tailscale",
		},
	}, 0, "rpm", false)
	if err != nil {
		return nil, err
	}
	info := nfpm.WithDefaults(&nfpm.Info{
		Name:        "tailscale",
		Arch:        arch,
		Platform:    "linux",
		Version:     b.Version.Short,
		Maintainer:  "Tailscale Inc <info@tailscale.com>",
		Description: "The easiest, most secure, cross platform way to use WireGuard + oauth2 + 2FA/SSO",
		Homepage:    "https://www.tailscale.com",
		License:     "MIT",
		Overridables: nfpm.Overridables{
			Contents: contents,
			Scripts: nfpm.Scripts{
				PostInstall: filepath.Join(repoDir, "release/rpm/rpm.postinst.sh"),
				PreRemove:   filepath.Join(repoDir, "release/rpm/rpm.prerm.sh"),
				PostRemove:  filepath.Join(repoDir, "release/rpm/rpm.postrm.sh"),
			},
			Depends:   []string{"iptables", "iproute"},
			Replaces:  []string{"tailscale-relay"},
			Conflicts: []string{"tailscale-relay"},
			RPM: nfpm.RPM{
				Group: "Network",
				Signature: nfpm.RPMSignature{
					PackageSignature: nfpm.PackageSignature{
						SignFn: t.signer,
					},
				},
			},
		},
	})
	pkg, err := nfpm.Get("rpm")
	if err != nil {
		return nil, err
	}

	filename := fmt.Sprintf("tailscale_%s_%s.rpm", b.Version.Short, arch)
	log.Printf("Building %s", filename)

	f, err := os.Create(filepath.Join(b.Out, filename))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := pkg.Package(info, f); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	return []string{filename}, nil
}

// debArch returns the debian arch name for the given Go arch name.
// nfpm also does this translation internally, but we need to do it outside nfpm
// because we also need the filename to be correct.
func debArch(arch string) string {
	switch arch {
	case "386":
		return "i386"
	case "arm":
		// TODO: this is supposed to be "armel" for GOARM=5, and "armhf" for
		// GOARM=6 and 7. But we have some tech debt to pay off here before we
		// can ship more than 1 ARM deb, so for now match redo's behavior of
		// shipping armv5 binaries in an armv7 trenchcoat.
		return "armhf"
	case "mipsle":
		return "mipsel"
	case "mips64le":
		return "mips64el"
	default:
		return arch
	}
}

// rpmArch returns the RPM arch name for the given Go arch name.
// nfpm also does this translation internally, but we need to do it outside nfpm
// because we also need the filename to be correct.
func rpmArch(arch string) string {
	switch arch {
	case "amd64":
		return "x86_64"
	case "386":
		return "i386"
	case "arm":
		return "armv7hl"
	case "arm64":
		return "aarch64"
	case "mipsle":
		return "mipsel"
	case "mips64le":
		return "mips64el"
	default:
		return arch
	}
}
