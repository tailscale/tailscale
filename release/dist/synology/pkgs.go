// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package synology contains dist Targets for building Synology Tailscale packages.
package synology

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/release/dist"
)

type target struct {
	filenameArch    string
	dsmMajorVersion int
	dsmMinorVersion int
	goenv           map[string]string
	packageCenter   bool
	signer          dist.Signer
}

func (t *target) String() string {
	return fmt.Sprintf("synology/dsm%s/%s", t.dsmVersionString(), t.filenameArch)
}

func (t *target) Build(b *dist.Build) ([]string, error) {
	inner, err := getSynologyBuilds(b).buildInnerPackage(b, t.dsmMajorVersion, t.goenv)
	if err != nil {
		return nil, err
	}

	return t.buildSPK(b, inner)
}

// dsmVersionInt combines major and minor version info into an int
// representation.
//
// Version 7.2 becomes 72 as an example.
func (t *target) dsmVersionInt() int {
	return t.dsmMajorVersion*10 + t.dsmMinorVersion
}

// dsmVersionString returns a string representation of the version
// including minor version information if it exists.
//
// If dsmMinorVersion is 0 this returns dsmMajorVersion as a string,
// otherwise it returns "dsmMajorVersion-dsmMinorVersion".
func (t *target) dsmVersionString() string {
	dsmVersionString := fmt.Sprintf("%d", t.dsmMajorVersion)
	if t.dsmMinorVersion != 0 {
		dsmVersionString = fmt.Sprintf("%s-%d", dsmVersionString, t.dsmMinorVersion)
	}

	return dsmVersionString
}

func (t *target) buildSPK(b *dist.Build, inner *innerPkg) ([]string, error) {
	synoVersion := b.Version.Synology[t.dsmVersionInt()]
	filename := fmt.Sprintf("tailscale-%s-%s-%d-dsm%s.spk", t.filenameArch, b.Version.Short, synoVersion, t.dsmVersionString())
	out := filepath.Join(b.Out, filename)
	if t.packageCenter {
		log.Printf("Building %s (for package center)", filename)
	} else {
		log.Printf("Building %s (for sideloading)", filename)
	}

	if synoVersion > 2147483647 {
		// Synology requires that version number is within int32 range.
		// Erroring here if we create a build with a higher version.
		// In this case, we'll want to adjust the VersionInfo.Synology logic in
		// the mkversion package.
		return nil, errors.New("syno version exceeds int32 range")
	}

	privFile := fmt.Sprintf("privilege-dsm%d", t.dsmMajorVersion)
	if t.packageCenter && t.dsmMajorVersion == 7 {
		privFile += ".for-package-center"
	}

	f, err := os.Create(out)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	defer tw.Close()

	err = writeTar(tw, b.Time,
		memFile("INFO", t.mkInfo(b, inner.uncompressedSz), 0644),
		static("PACKAGE_ICON.PNG", "PACKAGE_ICON.PNG", 0644),
		static("PACKAGE_ICON_256.PNG", "PACKAGE_ICON_256.PNG", 0644),
		static("Tailscale.sc", "Tailscale.sc", 0644),
		dir("conf"),
		static("resource", "conf/resource", 0644),
		static(privFile, "conf/privilege", 0644),
		file(inner.path, "package.tgz", 0644),
		dir("scripts"),
		static("scripts/start-stop-status", "scripts/start-stop-status", 0644),
		static("scripts/postupgrade", "scripts/postupgrade", 0644),
		static("scripts/preupgrade", "scripts/preupgrade", 0644),
	)
	if err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	files := []string{out}

	if t.signer != nil {
		outSig := out + ".sig"
		if err := t.signer.SignFile(out, outSig); err != nil {
			return nil, err
		}
		files = append(files, outSig)
	}

	return files, nil
}

func (t *target) mkInfo(b *dist.Build, uncompressedSz int64) []byte {
	var ret bytes.Buffer
	f := func(k, v string) {
		fmt.Fprintf(&ret, "%s=%q\n", k, v)
	}
	f("package", "Tailscale")
	f("version", fmt.Sprintf("%s-%d", b.Version.Short, b.Version.Synology[t.dsmVersionInt()]))
	f("arch", t.filenameArch)
	f("description", "Connect all your devices using WireGuard, without the hassle.")
	f("displayname", "Tailscale")
	f("maintainer", "Tailscale, Inc.")
	f("maintainer_url", "https://github.com/tailscale/tailscale")
	f("create_time", b.Time.Format("20060102-15:04:05"))
	f("dsmuidir", "ui")
	f("dsmappname", "SYNO.SDS.Tailscale")
	f("startstop_restart_services", "nginx")
	switch t.dsmMajorVersion {
	case 6:
		f("os_min_ver", "6.0.1-7445")
		f("os_max_ver", "7.0-40000")
	case 7:
		if t.packageCenter {
			switch t.dsmMinorVersion {
			case 0:
				f("os_min_ver", "7.0-40000")
				f("os_max_ver", "7.2-60000")
			case 2:
				f("os_min_ver", "7.2-60000")
			default:
				panic(fmt.Sprintf("unsupported DSM major.minor version %s", t.dsmVersionString()))
			}
		} else {
			// We do not clamp the os_max_ver currently for non-package center builds as
			// the binaries for 7.0 and 7.2 are identical.
			f("os_min_ver", "7.0-40000")
			f("os_max_ver", "")
		}
	default:
		panic(fmt.Sprintf("unsupported DSM major version %d", t.dsmMajorVersion))
	}
	f("extractsize", fmt.Sprintf("%v", uncompressedSz>>10)) // in KiB
	return ret.Bytes()
}

type synologyBuildsMemoizeKey struct{}

type innerPkg struct {
	path           string
	uncompressedSz int64
}

// synologyBuilds is extra build context shared by all synology builds.
type synologyBuilds struct {
	innerPkgs dist.Memoize[*innerPkg]
}

// getSynologyBuilds returns the synologyBuilds for b, creating one if needed.
func getSynologyBuilds(b *dist.Build) *synologyBuilds {
	return b.Extra(synologyBuildsMemoizeKey{}, func() any { return new(synologyBuilds) }).(*synologyBuilds)
}

// buildInnerPackage builds the inner tarball for synology packages,
// which contains the files to unpack to disk on installation (as
// opposed to the outer tarball, which contains package metadata)
func (m *synologyBuilds) buildInnerPackage(b *dist.Build, dsmVersion int, goenv map[string]string) (*innerPkg, error) {
	key := []any{dsmVersion, goenv}
	return m.innerPkgs.Do(key, func() (*innerPkg, error) {
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

		tmp := b.TmpDir()
		out := filepath.Join(tmp, "package.tgz")

		f, err := os.Create(out)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		gw := gzip.NewWriter(f)
		defer gw.Close()
		cw := &countingWriter{gw, 0}
		tw := tar.NewWriter(cw)
		defer tw.Close()

		err = writeTar(tw, b.Time,
			dir("bin"),
			file(tsd, "bin/tailscaled", 0755),
			file(ts, "bin/tailscale", 0755),
			dir("conf"),
			static("Tailscale.sc", "conf/Tailscale.sc", 0644),
			static(fmt.Sprintf("logrotate-dsm%d", dsmVersion), "conf/logrotate.conf", 0644),
			dir("ui"),
			static("PACKAGE_ICON_256.PNG", "ui/PACKAGE_ICON_256.PNG", 0644),
			static("config", "ui/config", 0644),
			static("index.cgi", "ui/index.cgi", 0755))
		if err != nil {
			return nil, err
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

		return &innerPkg{out, cw.n}, nil
	})
}

// writeTar writes ents to tw.
func writeTar(tw *tar.Writer, modTime time.Time, ents ...tarEntry) error {
	for _, ent := range ents {
		if err := ent(tw, modTime); err != nil {
			return err
		}
	}
	return nil
}

// tarEntry is a function that writes tar entries (files or
// directories) to a tar.Writer.
type tarEntry func(*tar.Writer, time.Time) error

// fsFile returns a tarEntry that writes src in fsys to dst in the tar
// file, with mode.
func fsFile(fsys fs.FS, src, dst string, mode int64) tarEntry {
	return func(tw *tar.Writer, modTime time.Time) error {
		f, err := fsys.Open(src)
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
			ModTime: modTime,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err = io.Copy(tw, f); err != nil {
			return err
		}
		return nil
	}
}

// file returns a tarEntry that writes src on disk into the tar file as
// dst, with mode.
func file(src, dst string, mode int64) tarEntry {
	return fsFile(os.DirFS(filepath.Dir(src)), filepath.Base(src), dst, mode)
}

//go:embed files/*
var files embed.FS

// static returns a tarEntry that writes src in files/ into the tar
// file as dst, with mode.
func static(src, dst string, mode int64) tarEntry {
	fsys, err := fs.Sub(files, "files")
	if err != nil {
		panic(err)
	}
	return fsFile(fsys, src, dst, mode)
}

// memFile returns a tarEntry that writes bs to dst in the tar file,
// with mode.
func memFile(dst string, bs []byte, mode int64) tarEntry {
	return func(tw *tar.Writer, modTime time.Time) error {
		hdr := &tar.Header{
			Name:    dst,
			Size:    int64(len(bs)),
			Mode:    mode,
			ModTime: modTime,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(bs); err != nil {
			return err
		}
		return nil
	}
}

// dir returns a tarEntry that creates a world-readable directory in
// the tar file.
func dir(name string) tarEntry {
	return func(tw *tar.Writer, modTime time.Time) error {
		return tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeDir,
			Name:     name + "/",
			Mode:     0755,
			ModTime:  modTime,
			// TODO: why tailscale? Files are being written as owned by root.
			Uname: "tailscale",
			Gname: "tailscale",
		})
	}
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (cw *countingWriter) Write(bs []byte) (int, error) {
	n, err := cw.w.Write(bs)
	cw.n += int64(n)
	return n, err
}
