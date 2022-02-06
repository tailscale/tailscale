// Package deb implements nfpm.Packager providing .deb bindings.
package deb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5" // nolint:gas
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/blakesmith/ar"
	"github.com/goreleaser/chglog"

	"github.com/goreleaser/nfpm"
	"github.com/goreleaser/nfpm/internal/files"
	"github.com/goreleaser/nfpm/internal/sign"
)

// nolint: gochecknoinits
func init() {
	nfpm.Register("deb", Default)
}

// nolint: gochecknoglobals
var archToDebian = map[string]string{
	"386":     "i386",
	"arm":     "armhf",
	"arm5":    "armel",
	"arm6":    "armhf",
	"arm7":    "armhf",
	"mipsle":  "mipsel",
	"ppc64le": "ppc64el",
}

// Default deb packager.
// nolint: gochecknoglobals
var Default = &Deb{}

// Deb is a deb packager implementation.
type Deb struct{}

// ConventionalFileName returns a file name according
// to the conventions for debian packages. See:
// https://manpages.debian.org/buster/dpkg-dev/dpkg-name.1.en.html
func (*Deb) ConventionalFileName(info *nfpm.Info) string {
	arch, ok := archToDebian[info.Arch]
	if !ok {
		arch = info.Arch
	}

	version := info.Version
	if info.Release != "" {
		version += "-" + info.Release
	}

	if info.Prerelease != "" {
		version += "~" + info.Prerelease
	}

	if info.VersionMetadata != "" {
		version += "+" + info.VersionMetadata
	}

	// package_version_architecture.package-type
	return fmt.Sprintf("%s_%s_%s.deb", info.Name, version, arch)
}

// ErrInvalidSignatureType happens if the signature type of a deb is not one of
// origin, maint or archive.
var ErrInvalidSignatureType = errors.New("invalid signature type")

// Package writes a new deb package to the given writer using the given info.
func (*Deb) Package(info *nfpm.Info, deb io.Writer) (err error) { // nolint: funlen
	arch, ok := archToDebian[info.Arch]
	if ok {
		info.Arch = arch
	}

	dataTarGz, md5sums, instSize, err := createDataTarGz(info)
	if err != nil {
		return err
	}

	controlTarGz, err := createControl(instSize, md5sums, info)
	if err != nil {
		return err
	}

	debianBinary := []byte("2.0\n")

	var w = ar.NewWriter(deb)
	if err := w.WriteGlobalHeader(); err != nil {
		return fmt.Errorf("cannot write ar header to deb file: %w", err)
	}

	if err := addArFile(w, "debian-binary", debianBinary); err != nil {
		return fmt.Errorf("cannot pack debian-binary: %w", err)
	}

	if err := addArFile(w, "control.tar.gz", controlTarGz); err != nil {
		return fmt.Errorf("cannot add control.tar.gz to deb: %w", err)
	}

	if err := addArFile(w, "data.tar.gz", dataTarGz); err != nil {
		return fmt.Errorf("cannot add data.tar.gz to deb: %w", err)
	}

	// TODO: refactor this
	if info.Deb.Signature.KeyFile != "" {
		data := io.MultiReader(bytes.NewReader(debianBinary), bytes.NewReader(controlTarGz),
			bytes.NewReader(dataTarGz))

		sig, err := sign.PGPArmoredDetachSign(data, info.Deb.Signature.KeyFile,
			info.Deb.Signature.KeyPassphrase)
		if err != nil {
			return &nfpm.ErrSigningFailure{Err: err}
		}

		sigType := "origin"
		if info.Deb.Signature.Type != "" {
			sigType = info.Deb.Signature.Type
		}

		if sigType != "origin" && sigType != "maint" && sigType != "archive" {
			return &nfpm.ErrSigningFailure{
				Err: ErrInvalidSignatureType,
			}
		}

		if err := addArFile(w, "_gpg"+sigType, sig); err != nil {
			return &nfpm.ErrSigningFailure{
				Err: fmt.Errorf("add signature to ar file: %w", err),
			}
		}
	}

	return nil
}

func addArFile(w *ar.Writer, name string, body []byte) error {
	var header = ar.Header{
		Name:    files.ToNixPath(name),
		Size:    int64(len(body)),
		Mode:    0644,
		ModTime: time.Now(),
	}
	if err := w.WriteHeader(&header); err != nil {
		return fmt.Errorf("cannot write file header: %w", err)
	}
	_, err := w.Write(body)
	return err
}

func createDataTarGz(info *nfpm.Info) (dataTarGz, md5sums []byte, instSize int64, err error) {
	var buf bytes.Buffer
	var compress = gzip.NewWriter(&buf)
	var out = tar.NewWriter(compress)

	// the writers are properly closed later, this is just in case that we have
	// an error in another part of the code.
	defer out.Close()      // nolint: errcheck
	defer compress.Close() // nolint: errcheck

	var created = map[string]bool{}
	if err = createEmptyFoldersInsideTarGz(info, out, created); err != nil {
		return nil, nil, 0, err
	}

	md5buf, instSize, err := createFilesInsideTarGz(info, out, created)
	if err != nil {
		return nil, nil, 0, err
	}

	if err := createSymlinksInsideTarGz(info, out, created); err != nil {
		return nil, nil, 0, err
	}

	if err := out.Close(); err != nil {
		return nil, nil, 0, fmt.Errorf("closing data.tar.gz: %w", err)
	}
	if err := compress.Close(); err != nil {
		return nil, nil, 0, fmt.Errorf("closing data.tar.gz: %w", err)
	}

	return buf.Bytes(), md5buf.Bytes(), instSize, nil
}

func createSymlinksInsideTarGz(info *nfpm.Info, out *tar.Writer, created map[string]bool) error {
	for src, dst := range info.Symlinks {
		if err := createTree(out, src, created); err != nil {
			return err
		}

		err := newItemInsideTarGz(out, []byte{}, &tar.Header{
			Name:     normalizePath(src),
			Linkname: dst,
			Typeflag: tar.TypeSymlink,
			ModTime:  time.Now(),
			Format:   tar.FormatGNU,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func createFilesInsideTarGz(info *nfpm.Info, out *tar.Writer, created map[string]bool) (bytes.Buffer, int64, error) {
	var md5buf bytes.Buffer
	var instSize int64

	filesToCopy, err := files.Expand(info.Files, info.DisableGlobbing)
	if err != nil {
		return md5buf, 0, err
	}

	configFiles, err := files.Expand(info.ConfigFiles, info.DisableGlobbing)
	if err != nil {
		return md5buf, 0, err
	}

	filesToCopy = append(filesToCopy, configFiles...)

	for _, file := range filesToCopy {
		if err = createTree(out, file.Destination, created); err != nil {
			return md5buf, 0, err
		}

		var size int64 // declare early to avoid shadowing err
		size, err = copyToTarAndDigest(out, &md5buf, file.Source, file.Destination)
		if err != nil {
			return md5buf, 0, err
		}
		instSize += size
	}

	if info.Changelog != "" {
		size, err := createChangelogInsideTarGz(out, &md5buf, created, info)
		if err != nil {
			return md5buf, 0, err
		}

		instSize += size
	}

	return md5buf, instSize, nil
}

func createEmptyFoldersInsideTarGz(info *nfpm.Info, out *tar.Writer, created map[string]bool) error {
	for _, folder := range info.EmptyFolders {
		// this .nope is actually not created, because createTree ignore the
		// last part of the path, assuming it is a file.
		// TODO: should probably refactor this
		if err := createTree(out, files.ToNixPath(filepath.Join(folder, ".nope")), created); err != nil {
			return err
		}
	}
	return nil
}

func copyToTarAndDigest(tarw *tar.Writer, md5w io.Writer, src, dst string) (int64, error) {
	file, err := os.OpenFile(src, os.O_RDONLY, 0600) //nolint:gosec
	if err != nil {
		return 0, fmt.Errorf("could not add file to the archive: %w", err)
	}
	// don't care if it errs while closing...
	defer file.Close() // nolint: errcheck,gosec
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	if info.IsDir() {
		// TODO: this should probably return an error
		return 0, nil
	}
	var header = tar.Header{
		Name:    normalizePath(dst),
		Size:    info.Size(),
		Mode:    int64(info.Mode()),
		ModTime: time.Now(),
		Format:  tar.FormatGNU,
	}
	if err := tarw.WriteHeader(&header); err != nil {
		return 0, fmt.Errorf("cannot write header of %s to data.tar.gz: %w", src, err)
	}
	var digest = md5.New() // nolint:gas
	if _, err := io.Copy(tarw, io.TeeReader(file, digest)); err != nil {
		return 0, fmt.Errorf("failed to copy: %w", err)
	}
	if _, err := fmt.Fprintf(md5w, "%x  %s\n", digest.Sum(nil), header.Name); err != nil {
		return 0, fmt.Errorf("failed to write md5: %w", err)
	}
	return info.Size(), nil
}

func createChangelogInsideTarGz(tarw *tar.Writer, md5w io.Writer, created map[string]bool,
	info *nfpm.Info) (int64, error) {
	var buf bytes.Buffer
	var out = gzip.NewWriter(&buf)
	// the writers are properly closed later, this is just in case that we have
	// an error in another part of the code.
	defer out.Close() // nolint: errcheck

	changelogContent, err := formatChangelog(info)
	if err != nil {
		return 0, err
	}

	if _, err = out.Write([]byte(changelogContent)); err != nil {
		return 0, err
	}

	if err = out.Close(); err != nil {
		return 0, fmt.Errorf("closing changelog.gz: %w", err)
	}

	changelogData := buf.Bytes()

	// https://www.debian.org/doc/manuals/developers-reference/pkgs.de.html#recording-changes-in-the-package
	changelogName := normalizePath(fmt.Sprintf("/usr/share/doc/%s/changelog.gz", info.Name))
	if err = createTree(tarw, changelogName, created); err != nil {
		return 0, err
	}

	var digest = md5.New() // nolint:gas
	if _, err = digest.Write(changelogData); err != nil {
		return 0, err
	}

	if _, err = fmt.Fprintf(md5w, "%x  %s\n", digest.Sum(nil), changelogName); err != nil {
		return 0, err
	}

	if err = newFileInsideTarGz(tarw, changelogName, changelogData); err != nil {
		return 0, err
	}

	return int64(len(changelogData)), nil
}

func formatChangelog(info *nfpm.Info) (string, error) {
	changelog, err := info.GetChangeLog()
	if err != nil {
		return "", err
	}

	tpl, err := chglog.DebTemplate()
	if err != nil {
		return "", err
	}

	formattedChangelog, err := chglog.FormatChangelog(changelog, tpl)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(formattedChangelog) + "\n", nil
}

// nolint:funlen
func createControl(instSize int64, md5sums []byte, info *nfpm.Info) (controlTarGz []byte, err error) {
	var buf bytes.Buffer
	var compress = gzip.NewWriter(&buf)
	var out = tar.NewWriter(compress)
	// the writers are properly closed later, this is just in case that we have
	// an error in another part of the code.
	defer out.Close()      // nolint: errcheck
	defer compress.Close() // nolint: errcheck

	var body bytes.Buffer
	if err = writeControl(&body, controlData{
		Info:          info,
		InstalledSize: instSize / 1024,
	}); err != nil {
		return nil, err
	}

	filesToCreate := map[string][]byte{
		"control":   body.Bytes(),
		"md5sums":   md5sums,
		"conffiles": conffiles(info),
	}

	if info.Changelog != "" {
		changeLogData, err := formatChangelog(info)
		if err != nil {
			return nil, err
		}

		filesToCreate["changelog"] = []byte(changeLogData)
	}

	triggers := createTriggers(info)
	if len(triggers) > 0 {
		filesToCreate["triggers"] = triggers
	}

	for name, content := range filesToCreate {
		if err := newFileInsideTarGz(out, name, content); err != nil {
			return nil, err
		}
	}

	type fileAndMode struct {
		fileName string
		mode     int64
	}

	var specialFiles = map[string]*fileAndMode{}
	specialFiles[info.Scripts.PreInstall] = &fileAndMode{
		fileName: "preinst",
		mode:     0755,
	}
	specialFiles[info.Scripts.PostInstall] = &fileAndMode{
		fileName: "postinst",
		mode:     0755,
	}
	specialFiles[info.Scripts.PreRemove] = &fileAndMode{
		fileName: "prerm",
		mode:     0755,
	}
	specialFiles[info.Scripts.PostRemove] = &fileAndMode{
		fileName: "postrm",
		mode:     0755,
	}
	specialFiles[info.Overridables.Deb.Scripts.Rules] = &fileAndMode{
		fileName: "rules",
		mode:     0755,
	}
	specialFiles[info.Overridables.Deb.Scripts.Templates] = &fileAndMode{
		fileName: "templates",
		mode:     0644,
	}

	for path, destMode := range specialFiles {
		if path != "" {
			if err := newFilePathInsideTarGz(out, path, destMode.fileName, destMode.mode); err != nil {
				return nil, err
			}
		}
	}

	if err := out.Close(); err != nil {
		return nil, fmt.Errorf("closing control.tar.gz: %w", err)
	}
	if err := compress.Close(); err != nil {
		return nil, fmt.Errorf("closing control.tar.gz: %w", err)
	}
	return buf.Bytes(), nil
}

func newItemInsideTarGz(out *tar.Writer, content []byte, header *tar.Header) error {
	if err := out.WriteHeader(header); err != nil {
		return fmt.Errorf("cannot write header of %s file to control.tar.gz: %w", header.Name, err)
	}
	if _, err := out.Write(content); err != nil {
		return fmt.Errorf("cannot write %s file to control.tar.gz: %w", header.Name, err)
	}
	return nil
}

func newFileInsideTarGz(out *tar.Writer, name string, content []byte) error {
	return newItemInsideTarGz(out, content, &tar.Header{
		Name:     normalizePath(name),
		Size:     int64(len(content)),
		Mode:     0644,
		ModTime:  time.Now(),
		Typeflag: tar.TypeReg,
		Format:   tar.FormatGNU,
	})
}

func newFilePathInsideTarGz(out *tar.Writer, path, dest string, mode int64) error {
	file, err := os.Open(path) //nolint:gosec
	if err != nil {
		return err
	}
	content, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}
	return newItemInsideTarGz(out, content, &tar.Header{
		Name:     normalizePath(dest),
		Size:     int64(len(content)),
		Mode:     mode,
		ModTime:  time.Now(),
		Typeflag: tar.TypeReg,
		Format:   tar.FormatGNU,
	})
}

// normalizePath returns a path separated by slashes, all relative path items
// resolved and relative to the current directory (so it starts with "./").
func normalizePath(src string) string {
	return "." + files.ToNixPath(filepath.Join("/", src))
}

// this is needed because the data.tar.gz file should have the empty folders
// as well, so we walk through the dst and create all subfolders.
func createTree(tarw *tar.Writer, dst string, created map[string]bool) error {
	for _, path := range pathsToCreate(dst) {
		path = normalizePath(path) + "/"

		if created[path] {
			// skipping dir that was previously created inside the archive
			// (eg: usr/)
			continue
		}
		if err := tarw.WriteHeader(&tar.Header{
			Name:     path,
			Mode:     0755,
			Typeflag: tar.TypeDir,
			Format:   tar.FormatGNU,
			ModTime:  time.Now(),
		}); err != nil {
			return fmt.Errorf("failed to create folder: %w", err)
		}
		created[path] = true
	}
	return nil
}

func pathsToCreate(dst string) []string {
	var paths = []string{}
	var base = strings.TrimPrefix(dst, "/")
	for {
		base = filepath.Dir(base)
		if base == "." {
			break
		}
		paths = append(paths, files.ToNixPath(base))
	}
	// we don't really need to create those things in order apparently, but,
	// it looks really weird if we don't.
	var result = []string{}
	for i := len(paths) - 1; i >= 0; i-- {
		result = append(result, paths[i])
	}
	return result
}

func conffiles(info *nfpm.Info) []byte {
	// nolint: prealloc
	var confs []string
	for _, dst := range info.ConfigFiles {
		confs = append(confs, dst)
	}
	return []byte(strings.Join(confs, "\n") + "\n")
}

func createTriggers(info *nfpm.Info) []byte {
	var buffer bytes.Buffer

	// https://man7.org/linux/man-pages/man5/deb-triggers.5.html
	triggerEntries := []struct {
		Directive    string
		TriggerNames *[]string
	}{
		{"interest", &info.Deb.Triggers.Interest},
		{"interest-await", &info.Deb.Triggers.InterestAwait},
		{"interest-noawait", &info.Deb.Triggers.InterestNoAwait},
		{"activate", &info.Deb.Triggers.Activate},
		{"activate-await", &info.Deb.Triggers.ActivateAwait},
		{"activate-noawait", &info.Deb.Triggers.ActivateNoAwait},
	}

	for _, triggerEntry := range triggerEntries {
		for _, triggerName := range *triggerEntry.TriggerNames {
			fmt.Fprintf(&buffer, "%s %s\n", triggerEntry.Directive, triggerName)
		}
	}

	return buffer.Bytes()
}

const controlTemplate = `
{{- /* Mandatory fields */ -}}
Package: {{.Info.Name}}
Version: {{ if .Info.Epoch}}{{ .Info.Epoch }}:{{ end }}{{.Info.Version}}
         {{- if .Info.Release}}-{{ .Info.Release }}{{- end }}
         {{- if .Info.Prerelease}}~{{ .Info.Prerelease }}{{- end }}
         {{- if .Info.VersionMetadata}}+{{ .Info.VersionMetadata }}{{- end }}
Section: {{.Info.Section}}
Priority: {{.Info.Priority}}
Architecture: {{.Info.Arch}}
{{- /* Optional fields */ -}}
{{- if .Info.Maintainer}}
Maintainer: {{.Info.Maintainer}}
{{- end }}
{{- if .Info.Vendor}}
Vendor: {{.Info.Vendor}}
{{- end }}
Installed-Size: {{.InstalledSize}}
{{- with .Info.Replaces}}
Replaces: {{join .}}
{{- end }}
{{- with .Info.Provides}}
Provides: {{join .}}
{{- end }}
{{- with .Info.Depends}}
Depends: {{join .}}
{{- end }}
{{- with .Info.Recommends}}
Recommends: {{join .}}
{{- end }}
{{- with .Info.Suggests}}
Suggests: {{join .}}
{{- end }}
{{- with .Info.Conflicts}}
Conflicts: {{join .}}
{{- end }}
{{- with .Info.Deb.Breaks}}
Breaks: {{join .}}
{{- end }}
{{- if .Info.Homepage}}
Homepage: {{.Info.Homepage}}
{{- end }}
{{- /* Mandatory fields */}}
Description: {{multiline .Info.Description}}
`

type controlData struct {
	Info          *nfpm.Info
	InstalledSize int64
}

func writeControl(w io.Writer, data controlData) error {
	var tmpl = template.New("control")
	tmpl.Funcs(template.FuncMap{
		"join": func(strs []string) string {
			return strings.Trim(strings.Join(strs, ", "), " ")
		},
		"multiline": func(strs string) string {
			ret := strings.ReplaceAll(strs, "\n", "\n  ")
			return strings.Trim(ret, " \n")
		},
	})
	return template.Must(tmpl.Parse(controlTemplate)).Execute(w, data)
}
