// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package clientupdate

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

func TestUpdateDebianAptSourcesListBytes(t *testing.T) {
	tests := []struct {
		name    string
		toTrack string
		in      string
		want    string // empty means want no change
		wantErr string
	}{
		{
			name:    "stable-to-unstable",
			toTrack: UnstableTrack,
			in:      "# Tailscale packages for debian buster\ndeb https://pkgs.tailscale.com/stable/debian bullseye main\n",
			want:    "# Tailscale packages for debian buster\ndeb https://pkgs.tailscale.com/unstable/debian bullseye main\n",
		},
		{
			name:    "stable-unchanged",
			toTrack: StableTrack,
			in:      "# Tailscale packages for debian buster\ndeb https://pkgs.tailscale.com/stable/debian bullseye main\n",
		},
		{
			name:    "if-both-stable-and-unstable-dont-change",
			toTrack: StableTrack,
			in: "# Tailscale packages for debian buster\n" +
				"deb https://pkgs.tailscale.com/stable/debian bullseye main\n" +
				"deb https://pkgs.tailscale.com/unstable/debian bullseye main\n",
		},
		{
			name:    "if-both-stable-and-unstable-dont-change-unstable",
			toTrack: UnstableTrack,
			in: "# Tailscale packages for debian buster\n" +
				"deb https://pkgs.tailscale.com/stable/debian bullseye main\n" +
				"deb https://pkgs.tailscale.com/unstable/debian bullseye main\n",
		},
		{
			name:    "signed-by-form",
			toTrack: UnstableTrack,
			in:      "# Tailscale packages for ubuntu jammy\ndeb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/ubuntu jammy main\n",
			want:    "# Tailscale packages for ubuntu jammy\ndeb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/unstable/ubuntu jammy main\n",
		},
		{
			name:    "unsupported-lines",
			toTrack: UnstableTrack,
			in:      "# Tailscale packages for ubuntu jammy\ndeb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/foobar/ubuntu jammy main\n",
			wantErr: "unexpected/unsupported /etc/apt/sources.list.d/tailscale.list contents",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newContent, err := updateDebianAptSourcesListBytes([]byte(tt.in), tt.toTrack)
			if err != nil {
				if err.Error() != tt.wantErr {
					t.Fatalf("error = %v; want %q", err, tt.wantErr)
				}
				return
			}
			if tt.wantErr != "" {
				t.Fatalf("got no error; want %q", tt.wantErr)
			}
			var gotChange string
			if string(newContent) != tt.in {
				gotChange = string(newContent)
			}
			if gotChange != tt.want {
				t.Errorf("wrong result\n got: %q\nwant: %q", gotChange, tt.want)
			}
		})
	}
}

var YUMRepos = map[string]string{
	StableTrack: `
[tailscale-stable]
name=Tailscale stable
baseurl=https://pkgs.tailscale.com/stable/fedora/$basearch
enabled=1
type=rpm
repo_gpgcheck=1
gpgcheck=0
gpgkey=https://pkgs.tailscale.com/stable/fedora/repo.gpg
`,

	UnstableTrack: `
[tailscale-unstable]
name=Tailscale unstable
baseurl=https://pkgs.tailscale.com/unstable/fedora/$basearch
enabled=1
type=rpm
repo_gpgcheck=1
gpgcheck=0
gpgkey=https://pkgs.tailscale.com/unstable/fedora/repo.gpg
`,

	ReleaseCandidateTrack: `
[tailscale-release-candidate]
name=Tailscale release-candidate
baseurl=https://pkgs.tailscale.com/release-candidate/fedora/$basearch
enabled=1
type=rpm
repo_gpgcheck=1
gpgcheck=0
gpgkey=https://pkgs.tailscale.com/release-candidate/fedora/repo.gpg
`,

	"FakeRepo": `
[fedora]
name=Fedora $releasever - $basearch
#baseurl=http://download.example/pub/fedora/linux/releases/$releasever/Everything/$basearch/os/
metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-$releasever&arch=$basearch
enabled=1
countme=1
metadata_expire=7d
repo_gpgcheck=0
type=rpm
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-$releasever-$basearch
skip_if_unavailable=False`,
}

func TestUpdateYUMRepoTrack(t *testing.T) {
	tests := []struct {
		desc    string
		before  string
		track   string
		after   string
		rewrote bool
		wantErr bool
	}{
		{
			desc:   "same track",
			before: YUMRepos[StableTrack],
			track:  StableTrack,
			after:  YUMRepos[StableTrack],
		},
		{
			desc:    "change track",
			before:  YUMRepos[StableTrack],
			track:   UnstableTrack,
			after:   YUMRepos[UnstableTrack],
			rewrote: true,
		},
		{
			desc:    "change track RC",
			before:  YUMRepos[StableTrack],
			track:   ReleaseCandidateTrack,
			after:   YUMRepos[ReleaseCandidateTrack],
			rewrote: true,
		},
		{
			desc:    "non-tailscale repo file",
			before:  YUMRepos["FakeRepo"],
			track:   StableTrack,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tailscale.repo")
			if err := os.WriteFile(path, []byte(tt.before), 0644); err != nil {
				t.Fatal(err)
			}

			rewrote, err := updateYUMRepoTrack(path, tt.track)
			if err == nil && tt.wantErr {
				t.Fatal("got nil error, want non-nil")
			}
			if err != nil && !tt.wantErr {
				t.Fatalf("got error %q, want nil", err)
			}
			if err != nil {
				return
			}
			if rewrote != tt.rewrote {
				t.Errorf("got rewrote flag %v, want %v", rewrote, tt.rewrote)
			}

			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != tt.after {
				t.Errorf("got repo file after update:\n%swant:\n%s", after, tt.after)
			}
		})
	}
}

func TestParseAlpinePackageVersion(t *testing.T) {
	tests := []struct {
		desc    string
		out     string
		want    string
		wantErr bool
	}{
		{
			desc: "valid version",
			out: `
tailscale-1.44.2-r0 description:
The easiest, most secure way to use WireGuard and 2FA

tailscale-1.44.2-r0 webpage:
https://tailscale.com/

tailscale-1.44.2-r0 installed size:
32 MiB
`,
			want: "1.44.2",
		},
		{
			desc: "wrong package output",
			out: `
busybox-1.36.1-r0 description:
Size optimized toolbox of many common UNIX utilities

busybox-1.36.1-r0 webpage:
https://busybox.net/

busybox-1.36.1-r0 installed size:
924 KiB
`,
			wantErr: true,
		},
		{
			desc: "missing version",
			out: `
tailscale description:
The easiest, most secure way to use WireGuard and 2FA

tailscale webpage:
https://tailscale.com/

tailscale installed size:
32 MiB
`,
			wantErr: true,
		},
		{
			desc:    "empty output",
			out:     "",
			wantErr: true,
		},
		{
			desc: "multiple versions",
			out: `
tailscale-1.54.1-r0 description:
The easiest, most secure way to use WireGuard and 2FA

tailscale-1.54.1-r0 webpage:
https://tailscale.com/

tailscale-1.54.1-r0 installed size:
34 MiB

tailscale-1.58.2-r0 description:
The easiest, most secure way to use WireGuard and 2FA

tailscale-1.58.2-r0 webpage:
https://tailscale.com/

tailscale-1.58.2-r0 installed size:
35 MiB
`,
			want: "1.58.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got, err := parseAlpinePackageVersion([]byte(tt.out))
			if err == nil && tt.wantErr {
				t.Fatalf("got nil error and version %q, want non-nil error", got)
			}
			if err != nil && !tt.wantErr {
				t.Fatalf("got error: %q, want nil", err)
			}
			if got != tt.want {
				t.Fatalf("got version: %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSynoArch(t *testing.T) {
	tests := []struct {
		goarch         string
		synoinfoUnique string
		want           string
		wantErr        bool
	}{
		{goarch: "amd64", synoinfoUnique: "synology_x86_224", want: "x86_64"},
		{goarch: "arm64", synoinfoUnique: "synology_armv8_124", want: "armv8"},
		{goarch: "386", synoinfoUnique: "synology_i686_415play", want: "i686"},
		{goarch: "arm", synoinfoUnique: "synology_88f6281_213air", want: "88f6281"},
		{goarch: "arm", synoinfoUnique: "synology_88f6282_413j", want: "88f6282"},
		{goarch: "arm", synoinfoUnique: "synology_hi3535_NVR1218", want: "hi3535"},
		{goarch: "arm", synoinfoUnique: "synology_alpine_1517", want: "alpine"},
		{goarch: "arm", synoinfoUnique: "synology_armada370_216se", want: "armada370"},
		{goarch: "arm", synoinfoUnique: "synology_armada375_115", want: "armada375"},
		{goarch: "arm", synoinfoUnique: "synology_armada38x_419slim", want: "armada38x"},
		{goarch: "arm", synoinfoUnique: "synology_armadaxp_RS815", want: "armadaxp"},
		{goarch: "arm", synoinfoUnique: "synology_comcerto2k_414j", want: "comcerto2k"},
		{goarch: "arm", synoinfoUnique: "synology_monaco_216play", want: "monaco"},
		{goarch: "ppc64", synoinfoUnique: "synology_qoriq_413", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s-%s", tt.goarch, tt.synoinfoUnique), func(t *testing.T) {
			synoinfoConfPath := filepath.Join(t.TempDir(), "synoinfo.conf")
			if err := os.WriteFile(
				synoinfoConfPath,
				[]byte(fmt.Sprintf("unique=%q\n", tt.synoinfoUnique)),
				0600,
			); err != nil {
				t.Fatal(err)
			}
			got, err := synoArch(tt.goarch, synoinfoConfPath)
			if err != nil {
				if !tt.wantErr {
					t.Fatalf("got unexpected error %v", err)
				}
				return
			}
			if tt.wantErr {
				t.Fatalf("got %q, expected an error", got)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSynoinfo(t *testing.T) {
	tests := []struct {
		desc    string
		content string
		want    string
		wantErr bool
	}{
		{
			desc: "double-quoted",
			content: `
company_title="Synology"
unique="synology_88f6281_213air"
`,
			want: "88f6281",
		},
		{
			desc: "single-quoted",
			content: `
company_title="Synology"
unique='synology_88f6281_213air'
`,
			want: "88f6281",
		},
		{
			desc: "unquoted",
			content: `
company_title="Synology"
unique=synology_88f6281_213air
`,
			want: "88f6281",
		},
		{
			desc: "missing unique",
			content: `
company_title="Synology"
`,
			wantErr: true,
		},
		{
			desc: "empty unique",
			content: `
company_title="Synology"
unique=
`,
			wantErr: true,
		},
		{
			desc: "empty unique double-quoted",
			content: `
company_title="Synology"
unique=""
`,
			wantErr: true,
		},
		{
			desc: "empty unique single-quoted",
			content: `
company_title="Synology"
unique=''
`,
			wantErr: true,
		},
		{
			desc: "malformed unique",
			content: `
company_title="Synology"
unique="synology_88f6281"
`,
			wantErr: true,
		},
		{
			desc:    "empty file",
			content: ``,
			wantErr: true,
		},
		{
			desc: "empty lines and comments",
			content: `

# In a file named synoinfo? Shocking!
company_title="Synology"


# unique= is_a_field_that_follows
unique="synology_88f6281_213air"

`,
			want: "88f6281",
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			synoinfoConfPath := filepath.Join(t.TempDir(), "synoinfo.conf")
			if err := os.WriteFile(synoinfoConfPath, []byte(tt.content), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := parseSynoinfo(synoinfoConfPath)
			if err != nil {
				if !tt.wantErr {
					t.Fatalf("got unexpected error %v", err)
				}
				return
			}
			if tt.wantErr {
				t.Fatalf("got %q, expected an error", got)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUnpackLinuxTarball(t *testing.T) {
	oldBinaryPaths := binaryPaths
	t.Cleanup(func() { binaryPaths = oldBinaryPaths })

	tests := []struct {
		desc    string
		tarball map[string]string
		before  map[string]string
		after   map[string]string
		wantErr bool
	}{
		{
			desc: "success",
			before: map[string]string{
				"tailscale":  "v1",
				"tailscaled": "v1",
			},
			tarball: map[string]string{
				"/usr/bin/tailscale":  "v2",
				"/usr/bin/tailscaled": "v2",
			},
			after: map[string]string{
				"tailscale":  "v2",
				"tailscaled": "v2",
			},
		},
		{
			desc: "don't touch unrelated files",
			before: map[string]string{
				"tailscale":  "v1",
				"tailscaled": "v1",
				"foo":        "bar",
			},
			tarball: map[string]string{
				"/usr/bin/tailscale":  "v2",
				"/usr/bin/tailscaled": "v2",
			},
			after: map[string]string{
				"tailscale":  "v2",
				"tailscaled": "v2",
				"foo":        "bar",
			},
		},
		{
			desc: "unmodified",
			before: map[string]string{
				"tailscale":  "v1",
				"tailscaled": "v1",
			},
			tarball: map[string]string{
				"/usr/bin/tailscale":  "v1",
				"/usr/bin/tailscaled": "v1",
			},
			after: map[string]string{
				"tailscale":  "v1",
				"tailscaled": "v1",
			},
		},
		{
			desc: "ignore extra tarball files",
			before: map[string]string{
				"tailscale":  "v1",
				"tailscaled": "v1",
			},
			tarball: map[string]string{
				"/usr/bin/tailscale":          "v2",
				"/usr/bin/tailscaled":         "v2",
				"/systemd/tailscaled.service": "v2",
			},
			after: map[string]string{
				"tailscale":  "v2",
				"tailscaled": "v2",
			},
		},
		{
			desc: "tarball missing tailscaled",
			before: map[string]string{
				"tailscale":  "v1",
				"tailscaled": "v1",
			},
			tarball: map[string]string{
				"/usr/bin/tailscale": "v2",
			},
			after: map[string]string{
				"tailscale":     "v1",
				"tailscale.new": "v2",
				"tailscaled":    "v1",
			},
			wantErr: true,
		},
		{
			desc: "duplicate tailscale binary",
			before: map[string]string{
				"tailscale":  "v1",
				"tailscaled": "v1",
			},
			tarball: map[string]string{
				"/usr/bin/tailscale":  "v2",
				"/usr/sbin/tailscale": "v2",
				"/usr/bin/tailscaled": "v2",
			},
			after: map[string]string{
				"tailscale":      "v1",
				"tailscale.new":  "v2",
				"tailscaled":     "v1",
				"tailscaled.new": "v2",
			},
			wantErr: true,
		},
		{
			desc: "empty archive",
			before: map[string]string{
				"tailscale":  "v1",
				"tailscaled": "v1",
			},
			tarball: map[string]string{},
			after: map[string]string{
				"tailscale":  "v1",
				"tailscaled": "v1",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			// Swap out binaryPaths function to point at dummy file paths.
			tmp := t.TempDir()
			tailscalePath := filepath.Join(tmp, "tailscale")
			tailscaledPath := filepath.Join(tmp, "tailscaled")
			binaryPaths = func() (string, string, error) {
				return tailscalePath, tailscaledPath, nil
			}
			for name, content := range tt.before {
				if err := os.WriteFile(filepath.Join(tmp, name), []byte(content), 0755); err != nil {
					t.Fatal(err)
				}
			}
			tarPath := filepath.Join(tmp, "tailscale.tgz")
			genTarball(t, tarPath, tt.tarball)

			up := &Updater{Arguments: Arguments{Logf: t.Logf}}
			err := up.unpackLinuxTarball(tarPath)
			if err != nil {
				if !tt.wantErr {
					t.Fatalf("unexpected error: %v", err)
				}
			} else if tt.wantErr {
				t.Fatalf("unpack succeeded, expected an error")
			}

			gotAfter := make(map[string]string)
			err = filepath.WalkDir(tmp, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.Type().IsDir() {
					return nil
				}
				if path == tarPath {
					return nil
				}
				content, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				path = filepath.ToSlash(path)
				base := filepath.ToSlash(tmp)
				gotAfter[strings.TrimPrefix(path, base+"/")] = string(content)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}

			if !maps.Equal(gotAfter, tt.after) {
				t.Errorf("files after unpack: %+v, want %+v", gotAfter, tt.after)
			}
		})
	}
}

func genTarball(t *testing.T, path string, files map[string]string) {
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()
	for file, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: file,
			Size: int64(len(content)),
			Mode: 0755,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWriteFileOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test")
	for i := range 2 {
		content := fmt.Sprintf("content %d", i)
		if err := writeFile(strings.NewReader(content), path, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != content {
			t.Errorf("got content: %q, want: %q", got, content)
		}
	}
}

func TestWriteFileSymlink(t *testing.T) {
	// Test for a malicious symlink at the destination path.
	// f2 points to f1 and writeFile(f2) should not end up overwriting f1.
	tmp := t.TempDir()
	f1 := filepath.Join(tmp, "f1")
	if err := os.WriteFile(f1, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	f2 := filepath.Join(tmp, "f2")
	if err := os.Symlink(f1, f2); err != nil {
		t.Fatal(err)
	}

	if err := writeFile(strings.NewReader("new"), f2, 0600); err != nil {
		t.Errorf("writeFile(%q) failed: %v", f2, err)
	}
	want := map[string]string{
		f1: "old",
		f2: "new",
	}
	for f, content := range want {
		got, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != content {
			t.Errorf("%q: got content %q, want %q", f, got, content)
		}
	}
}

func TestCleanupOldDownloads(t *testing.T) {
	tests := []struct {
		desc     string
		before   []string
		symlinks map[string]string
		glob     string
		after    []string
	}{
		{
			desc: "MSIs",
			before: []string{
				"MSICache/tailscale-1.0.0.msi",
				"MSICache/tailscale-1.1.0.msi",
				"MSICache/readme.txt",
			},
			glob: "MSICache/*.msi",
			after: []string{
				"MSICache/readme.txt",
			},
		},
		{
			desc: "SPKs",
			before: []string{
				"tmp/tailscale-update-1/tailscale-1.0.0.spk",
				"tmp/tailscale-update-2/tailscale-1.1.0.spk",
				"tmp/readme.txt",
				"tmp/tailscale-update-3",
				"tmp/tailscale-update-4/tailscale-1.3.0",
			},
			glob: "tmp/tailscale-update*/*.spk",
			after: []string{
				"tmp/readme.txt",
				"tmp/tailscale-update-3",
				"tmp/tailscale-update-4/tailscale-1.3.0",
			},
		},
		{
			desc:   "empty-target",
			before: []string{},
			glob:   "tmp/tailscale-update*/*.spk",
			after:  []string{},
		},
		{
			desc: "keep-dirs",
			before: []string{
				"tmp/tailscale-update-1/tailscale-1.0.0.spk",
			},
			glob: "tmp/tailscale-update*",
			after: []string{
				"tmp/tailscale-update-1/tailscale-1.0.0.spk",
			},
		},
		{
			desc: "no-follow-symlinks",
			before: []string{
				"MSICache/tailscale-1.0.0.msi",
				"MSICache/tailscale-1.1.0.msi",
				"MSICache/readme.txt",
			},
			symlinks: map[string]string{
				"MSICache/tailscale-1.3.0.msi": "MSICache/tailscale-1.0.0.msi",
				"MSICache/tailscale-1.4.0.msi": "MSICache/readme.txt",
			},
			glob: "MSICache/*.msi",
			after: []string{
				"MSICache/tailscale-1.3.0.msi",
				"MSICache/tailscale-1.4.0.msi",
				"MSICache/readme.txt",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dir := t.TempDir()
			for _, p := range tt.before {
				if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, p), []byte(tt.desc), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for from, to := range tt.symlinks {
				if err := os.Symlink(filepath.Join(dir, to), filepath.Join(dir, from)); err != nil {
					t.Fatal(err)
				}
			}

			up := &Updater{Arguments: Arguments{Logf: t.Logf}}
			up.cleanupOldDownloads(filepath.Join(dir, tt.glob))

			var after []string
			if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
				if !d.IsDir() {
					after = append(after, strings.TrimPrefix(filepath.ToSlash(path), filepath.ToSlash(dir)+"/"))
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}

			sort.Strings(after)
			sort.Strings(tt.after)
			if !slices.Equal(after, tt.after) {
				t.Errorf("got files after cleanup: %q, want: %q", after, tt.after)
			}
		})
	}
}

func TestParseUnraidPluginVersion(t *testing.T) {
	tests := []struct {
		plgPath string
		wantVer string
		wantErr string
	}{
		{plgPath: "testdata/tailscale-1.52.0.plg", wantVer: "1.52.0"},
		{plgPath: "testdata/tailscale-1.54.0.plg", wantVer: "1.54.0"},
		{plgPath: "testdata/tailscale-nover.plg", wantErr: "version not found in plg file"},
		{plgPath: "testdata/tailscale-nover-path-mentioned.plg", wantErr: "version not found in plg file"},
	}
	for _, tt := range tests {
		t.Run(tt.plgPath, func(t *testing.T) {
			got, err := parseUnraidPluginVersion(tt.plgPath)
			if got != tt.wantVer {
				t.Errorf("got version: %q, want %q", got, tt.wantVer)
			}
			var gotErr string
			if err != nil {
				gotErr = err.Error()
			}
			if gotErr != tt.wantErr {
				t.Errorf("got error: %q, want %q", gotErr, tt.wantErr)
			}
		})
	}
}

func TestConfirm(t *testing.T) {
	curTrack := CurrentTrack
	defer func() { CurrentTrack = curTrack }()

	tests := []struct {
		desc      string
		fromTrack string
		toTrack   string
		fromVer   string
		toVer     string
		confirm   func(string) bool
		want      bool
	}{
		{
			desc:      "on latest stable",
			fromTrack: StableTrack,
			toTrack:   StableTrack,
			fromVer:   "1.66.0",
			toVer:     "1.66.0",
			want:      false,
		},
		{
			desc:      "stable upgrade",
			fromTrack: StableTrack,
			toTrack:   StableTrack,
			fromVer:   "1.66.0",
			toVer:     "1.68.0",
			want:      true,
		},
		{
			desc:      "unstable upgrade",
			fromTrack: UnstableTrack,
			toTrack:   UnstableTrack,
			fromVer:   "1.67.1",
			toVer:     "1.67.2",
			want:      true,
		},
		{
			desc:      "from stable to unstable",
			fromTrack: StableTrack,
			toTrack:   UnstableTrack,
			fromVer:   "1.66.0",
			toVer:     "1.67.1",
			want:      true,
		},
		{
			desc:      "from unstable to stable",
			fromTrack: UnstableTrack,
			toTrack:   StableTrack,
			fromVer:   "1.67.1",
			toVer:     "1.66.0",
			want:      true,
		},
		{
			desc:      "confirm callback rejects",
			fromTrack: StableTrack,
			toTrack:   StableTrack,
			fromVer:   "1.66.0",
			toVer:     "1.66.1",
			confirm: func(string) bool {
				return false
			},
			want: false,
		},
		{
			desc:      "confirm callback allows",
			fromTrack: StableTrack,
			toTrack:   StableTrack,
			fromVer:   "1.66.0",
			toVer:     "1.66.1",
			confirm: func(string) bool {
				return true
			},
			want: true,
		},
		{
			desc:      "downgrade",
			fromTrack: StableTrack,
			toTrack:   StableTrack,
			fromVer:   "1.66.1",
			toVer:     "1.66.0",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			CurrentTrack = tt.fromTrack
			up := Updater{
				currentVersion: tt.fromVer,
				Arguments: Arguments{
					Track:   tt.toTrack,
					Confirm: tt.confirm,
					Logf:    t.Logf,
				},
			}

			if got := up.confirm(tt.toVer); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
