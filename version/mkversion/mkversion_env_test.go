// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package mkversion

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// gitIn runs git with args in dir and returns its trimmed output, failing
// the test on error.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_SYSTEM="+os.DevNull,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v (in %s): %v\n%s", args, dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

// newTestRepos builds a synthetic tailscale.com repo whose VERSION.txt says
// versionTxt with commitsPast commits after the version bump, and a corp-like
// repo whose go.mod pins that tailscale.com head via a pseudo-version.
// It returns both working checkouts.
func newTestRepos(t *testing.T, versionTxt string, commitsPast int) (ossSrc, corpSrc string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git not available: %v", err)
	}
	ossSrc, corpSrc = t.TempDir(), t.TempDir()

	gitIn(t, ossSrc, "init", "-q", "-b", "main")
	for name, contents := range map[string]string{
		"VERSION.txt": versionTxt + "\n",
		"go.mod":      "module tailscale.com\n\ngo 1.25\n",
	} {
		if err := os.WriteFile(filepath.Join(ossSrc, name), []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
	}
	gitIn(t, ossSrc, "add", ".")
	gitIn(t, ossSrc, "commit", "-q", "-m", "version bump")
	for range commitsPast {
		gitIn(t, ossSrc, "commit", "-q", "--allow-empty", "-m", "change")
	}
	ossHead := gitIn(t, ossSrc, "rev-parse", "HEAD")

	gitIn(t, corpSrc, "init", "-q", "-b", "main")
	goMod := "module tailscale.io\n\ngo 1.25\n\nrequire tailscale.com v" +
		versionTxt + "-pre.0.20260101000000-" + ossHead[:12] + "\n"
	if err := os.WriteFile(filepath.Join(corpSrc, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, corpSrc, "add", "go.mod")
	gitIn(t, corpSrc, "commit", "-q", "-m", "pin oss")
	return ossSrc, corpSrc
}

// clearVersionEnv unsets every environment variable mkversion consults so
// each test starts from the git-derived default.
func clearVersionEnv(t *testing.T) {
	for _, k := range []string{
		envVersionLong, envGitHash, envExtraGitHash, envGitDate, envExtraGitDate,
		envVersionOverride, "TS_MKVERSION_OSS_GIT_CACHE",
	} {
		t.Setenv(k, "")
	}
}

// setVersionEnv sets the TS_VERSION_* variables to describe v, as a
// build system that already knows the version would.
func setVersionEnv(t *testing.T, v VersionInfo) {
	t.Setenv(envVersionLong, v.Long)
	t.Setenv(envGitHash, v.GitHash)
	t.Setenv(envExtraGitHash, v.OtherHash)
	t.Setenv(envGitDate, v.GitDate)
	t.Setenv(envExtraGitDate, v.OtherDate)
}

// TestInfoFromEnvMatchesGit checks that a VersionInfo derived from git,
// fed back through the environment variables in a directory with no
// checkout at all, reproduces itself exactly.
func TestInfoFromEnvMatchesGit(t *testing.T) {
	tests := []struct {
		name        string
		versionTxt  string
		commitsPast int
	}{
		{"unstable_with_commits", "1.99.0", 3},
		{"stable_at_tag", "1.98.0", 0},
		{"stable_past_tag", "1.98.2", 2},
	}
	for _, tt := range tests {
		for _, corp := range []bool{false, true} {
			name := tt.name + "_oss"
			if corp {
				name = tt.name + "_corp"
			}
			t.Run(name, func(t *testing.T) {
				clearVersionEnv(t)
				ossSrc, corpSrc := newTestRepos(t, tt.versionTxt, tt.commitsPast)

				dir := ossSrc
				if corp {
					dir = corpSrc
					t.Setenv("TS_MKVERSION_OSS_GIT_CACHE", ossSrc)
				}
				want, err := InfoFrom(dir)
				if err != nil {
					t.Fatalf("InfoFrom via git: %v", err)
				}
				if want.GitDate == "" {
					t.Fatal("git path produced no GitDate")
				}
				if corp && want.OtherHash == "" {
					t.Fatal("corp git path produced no OtherHash")
				}
				if !corp && want.OtherHash != "" {
					t.Fatalf("OSS git path produced OtherHash %q", want.OtherHash)
				}

				setVersionEnv(t, want)
				got, err := InfoFrom(t.TempDir())
				if err != nil {
					t.Fatalf("InfoFrom via env: %v", err)
				}
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("env result differs from git result (-git +env):\n%s", diff)
				}
			})
		}
	}
}

// TestInfoFromEnvPrecedence checks that TS_VERSION_LONG wins over a real
// checkout with a different version, without running git.
func TestInfoFromEnvPrecedence(t *testing.T) {
	clearVersionEnv(t)
	ossSrc, _ := newTestRepos(t, "1.98.0", 0)
	fromGit, err := InfoFrom(ossSrc)
	if err != nil {
		t.Fatal(err)
	}

	const hash = "8895cec85d3a2f0b1c4e6d7f8a9b0c1d2e3f4a5b"
	t.Setenv(envVersionLong, "1.99.5-t"+shortHash(hash))
	t.Setenv(envGitHash, hash)
	t.Setenv("PATH", t.TempDir()) // no git binary reachable

	got, err := InfoFrom(ossSrc)
	if err != nil {
		t.Fatalf("InfoFrom: %v", err)
	}
	if got.Long == fromGit.Long {
		t.Fatalf("got git-derived version %q; want the environment's", got.Long)
	}
	want := VersionInfo{
		Major:   1,
		Minor:   99,
		Patch:   5,
		Short:   "1.99.5",
		Long:    "1.99.5-t8895cec85",
		GitHash: hash,
		Track:   "unstable",
		Synology: map[int]int64{
			60: 600099005,
			70: 700099005,
			72: 720099005,
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("wrong result (-want +got):\n%s", diff)
	}
}

// TestInfoFromEnvParsing covers the environment-only path on inputs a
// build system would supply, with no git involved.
func TestInfoFromEnvParsing(t *testing.T) {
	const (
		tHash = "8895cec85d3a2f0b1c4e6d7f8a9b0c1d2e3f4a5b"
		gHash = "15581c318e7a9b0c1d2e3f4a5b6c7d8e9f0a1b2c"
	)
	tests := []struct {
		name string
		env  map[string]string
		want VersionInfo
	}{
		{
			name: "unstable_oss",
			env: map[string]string{
				envVersionLong: "1.99.5-t8895cec85",
				envGitHash:     tHash,
				envGitDate:     "1700000000",
			},
			want: VersionInfo{
				Major: 1, Minor: 99, Patch: 5,
				Short:   "1.99.5",
				Long:    "1.99.5-t8895cec85",
				GitHash: tHash,
				GitDate: "1700000000",
				Track:   "unstable",
			},
		},
		{
			name: "stable_past_tag_corp",
			env: map[string]string{
				envVersionLong:  "1.98.2-3-t8895cec85-g15581c318",
				envGitHash:      tHash,
				envExtraGitHash: gHash,
				envGitDate:      "1700000000",
				envExtraGitDate: "1674781323", // 2023-01-27 01:02:03 UTC
			},
			want: VersionInfo{
				Major: 1, Minor: 98, Patch: 2,
				Short:      "1.98.2",
				Long:       "1.98.2-3-t8895cec85-g15581c318",
				GitHash:    tHash,
				GitDate:    "1700000000",
				OtherHash:  gHash,
				OtherDate:  "1674781323",
				Track:      "stable",
				Xcode:      "101.98.2",
				XcodeMacOS: "274.27.3723",
				Winres:     "1,98,2,0",
			},
		},
		{
			name: "stable_at_tag_corp_no_dates",
			env: map[string]string{
				envVersionLong:  "1.98.0-t8895cec85-g15581c318",
				envGitHash:      tHash,
				envExtraGitHash: gHash,
			},
			want: VersionInfo{
				Major: 1, Minor: 98, Patch: 0,
				Short:     "1.98.0",
				Long:      "1.98.0-t8895cec85-g15581c318",
				GitHash:   tHash,
				OtherHash: gHash,
				Track:     "stable",
				Xcode:     "101.98.0",
				Winres:    "1,98,0,0",
			},
		},
	}
	// Synology and MSIProductCodes are pure functions of the version
	// number already covered by TestMkversion, so compare the rest.
	ignore := cmp.FilterPath(func(p cmp.Path) bool {
		switch p.Last().String() {
		case ".Synology", ".MSIProductCodes":
			return true
		}
		return false
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearVersionEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			got, err := InfoFrom(t.TempDir())
			if err != nil {
				t.Fatalf("InfoFrom: %v", err)
			}
			if diff := cmp.Diff(tt.want, got, ignore); diff != "" {
				t.Errorf("wrong result (-want +got):\n%s", diff)
			}
			if tt.want.OtherHash != "" && len(got.MSIProductCodes) != 3 {
				t.Errorf("MSIProductCodes = %v; want 3 entries", got.MSIProductCodes)
			}
		})
	}
}

// TestInfoFromEnvRejects checks that every malformed or inconsistent
// combination of the environment variables is rejected with an error that
// names the offending variable.
func TestInfoFromEnvRejects(t *testing.T) {
	const (
		tHash = "8895cec85d3a2f0b1c4e6d7f8a9b0c1d2e3f4a5b"
		gHash = "15581c318e7a9b0c1d2e3f4a5b6c7d8e9f0a1b2c"
	)
	// good is a valid corp-style input; each case overrides parts of it.
	good := map[string]string{
		envVersionLong:  "1.98.2-3-t8895cec85-g15581c318",
		envGitHash:      tHash,
		envExtraGitHash: gHash,
		envGitDate:      "1700000000",
		envExtraGitDate: "1700000001",
	}
	tests := []struct {
		name    string
		env     map[string]string // overrides applied to good
		wantVar string            // variable the error must mention
	}{
		{
			name:    "long_missing_t_hash",
			env:     map[string]string{envVersionLong: "1.98.2", envExtraGitHash: ""},
			wantVar: envVersionLong,
		},
		{
			name:    "long_short_t_hash",
			env:     map[string]string{envVersionLong: "1.98.2-t8895cec", envExtraGitHash: ""},
			wantVar: envVersionLong,
		},
		{
			name:    "long_uppercase_hash",
			env:     map[string]string{envVersionLong: "1.98.2-t8895CEC85", envExtraGitHash: ""},
			wantVar: envVersionLong,
		},
		{
			name:    "long_trailing_garbage",
			env:     map[string]string{envVersionLong: "1.98.2-3-t8895cec85-g15581c318-dirty"},
			wantVar: envVersionLong,
		},
		{
			name:    "long_unstable_with_change_count",
			env:     map[string]string{envVersionLong: "1.99.5-2-t8895cec85-g15581c318"},
			wantVar: envVersionLong,
		},
		{
			name:    "long_stable_zero_change_count_no_roundtrip",
			env:     map[string]string{envVersionLong: "1.98.2-0-t8895cec85-g15581c318"},
			wantVar: envVersionLong,
		},
		{
			name:    "long_leading_zero_no_roundtrip",
			env:     map[string]string{envVersionLong: "1.98.02-t8895cec85-g15581c318"},
			wantVar: envVersionLong,
		},
		{
			name:    "git_hash_missing",
			env:     map[string]string{envGitHash: ""},
			wantVar: envGitHash,
		},
		{
			name:    "git_hash_short",
			env:     map[string]string{envGitHash: "8895cec85"},
			wantVar: envGitHash,
		},
		{
			name:    "git_hash_uppercase",
			env:     map[string]string{envGitHash: strings.ToUpper(tHash)},
			wantVar: envGitHash,
		},
		{
			name:    "git_hash_mismatch",
			env:     map[string]string{envGitHash: gHash},
			wantVar: envGitHash,
		},
		{
			name:    "extra_hash_missing",
			env:     map[string]string{envExtraGitHash: ""},
			wantVar: envExtraGitHash,
		},
		{
			name:    "extra_hash_short",
			env:     map[string]string{envExtraGitHash: "15581c318"},
			wantVar: envExtraGitHash,
		},
		{
			name:    "extra_hash_mismatch",
			env:     map[string]string{envExtraGitHash: tHash},
			wantVar: envExtraGitHash,
		},
		{
			name:    "extra_hash_without_g_part",
			env:     map[string]string{envVersionLong: "1.98.2-3-t8895cec85"},
			wantVar: envExtraGitHash,
		},
		{
			name:    "extra_date_without_g_part",
			env:     map[string]string{envVersionLong: "1.98.2-3-t8895cec85", envExtraGitHash: ""},
			wantVar: envExtraGitDate,
		},
		{
			name:    "git_date_not_integer",
			env:     map[string]string{envGitDate: "2023-01-27"},
			wantVar: envGitDate,
		},
		{
			name:    "git_date_negative",
			env:     map[string]string{envGitDate: "-1"},
			wantVar: envGitDate,
		},
		{
			name:    "extra_date_not_integer",
			env:     map[string]string{envExtraGitDate: "soon"},
			wantVar: envExtraGitDate,
		},
		{
			name:    "override_also_set",
			env:     map[string]string{envVersionOverride: "1.2.3"},
			wantVar: envVersionOverride,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearVersionEnv(t)
			for k, v := range good {
				t.Setenv(k, v)
			}
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			got, err := InfoFrom(t.TempDir())
			if err == nil {
				t.Fatalf("InfoFrom succeeded with %+v; want error mentioning %s", got, tt.wantVar)
			}
			if !strings.Contains(err.Error(), tt.wantVar) {
				t.Errorf("error %q does not mention %s", err, tt.wantVar)
			}
		})
	}

	// And the baseline must be accepted, or the table proves nothing.
	clearVersionEnv(t)
	for k, v := range good {
		t.Setenv(k, v)
	}
	if _, err := InfoFrom(t.TempDir()); err != nil {
		t.Fatalf("baseline input rejected: %v", err)
	}
}
