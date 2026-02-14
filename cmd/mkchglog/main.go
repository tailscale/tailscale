// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package main implements mkchglog, a tool to convert Tailscale's internal MDX
// changelogs into a structured YAML format for release automation tools like
// goreleaser/chlog or mkpkg.
//
// The tool performs the following:
//  1. Extracts 'clientVersion' from the YAML frontmatter to determine the version.
//  2. Extracts bullet points specifically from the "##### All Platforms"
//     and "##### Linux" sections.
//  3. Cleans entries by removing GitHub PR links (#1234), user tags (@user),
//     markdown link syntax [text](url), stripping backticks, brackets, and kb-links.
//  4. Formats the output into a YAML schema compatible with mkpkg and goreleaser,
//     supporting target-specific configurations (e.g., deb, rpm).
//
// Authentication:
// For private repositories, the tool uses the GITHUB_TOKEN or TS_GITHUB_TOKEN
// environment variables.
//
// Usage:
//
//	export GITHUB_TOKEN=$(gh auth token)
//	go run ./cmd/mkchglog [flags] <file_path | github_url>
//
// Flags:
//
//	--target   Target package type (e.g., "deb", "rpm"). Defaults to "deb".
//	--date     Release date in YYYY-MM-DD format. Defaults to current time.
//	--urgency  Release urgency (e.g., "low", "medium", "high"). Defaults to "medium".
//	--dist     Target distribution (e.g., "stable", "unstable"). Defaults to "unstable".
//	--maint    Packager identification string.
//	--debug    Enable verbose logging to stderr.
//
// Example:
//
//	go run ./cmd/mkchglog --target deb --dist stable --date 2026-01-27 \
//	  https://raw.githubusercontent.com/tailscale/tailscale-www/main/nextjs/src/data/changelog/2026/2026-01-27-client.mdx
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

var (
	debug   = flag.Bool("debug", false, "enable debug logging")
	dateArg = flag.String("date", "", "release date (YYYY-MM-DD)")
	target  = flag.String("target", "deb", "target package type (e.g., deb, rpm)")
	urgency = flag.String("urgency", "medium", "release urgency")
	dist    = flag.String("dist", "unstable", "target distribution")
	maint   = flag.String("maint", "Tailscale Inc <info@tailscale.com>", "packager identification")

	rePR    = regexp.MustCompile(`\s*\(#\d+\)`)
	reUser  = regexp.MustCompile(`\s*@[\w-]+`)
	reLinks = regexp.MustCompile(`\[([^\]]+)\]\([^\)]+\)`)
	reKbs   = regexp.MustCompile(`\[kb-[\w-]+\]`)
)

// OutputSchema matches a single version entry in the YAML list structure
// expected by chlog/mkpkg.
type OutputSchema struct {
	Deb          *DebConfig    `yaml:"deb,omitempty"`
	Semver       string        `yaml:"semver"`
	Date         string        `yaml:"date"`
	Packager     string        `yaml:"packager"`
	Urgency      string        `yaml:"urgency"`
	Distribution string        `yaml:"distribution"`
	Changes      []ChangeEntry `yaml:"changes"`
}

type DebConfig struct {
	Urgency       string   `yaml:"urgency"`
	Distributions []string `yaml:"distributions"`
}

type ChangeEntry struct {
	Note string `yaml:"note"`
}

type changelogData struct {
	Version string
	Items   []string
}

func main() {
	flag.Parse()
	args := flag.Args()

	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: mkchglog [flags] <file_path_or_github_url>\n")
		os.Exit(1)
	}

	releaseDate := time.Now()
	if *dateArg != "" {
		if parsed, err := time.Parse("2006-01-02", *dateArg); err == nil {
			releaseDate = parsed
		} else {
			fmt.Fprintf(os.Stderr, "invalid date format: %v\n", err)
			os.Exit(1)
		}
	}

	input := args[0]
	var rc io.ReadCloser
	var err error

	if strings.HasPrefix(input, "http") {
		rc, err = fetchURL(input)
	} else {
		rc, err = os.Open(input)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer rc.Close()

	data, err := parseMDX(rc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse error: %v\n", err)
		os.Exit(1)
	}

	// Build the single entry.
	entry := OutputSchema{
		Semver:       data.Version,
		Date:         releaseDate.Format(time.RFC3339),
		Packager:     *maint,
		Urgency:      *urgency,
		Distribution: *dist,
	}

	if *target == "deb" {
		entry.Deb = &DebConfig{
			Urgency:       *urgency,
			Distributions: []string{*dist},
		}
	}

	for _, item := range data.Items {
		entry.Changes = append(entry.Changes, ChangeEntry{Note: item})
	}

	// Wrap in a slice so the output is a YAML list (-), as required by chlog.
	out := []OutputSchema{entry}

	enc := yaml.NewEncoder(os.Stdout)
	enc.SetIndent(2)
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "yaml encode error: %v\n", err)
		os.Exit(1)
	}
}

func fetchURL(urlStr string) (io.ReadCloser, error) {
	cleanURL := urlStr
	if idx := strings.Index(cleanURL, "?"); idx != -1 {
		cleanURL = cleanURL[:idx]
	}
	if strings.Contains(cleanURL, "github.com") && !strings.Contains(cleanURL, "raw.githubusercontent.com") {
		cleanURL = strings.Replace(cleanURL, "github.com", "raw.githubusercontent.com", 1)
		cleanURL = strings.Replace(cleanURL, "/blob/", "/", 1)
	}

	if *debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] Fetching URL: %s\n", cleanURL)
	}

	req, _ := http.NewRequest("GET", cleanURL, nil)
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("TS_GITHUB_TOKEN")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("http error: %s", resp.Status)
	}
	return resp.Body, nil
}

func parseMDX(r io.Reader) (*changelogData, error) {
	data := &changelogData{Version: "unknown"}
	var (
		recording        bool
		inFrontmatter    bool
		frontmatterCount int
		scanner          = bufio.NewScanner(r)
	)

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "---" {
			frontmatterCount++
			inFrontmatter = (frontmatterCount == 1)
			continue
		}
		if inFrontmatter {
			if strings.HasPrefix(trimmed, "clientVersion:") {
				data.Version = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "clientVersion:")), `"'`)
			}
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			lower := strings.ToLower(trimmed)
			if strings.Contains(lower, "all platforms") || strings.Contains(lower, "linux") {
				recording = true
				if *debug {
					fmt.Fprintf(os.Stderr, "[DEBUG] START recording at header: %q\n", trimmed)
				}
			} else if strings.Contains(lower, "ios") || strings.Contains(lower, "macos") ||
				strings.Contains(lower, "windows") || strings.Contains(lower, "android") {
				if recording && *debug {
					fmt.Fprintf(os.Stderr, "[DEBUG] STOP recording at header: %q\n", trimmed)
				}
				recording = false
			}
			continue
		}
		if recording && isBullet(trimmed) {
			clean := cleanLine(stripBullet(trimmed))
			if clean != "" {
				data.Items = append(data.Items, clean)
			}
		}
	}
	return data, scanner.Err()
}

func isBullet(s string) bool {
	if len(s) < 2 {
		return false
	}
	return (s[0] == '*' || s[0] == '-' || s[0] == '+') && unicode.IsSpace(rune(s[1]))
}

func stripBullet(s string) string {
	return strings.TrimSpace(strings.TrimLeftFunc(s, func(r rune) bool {
		return r == '*' || r == '-' || r == '+' || unicode.IsSpace(r)
	}))
}

func cleanLine(s string) string {
	s = rePR.ReplaceAllString(s, "")
	s = reUser.ReplaceAllString(s, "")
	s = reLinks.ReplaceAllString(s, "$1")
	s = reKbs.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "[", "")
	s = strings.ReplaceAll(s, "]", "")
	return strings.TrimSpace(s)
}
