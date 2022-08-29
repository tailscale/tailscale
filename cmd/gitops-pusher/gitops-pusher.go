// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command gitops-pusher allows users to use a GitOps flow for managing Tailscale ACLs.
//
// See README.md for more details.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/tailscale/hujson"
)

var (
	rootFlagSet  = flag.NewFlagSet("gitops-pusher", flag.ExitOnError)
	policyFname  = rootFlagSet.String("policy-file", "./policy.hujson", "filename for policy file")
	cacheFname   = rootFlagSet.String("cache-file", "./version-cache.json", "filename for the previous known version hash")
	timeout      = rootFlagSet.Duration("timeout", 5*time.Minute, "timeout for the entire CI run")
	githubSyntax = rootFlagSet.Bool("github-syntax", true, "use GitHub Action error syntax (https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-error-message)")
)

func modifiedExternallyError() {
	if *githubSyntax {
		fmt.Printf("::warning file=%s,line=1,col=1,title=Policy File Modified Externally::The policy file was modified externally in the admin console.\n", *policyFname)
	} else {
		fmt.Printf("The policy file was modified externally in the admin console.\n")
	}
}

func apply(cache *Cache, tailnet, apiKey string) func(context.Context, []string) error {
	return func(ctx context.Context, args []string) error {
		controlEtag, err := getACLETag(ctx, tailnet, apiKey)
		if err != nil {
			return err
		}

		localEtag, err := sumFile(*policyFname)
		if err != nil {
			return err
		}

		if cache.PrevETag == "" {
			log.Println("no previous etag found, assuming local file is correct and recording that")
			cache.PrevETag = localEtag
		}

		log.Printf("control: %s", controlEtag)
		log.Printf("local:   %s", localEtag)
		log.Printf("cache:   %s", cache.PrevETag)

		if cache.PrevETag != controlEtag {
			modifiedExternallyError()
		}

		if controlEtag == localEtag {
			cache.PrevETag = localEtag
			log.Println("no update needed, doing nothing")
			return nil
		}

		if err := applyNewACL(ctx, tailnet, apiKey, *policyFname, controlEtag); err != nil {
			return err
		}

		cache.PrevETag = localEtag

		return nil
	}
}

func test(cache *Cache, tailnet, apiKey string) func(context.Context, []string) error {
	return func(ctx context.Context, args []string) error {
		controlEtag, err := getACLETag(ctx, tailnet, apiKey)
		if err != nil {
			return err
		}

		localEtag, err := sumFile(*policyFname)
		if err != nil {
			return err
		}

		if cache.PrevETag == "" {
			log.Println("no previous etag found, assuming local file is correct and recording that")
			cache.PrevETag = localEtag
		}

		log.Printf("control: %s", controlEtag)
		log.Printf("local:   %s", localEtag)
		log.Printf("cache:   %s", cache.PrevETag)

		if cache.PrevETag != controlEtag {
			modifiedExternallyError()
		}

		if controlEtag == localEtag {
			log.Println("no updates found, doing nothing")
			return nil
		}

		if err := testNewACLs(ctx, tailnet, apiKey, *policyFname); err != nil {
			return err
		}
		return nil
	}
}

func getChecksums(cache *Cache, tailnet, apiKey string) func(context.Context, []string) error {
	return func(ctx context.Context, args []string) error {
		controlEtag, err := getACLETag(ctx, tailnet, apiKey)
		if err != nil {
			return err
		}

		localEtag, err := sumFile(*policyFname)
		if err != nil {
			return err
		}

		if cache.PrevETag == "" {
			log.Println("no previous etag found, assuming local file is correct and recording that")
			cache.PrevETag = Shuck(localEtag)
		}

		log.Printf("control: %s", controlEtag)
		log.Printf("local:   %s", localEtag)
		log.Printf("cache:   %s", cache.PrevETag)

		return nil
	}
}

func main() {
	tailnet, ok := os.LookupEnv("TS_TAILNET")
	if !ok {
		log.Fatal("set envvar TS_TAILNET to your tailnet's name")
	}
	apiKey, ok := os.LookupEnv("TS_API_KEY")
	if !ok {
		log.Fatal("set envvar TS_API_KEY to your Tailscale API key")
	}
	cache, err := LoadCache(*cacheFname)
	if err != nil {
		if os.IsNotExist(err) {
			cache = &Cache{}
		} else {
			log.Fatalf("error loading cache: %v", err)
		}
	}
	defer cache.Save(*cacheFname)

	applyCmd := &ffcli.Command{
		Name:       "apply",
		ShortUsage: "gitops-pusher [options] apply",
		ShortHelp:  "Pushes changes to CONTROL",
		LongHelp:   `Pushes changes to CONTROL`,
		Exec:       apply(cache, tailnet, apiKey),
	}

	testCmd := &ffcli.Command{
		Name:       "test",
		ShortUsage: "gitops-pusher [options] test",
		ShortHelp:  "Tests ACL changes",
		LongHelp:   "Tests ACL changes",
		Exec:       test(cache, tailnet, apiKey),
	}

	cksumCmd := &ffcli.Command{
		Name:       "checksum",
		ShortUsage: "Shows checksums of ACL files",
		ShortHelp:  "Fetch checksum of CONTROL's ACL and the local ACL for comparison",
		LongHelp:   "Fetch checksum of CONTROL's ACL and the local ACL for comparison",
		Exec:       getChecksums(cache, tailnet, apiKey),
	}

	root := &ffcli.Command{
		ShortUsage:  "gitops-pusher [options] <command>",
		ShortHelp:   "Push Tailscale ACLs to CONTROL using a GitOps workflow",
		Subcommands: []*ffcli.Command{applyCmd, cksumCmd, testCmd},
		FlagSet:     rootFlagSet,
	}

	if err := root.Parse(os.Args[1:]); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if err := root.Run(ctx); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func sumFile(fname string) (string, error) {
	data, err := os.ReadFile(fname)
	if err != nil {
		return "", err
	}

	formatted, err := hujson.Format(data)
	if err != nil {
		return "", err
	}

	h := sha256.New()
	_, err = h.Write(formatted)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func applyNewACL(ctx context.Context, tailnet, apiKey, policyFname, oldEtag string) error {
	fin, err := os.Open(policyFname)
	if err != nil {
		return err
	}
	defer fin.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/acl", tailnet), fin)
	if err != nil {
		return err
	}

	req.SetBasicAuth(apiKey, "")
	req.Header.Set("Content-Type", "application/hujson")
	req.Header.Set("If-Match", `"`+oldEtag+`"`)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	got := resp.StatusCode
	want := http.StatusOK
	if got != want {
		var ate ACLTestError
		err := json.NewDecoder(resp.Body).Decode(&ate)
		if err != nil {
			return err
		}

		return ate
	}

	return nil
}

func testNewACLs(ctx context.Context, tailnet, apiKey, policyFname string) error {
	fin, err := os.Open(policyFname)
	if err != nil {
		return err
	}
	defer fin.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/acl/validate", tailnet), fin)
	if err != nil {
		return err
	}

	req.SetBasicAuth(apiKey, "")
	req.Header.Set("Content-Type", "application/hujson")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var ate ACLTestError
	err = json.NewDecoder(resp.Body).Decode(&ate)
	if err != nil {
		return err
	}

	if len(ate.Message) != 0 || len(ate.Data) != 0 {
		return ate
	}

	got := resp.StatusCode
	want := http.StatusOK
	if got != want {
		return fmt.Errorf("wanted HTTP status code %d but got %d", want, got)
	}

	return nil
}

var lineColMessageSplit = regexp.MustCompile(`line ([0-9]+), column ([0-9]+): (.*)$`)

type ACLTestError struct {
	Message string               `json:"message"`
	Data    []ACLTestErrorDetail `json:"data"`
}

func (ate ACLTestError) Error() string {
	var sb strings.Builder

	if *githubSyntax && lineColMessageSplit.MatchString(ate.Message) {
		sp := lineColMessageSplit.FindStringSubmatch(ate.Message)

		line := sp[1]
		col := sp[2]
		msg := sp[3]

		fmt.Fprintf(&sb, "::error file=%s,line=%s,col=%s::%s", *policyFname, line, col, msg)
	} else {
		fmt.Fprintln(&sb, ate.Message)
	}
	fmt.Fprintln(&sb)

	for _, data := range ate.Data {
		fmt.Fprintf(&sb, "For user %s:\n", data.User)
		for _, err := range data.Errors {
			fmt.Fprintf(&sb, "- %s\n", err)
		}
	}

	return sb.String()
}

type ACLTestErrorDetail struct {
	User   string   `json:"user"`
	Errors []string `json:"errors"`
}

func getACLETag(ctx context.Context, tailnet, apiKey string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/acl", tailnet), nil)
	if err != nil {
		return "", err
	}

	req.SetBasicAuth(apiKey, "")
	req.Header.Set("Accept", "application/hujson")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	got := resp.StatusCode
	want := http.StatusOK
	if got != want {
		return "", fmt.Errorf("wanted HTTP status code %d but got %d", want, got)
	}

	return Shuck(resp.Header.Get("ETag")), nil
}
