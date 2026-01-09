// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package wif deals with obtaining ID tokens from provider VMs
// to be used as part of Workload Identity Federation
package wif

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"tailscale.com/util/httpm"
)

type Environment string

const (
	EnvGitHub Environment = "github"
	EnvAWS    Environment = "aws"
	EnvGCP    Environment = "gcp"
	EnvNone   Environment = "none"
)

// ObtainProviderToken tries to detect what provider the client is running in
// and then tries to obtain an ID token for the audience that is passed as an argument
// To detect the environment, we do it in the following intentional order:
//  1. GitHub Actions (strongest env signals; may run atop any cloud)
//  2. AWS via IMDSv2 token endpoint (does not require env vars)
//  3. GCP via metadata header semantics
//  4. Azure via metadata endpoint
func ObtainProviderToken(ctx context.Context, audience string) (string, error) {
	env := detectEnvironment(ctx)

	switch env {
	case EnvGitHub:
		return acquireGitHubActionsIDToken(ctx, audience)
	case EnvAWS:
		return acquireAWSWebIdentityToken(ctx, audience)
	case EnvGCP:
		return acquireGCPMetadataIDToken(ctx, audience)
	default:
		return "", errors.New("could not detect environment; provide --id-token explicitly")
	}
}

func detectEnvironment(ctx context.Context) Environment {
	if os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" &&
		os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != "" {
		return EnvGitHub
	}

	client := httpClient()
	if detectAWSIMDSv2(ctx, client) {
		return EnvAWS
	}
	if detectGCPMetadata(ctx, client) {
		return EnvGCP
	}
	return EnvNone
}

func httpClient() *http.Client {
	return &http.Client{
		Timeout: time.Second * 5,
	}
}

func detectAWSIMDSv2(ctx context.Context, client *http.Client) bool {
	req, err := http.NewRequestWithContext(ctx, httpm.PUT, "http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "1")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

func detectGCPMetadata(ctx context.Context, client *http.Client) bool {
	req, err := http.NewRequestWithContext(ctx, httpm.GET, "http://metadata.google.internal", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.Header.Get("Metadata-Flavor") == "Google"
}

type githubOIDCResponse struct {
	Value string `json:"value"`
}

func acquireGitHubActionsIDToken(ctx context.Context, audience string) (string, error) {
	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqTok := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" || reqTok == "" {
		return "", errors.New("missing ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN (ensure workflow has permissions: id-token: write)")
	}

	u, err := url.Parse(reqURL)
	if err != nil {
		return "", fmt.Errorf("parse ACTIONS_ID_TOKEN_REQUEST_URL: %w", err)
	}
	if strings.TrimSpace(audience) != "" {
		q := u.Query()
		q.Set("audience", strings.TrimSpace(audience))
		u.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, httpm.GET, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+reqTok)
	req.Header.Set("Accept", "application/json")

	client := httpClient()
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request github oidc token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("github oidc token endpoint returned %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}

	var tr githubOIDCResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode github oidc response: %w", err)
	}
	if strings.TrimSpace(tr.Value) == "" {
		return "", errors.New("github oidc response contained empty token")
	}

	// GitHub response doesn't provide exp directly; caller can parse JWT if needed.
	return tr.Value, nil
}

func acquireAWSWebIdentityToken(ctx context.Context, audience string) (string, error) {
	// LoadDefaultConfig wires up the default credential chain (incl. IMDS).
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("load aws config: %w", err)
	}

	// Verify credentials are available before proceeding.
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return "", fmt.Errorf("AWS credentials unavailable (instance profile/IMDS?): %w", err)
	}

	imdsClient := imds.NewFromConfig(cfg)
	region, err := imdsClient.GetRegion(ctx, &imds.GetRegionInput{})
	if err != nil {
		return "", fmt.Errorf("couldn't get AWS region: %w", err)
	}
	cfg.Region = region.Region

	stsClient := sts.NewFromConfig(cfg)
	in := &sts.GetWebIdentityTokenInput{
		Audience:         []string{strings.TrimSpace(audience)},
		SigningAlgorithm: aws.String("ES384"),
		DurationSeconds:  aws.Int32(300), // 5 minutes
	}

	out, err := stsClient.GetWebIdentityToken(ctx, in)
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			return "", fmt.Errorf("aws sts:GetWebIdentityToken failed (%s): %w", apiErr.ErrorCode(), err)
		}
		return "", fmt.Errorf("aws sts:GetWebIdentityToken failed: %w", err)
	}

	if out.WebIdentityToken == nil || strings.TrimSpace(*out.WebIdentityToken) == "" {
		return "", fmt.Errorf("aws sts:GetWebIdentityToken returned empty token")
	}

	return *out.WebIdentityToken, nil
}

func acquireGCPMetadataIDToken(ctx context.Context, audience string) (string, error) {
	u := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
	v := url.Values{}
	v.Set("audience", strings.TrimSpace(audience))
	v.Set("format", "full")
	fullURL := u + "?" + v.Encode()

	req, err := http.NewRequestWithContext(ctx, httpm.GET, fullURL, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	client := httpClient()
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("call gcp metadata identity endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("gcp metadata identity endpoint returned %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return "", fmt.Errorf("read gcp id token: %w", err)
	}
	jwt := strings.TrimSpace(string(b))
	if jwt == "" {
		return "", fmt.Errorf("gcp metadata returned empty token")
	}

	return jwt, nil
}
