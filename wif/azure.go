// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

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

	"tailscale.com/util/httpm"
)

// Azure support covers three ways a workload can obtain a Microsoft Entra
// token without a stored secret:
//
//   - Azure VMs, scale sets, Batch pools and Linux container instances expose
//     the Instance Metadata Service (IMDS) at 169.254.169.254. The managed
//     identity attached to the resource mints a token for a given "resource"
//     (the audience).
//   - App Service, Functions, Container Apps and similar hosts have no IMDS and
//     instead inject IDENTITY_ENDPOINT and IDENTITY_HEADER, pointing at a local
//     token service that speaks a near-identical protocol.
//   - AKS pods using Microsoft Entra Workload ID get a projected Kubernetes
//     service account token (AZURE_FEDERATED_TOKEN_FILE) that must be exchanged
//     at the Entra token endpoint as a client assertion.
//
// In all three cases the audience passed to ObtainProviderToken must be an
// identifier Entra knows about: the client ID of an app registration in the
// workload's tenant, or one of that app's Application ID URIs (api://...).
// The app registration's requestedAccessTokenVersion decides whether the
// token is v1.0 (iss https://sts.windows.net/<tenant>/) or v2.0
// (iss https://login.microsoftonline.com/<tenant>/v2.0).
//
// AZURE_CLIENT_ID selects a user-assigned managed identity for the IMDS and
// IDENTITY_ENDPOINT paths (the same convention the Azure SDKs use); without
// it the system-assigned identity is used.

const (
	azureIMDSDefaultBase            = "http://169.254.169.254"
	azureIMDSTokenAPIVersion        = "2018-02-01"
	azureIMDSInstanceAPIVersion     = "2021-02-01"
	azureIdentityEndpointAPIVersion = "2019-08-01"
	azureDefaultAuthorityHost       = "https://login.microsoftonline.com/"
)

// azureIMDSBase is the IMDS base URL; a variable so tests can point it at a
// local server.
var azureIMDSBase = azureIMDSDefaultBase

// inAzureWorkloadIdentity reports whether the Microsoft Entra Workload ID
// webhook has injected its environment into this process.
func inAzureWorkloadIdentity() bool {
	return os.Getenv("AZURE_FEDERATED_TOKEN_FILE") != "" &&
		os.Getenv("AZURE_CLIENT_ID") != "" &&
		os.Getenv("AZURE_TENANT_ID") != ""
}

// inAzureIdentityEndpoint reports whether the App Service family managed
// identity endpoint is available.
func inAzureIdentityEndpoint() bool {
	return os.Getenv("IDENTITY_ENDPOINT") != "" && os.Getenv("IDENTITY_HEADER") != ""
}

// detectAzureEnv reports whether environment variables alone identify this as
// an Azure host. It must run before any 169.254.169.254 probe: on AKS the
// node's IMDS is reachable from pods and would silently yield the node's
// identity instead of the pod's.
func detectAzureEnv() bool {
	return inAzureWorkloadIdentity() || inAzureIdentityEndpoint()
}

// azureLocalHTTPClient returns a client for talking to IMDS and the local
// identity endpoint. Azure documents that IMDS must not be reached through a
// proxy, so the transport ignores proxy environment variables.
func azureLocalHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: nil},
	}
}

// detectAzureIMDS probes the Azure Instance Metadata Service. Azure requires
// the "Metadata: true" header and answers with a JSON document whose
// azEnvironment field names the cloud; AWS and GCP metadata servers share the
// IP but return 404 (or reject the request) for this path.
func detectAzureIMDS(ctx context.Context, client *http.Client) bool {
	u := azureIMDSBase + "/metadata/instance/compute?api-version=" + azureIMDSInstanceAPIVersion + "&format=json"
	req, err := http.NewRequestWithContext(ctx, httpm.GET, u, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}

	var compute struct {
		AzEnvironment string `json:"azEnvironment"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&compute); err != nil {
		return false
	}
	return strings.HasPrefix(strings.ToUpper(compute.AzEnvironment), "AZURE")
}

// acquireAzureIDToken obtains a Microsoft Entra token whose aud claim is
// audience, using whichever Azure identity mechanism the host provides.
func acquireAzureIDToken(ctx context.Context, audience string) (string, error) {
	audience = strings.TrimSpace(audience)
	if audience == "" {
		return "", errors.New("azure identity tokens require an audience")
	}

	switch {
	case inAzureWorkloadIdentity():
		return acquireAzureWorkloadIdentityToken(ctx, audience)
	case inAzureIdentityEndpoint():
		u, err := url.Parse(os.Getenv("IDENTITY_ENDPOINT"))
		if err != nil {
			return "", fmt.Errorf("parse IDENTITY_ENDPOINT: %w", err)
		}
		q := u.Query()
		q.Set("api-version", azureIdentityEndpointAPIVersion)
		q.Set("resource", audience)
		if cid := os.Getenv("AZURE_CLIENT_ID"); cid != "" {
			q.Set("client_id", cid)
		}
		u.RawQuery = q.Encode()
		return azureManagedIdentityToken(ctx, u.String(), http.Header{
			"X-IDENTITY-HEADER": {os.Getenv("IDENTITY_HEADER")},
		})
	default:
		q := url.Values{}
		q.Set("api-version", azureIMDSTokenAPIVersion)
		q.Set("resource", audience)
		if cid := os.Getenv("AZURE_CLIENT_ID"); cid != "" {
			q.Set("client_id", cid)
		}
		u := azureIMDSBase + "/metadata/identity/oauth2/token?" + q.Encode()
		return azureManagedIdentityToken(ctx, u, http.Header{
			"Metadata": {"true"},
		})
	}
}

// azureManagedIdentityToken calls a managed identity token endpoint (IMDS or
// IDENTITY_ENDPOINT) and returns the access token from its JSON response.
func azureManagedIdentityToken(ctx context.Context, fullURL string, headers http.Header) (string, error) {
	req, err := http.NewRequestWithContext(ctx, httpm.GET, fullURL, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	resp, err := azureLocalHTTPClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("call azure managed identity endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("azure managed identity endpoint returned %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}

	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode azure managed identity response: %w", err)
	}
	if strings.TrimSpace(tr.AccessToken) == "" {
		return "", errors.New("azure managed identity endpoint returned empty token")
	}
	return tr.AccessToken, nil
}

// acquireAzureWorkloadIdentityToken implements the Microsoft Entra Workload ID
// flow used on AKS: the projected Kubernetes service account token is sent to
// Entra as a client assertion for the federated client (AZURE_CLIENT_ID), and
// Entra returns a token for the audience.
func acquireAzureWorkloadIdentityToken(ctx context.Context, audience string) (string, error) {
	// Kubernetes rotates the projected token in place; read it every time.
	assertion, err := os.ReadFile(os.Getenv("AZURE_FEDERATED_TOKEN_FILE"))
	if err != nil {
		return "", fmt.Errorf("read AZURE_FEDERATED_TOKEN_FILE: %w", err)
	}
	return exchangeAzureClientAssertion(ctx, strings.TrimSpace(string(assertion)), os.Getenv("AZURE_CLIENT_ID"), os.Getenv("AZURE_TENANT_ID"), audience)
}

// exchangeAzureClientAssertion performs the OAuth 2.0 client credentials grant
// with a JWT client assertion against the Entra v2.0 token endpoint and
// returns the resulting access token for audience.
func exchangeAzureClientAssertion(ctx context.Context, assertion, clientID, tenantID, audience string) (string, error) {
	if assertion == "" {
		return "", errors.New("azure client assertion is empty")
	}
	if clientID == "" || tenantID == "" {
		return "", errors.New("azure client assertion exchange requires AZURE_CLIENT_ID and AZURE_TENANT_ID")
	}

	authority := os.Getenv("AZURE_AUTHORITY_HOST")
	if authority == "" {
		authority = azureDefaultAuthorityHost
	}
	tokenURL := strings.TrimSuffix(authority, "/") + "/" + tenantID + "/oauth2/v2.0/token"

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("scope", azureScopeForAudience(audience))
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)

	req, err := http.NewRequestWithContext(ctx, httpm.POST, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("call azure token endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("azure token endpoint returned %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}

	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode azure token response: %w", err)
	}
	if strings.TrimSpace(tr.AccessToken) == "" {
		return "", errors.New("azure token response contained empty token")
	}
	return tr.AccessToken, nil
}

// azureScopeForAudience converts an audience (app client ID or Application ID
// URI) into the "<resource>/.default" scope the Entra v2.0 endpoint expects.
func azureScopeForAudience(audience string) string {
	audience = strings.TrimSpace(audience)
	if strings.HasSuffix(audience, "/.default") {
		return audience
	}
	return strings.TrimSuffix(audience, "/") + "/.default"
}
