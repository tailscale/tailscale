// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"tailscale.com/internal/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

// defaultTailnet is a value that can be used in Tailscale API calls instead of tailnet name to indicate that the API
// call should be performed on the default tailnet for the provided credentials.
const (
	defaultTailnet = "-"
	oidcJWTPath    = "/var/run/secrets/tailscale/serviceaccount/token"
)

func newTSClient(logger *zap.SugaredLogger, clientID, clientIDPath, clientSecretPath, loginServer string) (*tailscale.Client, error) {
	baseURL := ipn.DefaultControlURL
	if loginServer != "" {
		baseURL = loginServer
	}

	var httpClient *http.Client
	if clientID == "" {
		// Use static client credentials mounted to disk.
		id, err := os.ReadFile(clientIDPath)
		if err != nil {
			return nil, fmt.Errorf("error reading client ID %q: %w", clientIDPath, err)
		}
		secret, err := os.ReadFile(clientSecretPath)
		if err != nil {
			return nil, fmt.Errorf("reading client secret %q: %w", clientSecretPath, err)
		}
		credentials := clientcredentials.Config{
			ClientID:     string(id),
			ClientSecret: string(secret),
			TokenURL:     fmt.Sprintf("%s%s", baseURL, "/api/v2/oauth/token"),
		}
		tokenSrc := credentials.TokenSource(context.Background())
		httpClient = oauth2.NewClient(context.Background(), tokenSrc)
	} else {
		// Use workload identity federation.
		tokenSrc := &jwtTokenSource{
			logger:  logger,
			jwtPath: oidcJWTPath,
			baseCfg: clientcredentials.Config{
				ClientID: clientID,
				TokenURL: fmt.Sprintf("%s%s", baseURL, "/api/v2/oauth/token-exchange"),
			},
		}
		httpClient = &http.Client{
			Transport: &oauth2.Transport{
				Source: tokenSrc,
			},
		}
	}

	c := tailscale.NewClient(defaultTailnet, nil)
	c.UserAgent = "tailscale-k8s-operator"
	c.HTTPClient = httpClient
	if loginServer != "" {
		c.BaseURL = loginServer
	}
	return c, nil
}

type tsClient interface {
	CreateKey(ctx context.Context, caps tailscale.KeyCapabilities) (string, *tailscale.Key, error)
	Device(ctx context.Context, deviceID string, fields *tailscale.DeviceFieldsOpts) (*tailscale.Device, error)
	DeleteDevice(ctx context.Context, nodeStableID string) error
	// GetVIPService is a method for getting a Tailscale Service. VIPService is the original name for Tailscale Service.
	GetVIPService(ctx context.Context, name tailcfg.ServiceName) (*tailscale.VIPService, error)
	// ListVIPServices is a method for listing all Tailscale Services. VIPService is the original name for Tailscale Service.
	ListVIPServices(ctx context.Context) (*tailscale.VIPServiceList, error)
	// CreateOrUpdateVIPService is a method for creating or updating a Tailscale Service.
	CreateOrUpdateVIPService(ctx context.Context, svc *tailscale.VIPService) error
	// DeleteVIPService is a method for deleting a Tailscale Service.
	DeleteVIPService(ctx context.Context, name tailcfg.ServiceName) error
}

// jwtTokenSource implements the [oauth2.TokenSource] interface, but with the
// ability to regenerate a fresh underlying token source each time a new value
// of the JWT parameter is needed due to expiration.
type jwtTokenSource struct {
	logger  *zap.SugaredLogger
	jwtPath string                   // Path to the file containing an automatically refreshed JWT.
	baseCfg clientcredentials.Config // Holds config that doesn't change for the lifetime of the process.

	mu         sync.Mutex         // Guards underlying.
	underlying oauth2.TokenSource // The oauth2 client implementation. Does its own separate caching of the access token.
}

func (s *jwtTokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.underlying != nil {
		t, err := s.underlying.Token()
		if err == nil && t != nil && t.Valid() {
			return t, nil
		}
	}

	s.logger.Debugf("Refreshing JWT from %s", s.jwtPath)
	tk, err := os.ReadFile(s.jwtPath)
	if err != nil {
		return nil, fmt.Errorf("error reading JWT from %q: %w", s.jwtPath, err)
	}

	// Shallow copy of the base config.
	credentials := s.baseCfg
	credentials.EndpointParams = map[string][]string{
		"jwt": {string(tk)},
	}

	src := credentials.TokenSource(context.Background())
	s.underlying = oauth2.ReuseTokenSourceWithExpiry(nil, src, time.Minute)
	return s.underlying.Token()
}
