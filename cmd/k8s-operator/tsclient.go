// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/oauth2/clientcredentials"
	"tailscale.com/internal/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

// defaultTailnet is a value that can be used in Tailscale API calls instead of tailnet name to indicate that the API
// call should be performed on the default tailnet for the provided credentials.
const (
	defaultTailnet = "-"
)

func newTSClient(ctx context.Context, clientIDPath, clientSecretPath, loginServer string) (tsClient, error) {
	clientID, err := os.ReadFile(clientIDPath)
	if err != nil {
		return nil, fmt.Errorf("error reading client ID %q: %w", clientIDPath, err)
	}
	clientSecret, err := os.ReadFile(clientSecretPath)
	if err != nil {
		return nil, fmt.Errorf("reading client secret %q: %w", clientSecretPath, err)
	}
	const tokenURLPath = "/api/v2/oauth/token"
	tokenURL := fmt.Sprintf("%s%s", ipn.DefaultControlURL, tokenURLPath)
	if loginServer != "" {
		tokenURL = fmt.Sprintf("%s%s", loginServer, tokenURLPath)
	}
	credentials := clientcredentials.Config{
		ClientID:     string(clientID),
		ClientSecret: string(clientSecret),
		TokenURL:     tokenURL,
	}
	c := tailscale.NewClient(defaultTailnet, nil)
	c.UserAgent = "tailscale-k8s-operator"
	c.HTTPClient = credentials.Client(ctx)
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
	// CreateOrUpdateVIPService is a method for creating or updating a Tailscale Service.
	CreateOrUpdateVIPService(ctx context.Context, svc *tailscale.VIPService) error
	// DeleteVIPService is a method for deleting a Tailscale Service.
	DeleteVIPService(ctx context.Context, name tailcfg.ServiceName) error
}
