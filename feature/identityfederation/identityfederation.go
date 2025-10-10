// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package identityfederation registers support for using ID tokens to
// automatically request authkeys for logging in.
package identityfederation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"tailscale.com/feature"
	"tailscale.com/internal/client/tailscale"
	"tailscale.com/ipn"
)

func init() {
	feature.Register("identityfederation")
	tailscale.HookResolveAuthKeyViaWIF.Set(resolveAuthKey)
}

// resolveAuthKey uses OIDC identity federation to exchange the provided ID token and client ID for an authkey.
func resolveAuthKey(ctx context.Context, baseURL, clientID, idToken string, tags []string) (string, error) {
	if clientID == "" {
		return "", nil // Short-circuit, no client ID means not using identity federation
	}

	if idToken == "" {
		return "", errors.New("federated identity authkeys require --id-token")
	}
	if len(tags) == 0 {
		return "", errors.New("federated identity authkeys require --advertise-tags")
	}
	if baseURL == "" {
		baseURL = ipn.DefaultControlURL
	}

	ephemeral, preauth, err := parseOptionalAttributes(clientID)
	if err != nil {
		return "", fmt.Errorf("failed to parse optional config attributes: %w", err)
	}

	accessToken, err := exchangeJWTForToken(ctx, baseURL, clientID, idToken)
	if err != nil {
		return "", fmt.Errorf("failed to exchange JWT for access token: %w", err)
	}
	if accessToken == "" {
		return "", errors.New("received empty access token from Tailscale")
	}

	tsClient := tailscale.NewClient("-", tailscale.APIKey(accessToken))
	tsClient.UserAgent = "tailscale-cli-identity-federation"
	tsClient.BaseURL = baseURL

	authkey, _, err := tsClient.CreateKey(ctx, tailscale.KeyCapabilities{
		Devices: tailscale.KeyDeviceCapabilities{
			Create: tailscale.KeyDeviceCreateCapabilities{
				Reusable:      false,
				Ephemeral:     ephemeral,
				Preauthorized: preauth,
				Tags:          tags,
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("unexpected error while creating authkey: %w", err)
	}
	if authkey == "" {
		return "", errors.New("received empty authkey from control server")
	}

	return authkey, nil
}

func parseOptionalAttributes(clientID string) (ephemeral bool, preauthorized bool, err error) {
	_, attrs, found := strings.Cut(clientID, "?")
	if !found {
		return true, false, nil
	}

	parsed, err := url.ParseQuery(attrs)
	if err != nil {
		return false, false, fmt.Errorf("failed to parse optional config attributes: %w", err)
	}

	for k := range parsed {
		switch k {
		case "ephemeral":
			ephemeral, err = strconv.ParseBool(parsed.Get(k))
		case "preauthorized":
			preauthorized, err = strconv.ParseBool(parsed.Get(k))
		default:
			return false, false, fmt.Errorf("unknown optional config attribute %q", k)
		}
	}

	return ephemeral, preauthorized, err
}

// exchangeJWTForToken exchanges a JWT for a Tailscale access token.
func exchangeJWTForToken(ctx context.Context, baseURL, clientID, idToken string) (string, error) {
	httpClient := &http.Client{Timeout: 10 * time.Second}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	token, err := (&oauth2.Config{
		Endpoint: oauth2.Endpoint{
			TokenURL: fmt.Sprintf("%s/api/v2/oauth/token-exchange", baseURL),
		},
	}).Exchange(ctx, "", oauth2.SetAuthURLParam("client_id", clientID), oauth2.SetAuthURLParam("jwt", idToken))
	if err != nil {
		// Try to extract more detailed error message
		var retrieveErr *oauth2.RetrieveError
		if errors.As(err, &retrieveErr) {
			return "", fmt.Errorf("token exchange failed with status %d: %s", retrieveErr.Response.StatusCode, string(retrieveErr.Body))
		}
		return "", fmt.Errorf("unexpected token exchange request error: %w", err)
	}

	return token.AccessToken, nil
}
