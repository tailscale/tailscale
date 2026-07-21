// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailscale

import (
	"context"

	"tailscale.com/feature"
)

type ResolveAuthKeyWIFArgs struct {
	// BaseURL is the URL of the control server used for token exchange and authkey generation.
	BaseURL string
	// ClientID is the federated client ID used for token exchange.
	ClientID string
	// IDToken is the Identity token from the identity provider.
	IDToken string
	// Audience is the federated audience acquired by configuring the trust credential in the admin UI.
	Audience string
	// Tags is the list of tags to be associated with the auth key.
	Tags []string
}

type ExchangeJWTForTokenWIFArgs struct {
	// BaseURL is the URL of the control server used for token exchange.
	BaseURL string
	// ClientID is the federated client ID used for token exchange.
	ClientID string
	// IDToken is a JWT identity token to use in the token exchange operation.
	IDToken string
}

// HookResolveAuthKeyViaWIF resolves to [identityfederation.resolveAuthKey] when the
// corresponding feature tag is enabled in the build process.
var HookResolveAuthKeyViaWIF feature.Hook[func(ctx context.Context, args ResolveAuthKeyWIFArgs) (string, error)]

// HookExchangeJWTForTokenViaWIF resolves to [identityfederation.exchangeJWTForToken] when the
// corresponding feature tag is enabled in the build process.
var HookExchangeJWTForTokenViaWIF feature.Hook[func(ctx context.Context, arg ExchangeJWTForTokenWIFArgs) (string, error)]
