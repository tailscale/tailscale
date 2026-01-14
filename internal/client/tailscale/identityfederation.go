// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailscale

import (
	"context"

	"tailscale.com/feature"
)

// HookResolveAuthKeyViaWIF resolves to [identityfederation.resolveAuthKey] when the
// corresponding feature tag is enabled in the build process.
//
// baseURL is the URL of the control server used for token exchange and authkey generation.
// clientID is the federated client ID used for token exchange
// idToken is the Identity token from the identity provider
// tags is the list of tags to be associated with the auth key
// audience is the federated audience acquired by configuring
// the trusted credential in the admin UI
var HookResolveAuthKeyViaWIF feature.Hook[func(ctx context.Context, baseURL, clientID, idToken, audience string, tags []string) (string, error)]

// HookExchangeJWTForTokenViaWIF resolves to [identityfederation.exchangeJWTForToken] when the
// corresponding feature tag is enabled in the build process.
//
// baseURL is the URL of the control server used for token exchange
// clientID is the federated client ID used for token exchange
// idToken is the Identity token from the identity provider
var HookExchangeJWTForTokenViaWIF feature.Hook[func(ctx context.Context, baseURL, clientID, idToken string) (string, error)]
