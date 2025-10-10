// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailscale

import (
	"context"

	"tailscale.com/feature"
)

// HookResolveAuthKeyViaWIF resolves to [identityfederation.ResolveAuthKey] when the
// corresponding feature tag is enabled in the build process.
//
// baseURL is the URL of the control server used for token exchange and authkey generation.
// clientID is the federated client ID used for token exchange, the format is <tailnet ID>/<oauth client ID>
// idToken is the Identity token from the identity provider
// tags is the list of tags to be associated with the auth key
var HookResolveAuthKeyViaWIF feature.Hook[func(ctx context.Context, baseURL, clientID, idToken string, tags []string) (string, error)]
