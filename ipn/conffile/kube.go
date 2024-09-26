// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package conffile

import (
	"context"
	"fmt"
	"time"

	"tailscale.com/kube/kubeclient"
)

func readKubeSecret(name string) ([]byte, error) {
	c, err := kubeclient.New()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	secret, err := c.GetSecret(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to read config from Secret %q: %w", name, err)
	}

	if contents, ok := secret.Data["tailscaled.hujson"]; ok {
		return contents, nil
	}

	return secret.Data["tailscaled"], nil
}
