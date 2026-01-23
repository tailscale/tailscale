// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tailscale.com/internal/client/tailscale"
	"tailscale.com/ipn"
	operatorutils "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

func clientForTailnet(ctx context.Context, cl client.Client, namespace, name string) (tsClient, error) {
	var tn tsapi.Tailnet
	if err := cl.Get(ctx, client.ObjectKey{Name: name}, &tn); err != nil {
		return nil, fmt.Errorf("failed to get tailnet %q: %w", name, err)
	}

	if !operatorutils.TailnetIsReady(&tn) {
		return nil, fmt.Errorf("tailnet %q is not ready", name)
	}

	var secret corev1.Secret
	if err := cl.Get(ctx, client.ObjectKey{Name: tn.Spec.Credentials.SecretName, Namespace: namespace}, &secret); err != nil {
		return nil, fmt.Errorf("failed to get Secret %q in namespace %q: %w", tn.Spec.Credentials.SecretName, namespace, err)
	}

	baseURL := ipn.DefaultControlURL
	if tn.Spec.LoginURL != "" {
		baseURL = tn.Spec.LoginURL
	}

	credentials := clientcredentials.Config{
		ClientID:     string(secret.Data["client_id"]),
		ClientSecret: string(secret.Data["client_secret"]),
		TokenURL:     baseURL + "/api/v2/oauth/token",
	}

	source := credentials.TokenSource(ctx)
	httpClient := oauth2.NewClient(ctx, source)

	ts := tailscale.NewClient(defaultTailnet, nil)
	ts.UserAgent = "tailscale-k8s-operator"
	ts.HTTPClient = httpClient
	ts.BaseURL = baseURL

	return ts, nil
}
