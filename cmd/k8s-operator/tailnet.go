// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"log"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tailscale.com/internal/client/tailscale"
	"tailscale.com/ipn"
	operatorutils "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

func clientForTailnet(ctx context.Context, cl client.Client, namespace, name string) (tsClient, string, error) {
	var tn tsapi.Tailnet
	if err := cl.Get(ctx, client.ObjectKey{Name: name}, &tn); err != nil {
		return nil, "", fmt.Errorf("failed to get tailnet %q: %w", name, err)
	}

	log.Printf("creating client for tailnet %q", name)

	if !operatorutils.TailnetIsReady(&tn) {
		return nil, "", fmt.Errorf("tailnet %q is not ready", name)
	}

	var secret corev1.Secret
	if err := cl.Get(ctx, client.ObjectKey{Name: tn.Spec.Credentials.SecretName, Namespace: namespace}, &secret); err != nil {
		return nil, "", fmt.Errorf("failed to get Secret %q in namespace %q: %w", tn.Spec.Credentials.SecretName, namespace, err)
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

	return ts, baseURL, nil
}

func clientFromProxyGroup(ctx context.Context, cl client.Client, obj client.Object, namespace string, def tsClient) (tsClient, error) {
	proxyGroup := obj.GetAnnotations()[AnnotationProxyGroup]
	if proxyGroup == "" {
		return def, nil
	}

	var pg tsapi.ProxyGroup
	if err := cl.Get(ctx, types.NamespacedName{Name: proxyGroup}, &pg); err != nil {
		return nil, err
	}

	if pg.Spec.Tailnet == "" {
		return def, nil
	}

	tailscaleClient, _, err := clientForTailnet(ctx, cl, namespace, pg.Spec.Tailnet)
	if err != nil {
		return nil, err
	}

	return tailscaleClient, nil
}
