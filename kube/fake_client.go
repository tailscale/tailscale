// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package kube provides a client to interact with Kubernetes.
// This package is Tailscale-internal and not meant for external consumption.
// Further, the API should not be considered stable.
package kube

import (
	"context"
	"net"
)

var _ Client = &FakeClient{}

type FakeClient struct {
	GetSecretImpl              func(context.Context, string) (*Secret, error)
	CheckSecretPermissionsImpl func(ctx context.Context, name string) (bool, bool, error)
}

func (fc *FakeClient) CheckSecretPermissions(ctx context.Context, name string) (bool, bool, error) {
	return fc.CheckSecretPermissionsImpl(ctx, name)
}
func (fc *FakeClient) GetSecret(ctx context.Context, name string) (*Secret, error) {
	return fc.GetSecretImpl(ctx, name)
}
func (fc *FakeClient) SetURL(_ string) {}
func (fc *FakeClient) SetDialer(dialer func(ctx context.Context, network, addr string) (net.Conn, error)) {
}
func (fc *FakeClient) StrategicMergePatchSecret(context.Context, string, *Secret, string) error {
	return nil
}
func (fc *FakeClient) JSONPatchSecret(context.Context, string, []JSONPatch) error {
	return nil
}
func (fc *FakeClient) UpdateSecret(context.Context, *Secret) error { return nil }
func (fc *FakeClient) CreateSecret(context.Context, *Secret) error { return nil }
