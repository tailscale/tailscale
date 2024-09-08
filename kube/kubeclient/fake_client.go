// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package kubeclient

import (
	"context"
	"net"

	"tailscale.com/kube/kubeapi"
)

var _ Client = &FakeClient{}

type FakeClient struct {
	GetSecretImpl              func(context.Context, string) (*kubeapi.Secret, error)
	CheckSecretPermissionsImpl func(ctx context.Context, name string) (bool, bool, error)
}

func (fc *FakeClient) CheckSecretPermissions(ctx context.Context, name string) (bool, bool, error) {
	return fc.CheckSecretPermissionsImpl(ctx, name)
}
func (fc *FakeClient) GetSecret(ctx context.Context, name string) (*kubeapi.Secret, error) {
	return fc.GetSecretImpl(ctx, name)
}
func (fc *FakeClient) SetURL(_ string) {}
func (fc *FakeClient) SetDialer(dialer func(ctx context.Context, network, addr string) (net.Conn, error)) {
}
func (fc *FakeClient) StrategicMergePatchSecret(context.Context, string, *kubeapi.Secret, string) error {
	return nil
}
func (fc *FakeClient) JSONPatchSecret(context.Context, string, []JSONPatch) error {
	return nil
}
func (fc *FakeClient) UpdateSecret(context.Context, *kubeapi.Secret) error { return nil }
func (fc *FakeClient) CreateSecret(context.Context, *kubeapi.Secret) error { return nil }
