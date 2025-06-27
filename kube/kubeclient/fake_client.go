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
	GetSecretImpl                 func(context.Context, string) (*kubeapi.Secret, error)
	CheckSecretPermissionsImpl    func(ctx context.Context, name string) (bool, bool, error)
	CreateSecretImpl              func(context.Context, *kubeapi.Secret) error
	UpdateSecretImpl              func(context.Context, *kubeapi.Secret) error
	JSONPatchResourceImpl         func(context.Context, string, string, []JSONPatch) error
	ListSecretsImpl               func(context.Context, map[string]string) (*kubeapi.SecretList, error)
	StrategicMergePatchSecretImpl func(context.Context, string, *kubeapi.Secret, string) error
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
func (fc *FakeClient) StrategicMergePatchSecret(ctx context.Context, name string, s *kubeapi.Secret, fieldManager string) error {
	return fc.StrategicMergePatchSecretImpl(ctx, name, s, fieldManager)
}
func (fc *FakeClient) Event(context.Context, string, string, string) error {
	return nil
}

func (fc *FakeClient) JSONPatchResource(ctx context.Context, resource, name string, patches []JSONPatch) error {
	return fc.JSONPatchResourceImpl(ctx, resource, name, patches)
}
func (fc *FakeClient) UpdateSecret(ctx context.Context, secret *kubeapi.Secret) error {
	return fc.UpdateSecretImpl(ctx, secret)
}
func (fc *FakeClient) CreateSecret(ctx context.Context, secret *kubeapi.Secret) error {
	return fc.CreateSecretImpl(ctx, secret)
}
func (fc *FakeClient) ListSecrets(ctx context.Context, selector map[string]string) (*kubeapi.SecretList, error) {
	if fc.ListSecretsImpl != nil {
		return fc.ListSecretsImpl(ctx, selector)
	}
	return nil, nil
}
