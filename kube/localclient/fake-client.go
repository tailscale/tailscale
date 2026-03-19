// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package localclient

import (
	"context"
	"fmt"

	"tailscale.com/ipn"
)

type FakeLocalClient struct {
	FakeIPNBusWatcher
	SetServeCalled bool
	EditPrefsCalls []*ipn.MaskedPrefs
	GetPrefsResult *ipn.Prefs
}

func (m *FakeLocalClient) SetServeConfig(ctx context.Context, cfg *ipn.ServeConfig) error {
	m.SetServeCalled = true
	return nil
}

func (m *FakeLocalClient) EditPrefs(ctx context.Context, mp *ipn.MaskedPrefs) (*ipn.Prefs, error) {
	m.EditPrefsCalls = append(m.EditPrefsCalls, mp)
	if m.GetPrefsResult == nil {
		return &ipn.Prefs{}, nil
	}
	return m.GetPrefsResult, nil
}

func (m *FakeLocalClient) GetPrefs(ctx context.Context) (*ipn.Prefs, error) {
	if m.GetPrefsResult == nil {
		return &ipn.Prefs{}, nil
	}
	return m.GetPrefsResult, nil
}

func (f *FakeLocalClient) WatchIPNBus(ctx context.Context, mask ipn.NotifyWatchOpt) (IPNBusWatcher, error) {
	return &f.FakeIPNBusWatcher, nil
}

func (f *FakeLocalClient) CertPair(ctx context.Context, domain string) ([]byte, []byte, error) {
	return nil, nil, fmt.Errorf("CertPair not implemented")
}

type FakeIPNBusWatcher struct {
	NotifyChan chan ipn.Notify
}

func (f *FakeIPNBusWatcher) Close() error {
	return nil
}

func (f *FakeIPNBusWatcher) Next() (ipn.Notify, error) {
	return <-f.NotifyChan, nil
}
