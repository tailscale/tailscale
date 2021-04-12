// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

type noopManager struct{}

func (m noopManager) SetDNS(OSConfig) error  { return nil }
func (m noopManager) SupportsSplitDNS() bool { return false }
func (m noopManager) Close() error           { return nil }
func (m noopManager) GetBaseConfig() (OSConfig, error) {
	return OSConfig{}, ErrGetBaseConfigNotSupported
}

func NewNoopManager() (noopManager, error) {
	return noopManager{}, nil
}
