// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

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

func isNoopManager(c OSConfigurator) bool {
	_, ok := c.(noopManager)
	return ok
}
