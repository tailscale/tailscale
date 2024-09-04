// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package kube

// TODO: figure out how to build a mechanism to dynamically update iptables/nftables rules
type EgressServices map[string]EgressService

type EgressService struct {
	TailnetTarget TailnetTarget `json:"tailnetTarget"`
	Ports         []PortMap     `json:"ports"`
}

type TailnetTarget struct {
	IP   string `json:"ip,omitempty"`
	FQDN string `json:"fqdn,omitempty"`
}

type PortMap struct {
	Protocol string `json:"protocol"`
	Src      uint16 `json:"src"`
	Dst      uint16 `json:"dst"`
}

type EgressServicesStatus map[string]EgressServiceStatus

type EgressServiceStatus struct {
	PodIP         string        `json:"podIP"`
	TailnetTarget TailnetTarget `json:"tailnetTarget"`
	Ports         []PortMap     `json:"ports"`
}
