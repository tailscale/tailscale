// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package xdp

import (
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type config -type counters_key -type counter_key_af -type counter_key_packets_bytes_action -type counter_key_prog_end bpf xdp.c -- -I headers

// STUNServer manages loading and unloading of an eBPF XDP program that serves
// the STUN protocol. It exports statistics for the XDP program via its
// implementation of the prometheus.Collector interface.
type STUNServer struct {
	mu       sync.Mutex
	objs     *bpfObjects
	metrics  *stunServerMetrics
	dstPort  int
	dropSTUN bool
	link     link.Link
}

//lint:ignore U1000 used in xdp_linux_test.go, which has a build tag
type noAttachOption struct{}

//lint:ignore u1000 Used in xdp_linux_test.go, which has a build tag
func (n noAttachOption) apply(opts *stunServerOptions) {
	opts.noAttach = true
}

func (s *STUNServerConfig) validate() error {
	if len(s.DeviceName) < 1 {
		return errors.New("DeviceName is unspecified")
	}
	if s.DstPort < 0 || s.DstPort > math.MaxUint16 {
		return errors.New("DstPort is outside of uint16 bounds")
	}
	return nil
}

// NewSTUNServer returns an instance of a STUNServer that has attached the STUN
// XDP program to the netdev and destination port specified by config.
func NewSTUNServer(config *STUNServerConfig, opts ...STUNServerOption) (*STUNServer, error) {
	o := &stunServerOptions{}
	for _, opt := range opts {
		opt.apply(o)
	}
	err := config.validate()
	if err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}
	objs := new(bpfObjects)
	err = loadBpfObjects(objs, nil)
	if err != nil {
		var ve *ebpf.VerifierError
		if config.FullVerifierErr && errors.As(err, &ve) {
			err = fmt.Errorf("verifier error: %+v", ve)
		}
		return nil, fmt.Errorf("error loading XDP program: %w", err)
	}
	server := &STUNServer{
		objs:    objs,
		metrics: newSTUNServerMetrics(),
		dstPort: config.DstPort,
	}
	var key uint32
	xdpConfig := &bpfConfig{
		DstPort: uint16(config.DstPort),
	}
	err = objs.ConfigMap.Put(key, xdpConfig)
	if err != nil {
		return nil, fmt.Errorf("error loading config in eBPF map: %w", err)
	}
	if o.noAttach {
		return server, nil
	}
	iface, err := net.InterfaceByName(config.DeviceName)
	if err != nil {
		return nil, fmt.Errorf("error finding device: %w", err)
	}
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
		Flags:     link.XDPAttachFlags(config.AttachFlags),
	})
	if err != nil {
		return nil, fmt.Errorf("error attaching XDP program to dev: %w", err)
	}
	server.link = link
	return server, nil
}

// Close unloads the XDP program and associated maps.
func (s *STUNServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	if s.link != nil {
		errs = append(errs, s.link.Close())
	}
	errs = append(errs, s.objs.Close())
	return errors.Join(errs...)
}

type stunServerMetrics struct {
	last     map[bpfCountersKey]uint64
	registry *prometheus.Registry
	packets  *prometheus.CounterVec
	bytes    *prometheus.CounterVec
}

func newSTUNServerMetrics() *stunServerMetrics {
	last := make(map[bpfCountersKey]uint64)
	registry := prometheus.NewRegistry()
	packets := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "xdp",
		Subsystem: "stun_server",
		Name:      "packets_total",
	}, []string{addressFamilyKey, xdpOutcomeKey, progEndKey})
	bytes := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "xdp",
		Subsystem: "stun_server",
		Name:      "bytes_total",
	}, []string{addressFamilyKey, xdpOutcomeKey, progEndKey})
	registry.MustRegister(packets, bytes)
	return &stunServerMetrics{
		last:     last,
		registry: registry,
		packets:  packets,
		bytes:    bytes,
	}
}

const (
	xdpOutcomeKey = "xdp_outcome"
	progEndKey    = "prog_end"
)

const (
	xdpOutcomePass    = "pass"
	xdpOutcomeAborted = "aborted"
	xdpOutcomeDrop    = "drop"
	xdpOutcomeTX      = "tx"
)

func sum(vals []uint64) uint64 {
	var s uint64
	for _, v := range vals {
		s += v
	}
	return s
}

const (
	addressFamilyKey = "address_family"
)

const (
	addressFamilyUnknown = "unknown"
	addressFamilyIPv4    = "ipv4"
	addressFamilyIPv6    = "ipv6"
)

var (
	// TODO(jwhited): go generate these maps or equivalent switch logic behind bpf2go
	pbaToOutcomeLV = map[bpfCounterKeyPacketsBytesAction]string{
		bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL:    xdpOutcomePass,
		bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL:      xdpOutcomePass,
		bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_ABORTED_TOTAL: xdpOutcomeAborted,
		bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_ABORTED_TOTAL:   xdpOutcomeAborted,
		bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_TX_TOTAL:      xdpOutcomeTX,
		bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_TX_TOTAL:        xdpOutcomeTX,
		bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_DROP_TOTAL:    xdpOutcomeDrop,
		bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_DROP_TOTAL:      xdpOutcomeDrop,
	}

	progEndLV = map[bpfCounterKeyProgEnd]string{
		bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED:                "unspecified",
		bpfCounterKeyProgEndCOUNTER_KEY_END_UNEXPECTED_FIRST_STUN_ATTR: "unexpected_first_stun_attr",
		bpfCounterKeyProgEndCOUNTER_KEY_END_INVALID_UDP_CSUM:           "invalid_udp_csum",
		bpfCounterKeyProgEndCOUNTER_KEY_END_INVALID_IP_CSUM:            "invalid_ip_csum",
		bpfCounterKeyProgEndCOUNTER_KEY_END_NOT_STUN_PORT:              "not_stun_port",
		bpfCounterKeyProgEndCOUNTER_KEY_END_INVALID_SW_ATTR_VAL:        "invalid_sw_attr_val",
		bpfCounterKeyProgEndCOUNTER_KEY_END_DROP_STUN:                  "drop_stun",
	}

	packetCounterKeys = map[bpfCounterKeyPacketsBytesAction]bool{
		bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL:    true,
		bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_ABORTED_TOTAL: true,
		bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_TX_TOTAL:      true,
		bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_DROP_TOTAL:    true,
	}

	//lint:ignore U1000 used in xdp_linux_test.go, which has a build tag
	bytesCounterKeys = map[bpfCounterKeyPacketsBytesAction]bool{
		bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL:    true,
		bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_ABORTED_TOTAL: true,
		bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_TX_TOTAL:      true,
		bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_DROP_TOTAL:    true,
	}
)

// increase returns the difference between "from" and "to" assuming they
// originated from the same counter gathered at different times, i.e. "from"
// was incremented by a non-negative value into "to". In the case of wraps
// increase returns the difference between "to" and zero.
func increase(from, to uint64) uint64 {
	if to >= from {
		return to - from
	}
	return to
}

func (s *stunServerMetrics) updateFromMapKV(key bpfCountersKey, vals []uint64) error {
	if key.Unused != 0 ||
		key.Af >= uint8(bpfCounterKeyAfCOUNTER_KEY_AF_LEN) ||
		key.Pba >= uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_BYTES_ACTION_LEN) ||
		key.ProgEnd >= uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_LEN) {
		return fmt.Errorf("unexpected counter key: %+v", key)
	}
	previousAllCPUs := s.last[key]
	allCPUs := sum(vals)
	s.last[key] = allCPUs
	inc := increase(previousAllCPUs, allCPUs)
	if inc == 0 {
		return nil
	}
	var af string
	switch key.Af {
	case uint8(bpfCounterKeyAfCOUNTER_KEY_AF_UNKNOWN):
		af = addressFamilyUnknown
	case uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4):
		af = addressFamilyIPv4
	case uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6):
		af = addressFamilyIPv6
	}
	labels := prometheus.Labels{
		addressFamilyKey: af,
		xdpOutcomeKey:    pbaToOutcomeLV[bpfCounterKeyPacketsBytesAction(key.Pba)],
		progEndKey:       progEndLV[bpfCounterKeyProgEnd(key.ProgEnd)],
	}
	var metric *prometheus.CounterVec
	if packetCounterKeys[bpfCounterKeyPacketsBytesAction(key.Pba)] {
		metric = s.packets
	} else {
		metric = s.bytes
	}
	metric.With(labels).Add(float64(inc))
	return nil
}

// Describe is part of the implementation of prometheus.Collector.
func (s *STUNServer) Describe(descCh chan<- *prometheus.Desc) {
	s.metrics.registry.Describe(descCh)
}

// Collect is part of the implementation of prometheus.Collector.
func (s *STUNServer) Collect(metricCh chan<- prometheus.Metric) {
	err := s.updateMetrics()
	if err != nil {
		log.Printf("xdp: error collecting metrics: %v", err)
	}
	s.metrics.registry.Collect(metricCh)
}

func (s *STUNServer) SetDropSTUN(v bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dropSTUN := 0
	if v {
		dropSTUN = 1
	}
	xdpConfig := &bpfConfig{
		DstPort:  uint16(s.dstPort),
		DropStun: uint16(dropSTUN),
	}
	var key uint32
	err := s.objs.ConfigMap.Put(key, xdpConfig)
	if err == nil {
		s.dropSTUN = v
	}
	return err
}

func (s *STUNServer) GetDropSTUN() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropSTUN
}

func (s *STUNServer) updateMetrics() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	iter := s.objs.CountersMap.Iterate()
	var key bpfCountersKey
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return err
	}
	vals := make([]uint64, numCPU)
	for iter.Next(&key, &vals) {
		err := s.metrics.updateFromMapKV(key, vals)
		if err != nil {
			return err
		}
	}
	return iter.Err()
}
