// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbus_test

import (
	"math/rand/v2"
	"testing"

	"tailscale.com/util/eventbus"
)

func BenchmarkBasicThroughput(b *testing.B) {
	bus := eventbus.New()
	pcli := bus.Client(b.Name() + "-pub")
	scli := bus.Client(b.Name() + "-sub")

	type emptyEvent [0]byte

	// One publisher and a corresponding subscriber shoveling events as fast as
	// they can through the plumbing.
	pub := eventbus.Publish[emptyEvent](pcli)
	sub := eventbus.Subscribe[emptyEvent](scli)

	go func() {
		for {
			select {
			case <-sub.Events():
				continue
			case <-sub.Done():
				return
			}
		}
	}()

	for b.Loop() {
		pub.Publish(emptyEvent{})
	}
	bus.Close()
}

func BenchmarkSubsThroughput(b *testing.B) {
	bus := eventbus.New()
	pcli := bus.Client(b.Name() + "-pub")
	scli1 := bus.Client(b.Name() + "-sub1")
	scli2 := bus.Client(b.Name() + "-sub2")

	type emptyEvent [0]byte

	// One publisher and two subscribers shoveling events as fast as they can
	// through the plumbing.
	pub := eventbus.Publish[emptyEvent](pcli)
	sub1 := eventbus.Subscribe[emptyEvent](scli1)
	sub2 := eventbus.Subscribe[emptyEvent](scli2)

	for _, sub := range []*eventbus.Subscriber[emptyEvent]{sub1, sub2} {
		go func() {
			for {
				select {
				case <-sub.Events():
					continue
				case <-sub.Done():
					return
				}
			}
		}()
	}

	for b.Loop() {
		pub.Publish(emptyEvent{})
	}
	bus.Close()
}

func BenchmarkMultiThroughput(b *testing.B) {
	bus := eventbus.New()
	cli := bus.Client(b.Name())

	type eventA struct{}
	type eventB struct{}

	// Two disjoint event streams routed through the global order.
	apub := eventbus.Publish[eventA](cli)
	asub := eventbus.Subscribe[eventA](cli)
	bpub := eventbus.Publish[eventB](cli)
	bsub := eventbus.Subscribe[eventB](cli)

	go func() {
		for {
			select {
			case <-asub.Events():
				continue
			case <-asub.Done():
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case <-bsub.Events():
				continue
			case <-bsub.Done():
				return
			}
		}
	}()

	var rng uint64
	var bits int
	for b.Loop() {
		if bits == 0 {
			rng = rand.Uint64()
			bits = 64
		}
		if rng&1 == 0 {
			apub.Publish(eventA{})
		} else {
			bpub.Publish(eventB{})
		}
		rng >>= 1
		bits--
	}
	bus.Close()
}
