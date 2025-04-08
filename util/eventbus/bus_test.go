// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbus_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/creachadair/taskgroup"
	"github.com/google/go-cmp/cmp"
	"tailscale.com/util/eventbus"
)

type EventA struct {
	Counter int
}

type EventB struct {
	Counter int
}

func TestBus(t *testing.T) {
	b := eventbus.New()
	defer b.Close()

	c := b.Client("TestSub")
	defer c.Close()
	s := eventbus.Subscribe[EventA](c)

	go func() {
		p := b.Client("TestPub")
		defer p.Close()
		pa := eventbus.Publish[EventA](p)
		defer pa.Close()
		pb := eventbus.Publish[EventB](p)
		defer pb.Close()
		pa.Publish(EventA{1})
		pb.Publish(EventB{2})
		pa.Publish(EventA{3})
	}()

	want := expectEvents(t, EventA{1}, EventA{3})
	for !want.Empty() {
		select {
		case got := <-s.Events():
			want.Got(got)
		case <-s.Done():
			t.Fatalf("queue closed unexpectedly")
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for event")
		}
	}
}

func TestBusMultipleConsumers(t *testing.T) {
	b := eventbus.New()
	defer b.Close()

	c1 := b.Client("TestSubA")
	defer c1.Close()
	s1 := eventbus.Subscribe[EventA](c1)

	c2 := b.Client("TestSubB")
	defer c2.Close()
	s2A := eventbus.Subscribe[EventA](c2)
	s2B := eventbus.Subscribe[EventB](c2)

	go func() {
		p := b.Client("TestPub")
		defer p.Close()
		pa := eventbus.Publish[EventA](p)
		defer pa.Close()
		pb := eventbus.Publish[EventB](p)
		defer pb.Close()
		pa.Publish(EventA{1})
		pb.Publish(EventB{2})
		pa.Publish(EventA{3})
	}()

	wantA := expectEvents(t, EventA{1}, EventA{3})
	wantB := expectEvents(t, EventA{1}, EventB{2}, EventA{3})
	for !wantA.Empty() || !wantB.Empty() {
		select {
		case got := <-s1.Events():
			wantA.Got(got)
		case got := <-s2A.Events():
			wantB.Got(got)
		case got := <-s2B.Events():
			wantB.Got(got)
		case <-s1.Done():
			t.Fatalf("queue closed unexpectedly")
		case <-s2A.Done():
			t.Fatalf("queue closed unexpectedly")
		case <-s2B.Done():
			t.Fatalf("queue closed unexpectedly")
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for event")
		}
	}
}

func TestSpam(t *testing.T) {
	b := eventbus.New()
	defer b.Close()

	const (
		publishers         = 100
		eventsPerPublisher = 20
		wantEvents         = publishers * eventsPerPublisher
		subscribers        = 100
	)

	var g taskgroup.Group

	received := make([][]EventA, subscribers)
	for i := range subscribers {
		c := b.Client(fmt.Sprintf("Subscriber%d", i))
		defer c.Close()
		s := eventbus.Subscribe[EventA](c)
		g.Go(func() error {
			for range wantEvents {
				select {
				case evt := <-s.Events():
					received[i] = append(received[i], evt)
				case <-s.Done():
					t.Errorf("queue done before expected number of events received")
					return errors.New("queue prematurely closed")
				case <-time.After(5 * time.Second):
					t.Errorf("timed out waiting for expected bus event after %d events", len(received[i]))
					return errors.New("timeout")
				}
			}
			return nil
		})
	}

	published := make([][]EventA, publishers)
	for i := range publishers {
		g.Run(func() {
			c := b.Client(fmt.Sprintf("Publisher%d", i))
			p := eventbus.Publish[EventA](c)
			for j := range eventsPerPublisher {
				evt := EventA{i*eventsPerPublisher + j}
				p.Publish(evt)
				published[i] = append(published[i], evt)
			}
		})
	}

	if err := g.Wait(); err != nil {
		t.Fatal(err)
	}
	var last []EventA
	for i, got := range received {
		if len(got) != wantEvents {
			// Receiving goroutine already reported an error, we just need
			// to fail early within the main test goroutine.
			t.FailNow()
		}
		if last == nil {
			continue
		}
		if diff := cmp.Diff(got, last); diff != "" {
			t.Errorf("Subscriber %d did not see the same events as %d (-got+want):\n%s", i, i-1, diff)
		}
		last = got
	}
	for i, sent := range published {
		if got := len(sent); got != eventsPerPublisher {
			t.Fatalf("Publisher %d sent %d events, want %d", i, got, eventsPerPublisher)
		}
	}

	// TODO: check that the published sequences are proper
	// subsequences of the received slices.
}

type queueChecker struct {
	t    *testing.T
	want []any
}

func expectEvents(t *testing.T, want ...any) *queueChecker {
	return &queueChecker{t, want}
}

func (q *queueChecker) Got(v any) {
	q.t.Helper()
	if q.Empty() {
		q.t.Fatalf("queue got unexpected %v", v)
	}
	if v != q.want[0] {
		q.t.Fatalf("queue got %#v, want %#v", v, q.want[0])
	}
	q.want = q.want[1:]
}

func (q *queueChecker) Empty() bool {
	return len(q.want) == 0
}
