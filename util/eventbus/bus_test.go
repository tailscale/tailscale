// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbus_test

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"regexp"
	"sync"
	"testing"
	"testing/synctest"
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
	cdone := c.Done()
	defer func() {
		c.Close()
		select {
		case <-cdone:
			t.Log("Client close signal received (OK)")
		case <-time.After(time.Second):
			t.Error("timed out waiting for client close signal")
		}
	}()
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

func TestSubscriberFunc(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := eventbus.New()
		defer b.Close()

		c := b.Client("TestClient")

		exp := expectEvents(t, EventA{12345})
		eventbus.SubscribeFunc[EventA](c, func(e EventA) { exp.Got(e) })

		p := eventbus.Publish[EventA](c)
		p.Publish(EventA{12345})

		synctest.Wait()
		c.Close()

		if !exp.Empty() {
			t.Errorf("unexpected extra events: %+v", exp.want)
		}
	})

	t.Run("CloseWait", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			b := eventbus.New()
			defer b.Close()

			c := b.Client(t.Name())

			eventbus.SubscribeFunc[EventA](c, func(e EventA) {
				time.Sleep(2 * time.Second)
			})

			p := eventbus.Publish[EventA](c)
			p.Publish(EventA{12345})

			synctest.Wait() // subscriber has the event
			c.Close()

			// If close does not wait for the subscriber, the test will fail
			// because an active goroutine remains in the bubble.
		})
	})

	t.Run("CloseWait/Belated", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			buf := swapLogBuf(t)

			b := eventbus.New()
			defer b.Close()

			c := b.Client(t.Name())

			// This subscriber stalls for a long time, so that when we try to
			// close the client it gives up and returns in the timeout condition.
			eventbus.SubscribeFunc[EventA](c, func(e EventA) {
				time.Sleep(time.Minute) // notably, longer than the wait period
			})

			p := eventbus.Publish[EventA](c)
			p.Publish(EventA{12345})

			synctest.Wait() // subscriber has the event
			c.Close()

			// Verify that the logger recorded that Close gave up on the slowpoke.
			want := regexp.MustCompile(`^.* tailscale.com/util/eventbus_test bus_test.go:\d+: ` +
				`giving up on subscriber for eventbus_test.EventA after \d+s at close.*`)
			if got := buf.String(); !want.MatchString(got) {
				t.Errorf("Wrong log output\ngot:  %q\nwant %s", got, want)
			}

			// Wait for the subscriber to actually finish to clean up the goroutine.
			time.Sleep(2 * time.Minute)
		})
	})

	t.Run("SubscriberPublishes", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			b := eventbus.New()
			defer b.Close()

			c := b.Client("TestClient")
			pa := eventbus.Publish[EventA](c)
			pb := eventbus.Publish[EventB](c)
			exp := expectEvents(t, EventA{127}, EventB{128})
			eventbus.SubscribeFunc[EventA](c, func(e EventA) {
				exp.Got(e)
				pb.Publish(EventB{Counter: e.Counter + 1})
			})
			eventbus.SubscribeFunc[EventB](c, func(e EventB) {
				exp.Got(e)
			})

			pa.Publish(EventA{127})

			synctest.Wait()
			c.Close()
			if !exp.Empty() {
				t.Errorf("unepxected extra events: %+v", exp.want)
			}
		})
	})
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

func TestClientMixedSubscribers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := eventbus.New()
		defer b.Close()

		c := b.Client("TestClient")

		var gotA EventA
		s1 := eventbus.Subscribe[EventA](c)

		var gotB EventB
		eventbus.SubscribeFunc[EventB](c, func(e EventB) {
			t.Logf("func sub received %[1]T %+[1]v", e)
			gotB = e
		})

		go func() {
			for {
				select {
				case <-s1.Done():
					return
				case e := <-s1.Events():
					t.Logf("chan sub received %[1]T %+[1]v", e)
					gotA = e
				}
			}
		}()

		p1 := eventbus.Publish[EventA](c)
		p2 := eventbus.Publish[EventB](c)

		go p1.Publish(EventA{12345})
		go p2.Publish(EventB{67890})

		synctest.Wait()
		c.Close()
		synctest.Wait()

		if diff := cmp.Diff(gotB, EventB{67890}); diff != "" {
			t.Errorf("Chan sub (-got, +want):\n%s", diff)
		}
		if diff := cmp.Diff(gotA, EventA{12345}); diff != "" {
			t.Errorf("Func sub (-got, +want):\n%s", diff)
		}
	})
}

func TestSpam(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := eventbus.New()
		defer b.Close()

		const (
			publishers         = 100
			eventsPerPublisher = 20
			wantEvents         = publishers * eventsPerPublisher
			subscribers        = 100
		)

		var g taskgroup.Group

		// A bunch of subscribers receiving on channels.
		chanReceived := make([][]EventA, subscribers)
		for i := range subscribers {
			c := b.Client(fmt.Sprintf("Subscriber%d", i))
			defer c.Close()

			s := eventbus.Subscribe[EventA](c)
			g.Go(func() error {
				for range wantEvents {
					select {
					case evt := <-s.Events():
						chanReceived[i] = append(chanReceived[i], evt)
					case <-s.Done():
						t.Errorf("queue done before expected number of events received")
						return errors.New("queue prematurely closed")
					case <-time.After(5 * time.Second):
						t.Logf("timed out waiting for expected bus event after %d events", len(chanReceived[i]))
						return errors.New("timeout")
					}
				}
				return nil
			})
		}

		// A bunch of subscribers receiving via a func.
		funcReceived := make([][]EventA, subscribers)
		for i := range subscribers {
			c := b.Client(fmt.Sprintf("SubscriberFunc%d", i))
			defer c.Close()
			eventbus.SubscribeFunc(c, func(e EventA) {
				funcReceived[i] = append(funcReceived[i], e)
			})
		}

		published := make([][]EventA, publishers)
		for i := range publishers {
			c := b.Client(fmt.Sprintf("Publisher%d", i))
			p := eventbus.Publish[EventA](c)
			g.Run(func() {
				defer c.Close()
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
		synctest.Wait()

		tests := []struct {
			name string
			recv [][]EventA
		}{
			{"Subscriber", chanReceived},
			{"SubscriberFunc", funcReceived},
		}
		for _, tc := range tests {
			for i, got := range tc.recv {
				if len(got) != wantEvents {
					t.Errorf("%s %d: got %d events, want %d", tc.name, i, len(got), wantEvents)
				}
				if i == 0 {
					continue
				}
				if diff := cmp.Diff(got, tc.recv[i-1]); diff != "" {
					t.Errorf("%s %d did not see the same events as %d (-got+want):\n%s", tc.name, i, i-1, diff)
				}
			}
		}
		for i, sent := range published {
			if got := len(sent); got != eventsPerPublisher {
				t.Fatalf("Publisher %d sent %d events, want %d", i, got, eventsPerPublisher)
			}
		}

		// TODO: check that the published sequences are proper
		// subsequences of the received slices.
	})
}

func TestClient_Done(t *testing.T) {
	b := eventbus.New()
	defer b.Close()

	c := b.Client(t.Name())
	s := eventbus.Subscribe[string](c)

	// The client is not Done until closed.
	select {
	case <-c.Done():
		t.Fatal("Client done before being closed")
	default:
		// OK
	}

	go c.Close()

	// Once closed, the client becomes Done.
	select {
	case <-c.Done():
		// OK
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for Client to be done")
	}

	// Thereafter, the subscriber should also be closed.
	select {
	case <-s.Done():
		// OK
	case <-time.After(time.Second):
		t.Fatal("timoeout waiting for Subscriber to be done")
	}
}

func TestMonitor(t *testing.T) {
	t.Run("ZeroWait", func(t *testing.T) {
		var zero eventbus.Monitor

		ready := make(chan struct{})
		go func() { zero.Wait(); close(ready) }()

		select {
		case <-ready:
			// OK
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for Wait to return")
		}
	})

	t.Run("ZeroDone", func(t *testing.T) {
		var zero eventbus.Monitor

		select {
		case <-zero.Done():
			// OK
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for zero monitor to be done")
		}
	})

	t.Run("ZeroClose", func(t *testing.T) {
		var zero eventbus.Monitor

		ready := make(chan struct{})
		go func() { zero.Close(); close(ready) }()

		select {
		case <-ready:
			// OK
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for Close to return")
		}
	})

	testMon := func(t *testing.T, release func(*eventbus.Client, eventbus.Monitor)) func(t *testing.T) {
		t.Helper()
		return func(t *testing.T) {
			bus := eventbus.New()
			cli := bus.Client("test client")

			// The monitored goroutine runs until the client or test subscription ends.
			sub := eventbus.Subscribe[string](cli)
			m := cli.Monitor(func(c *eventbus.Client) {
				select {
				case <-c.Done():
					t.Log("client closed")
				case <-sub.Done():
					t.Log("subscription closed")
				}
			})

			done := make(chan struct{})
			go func() {
				defer close(done)
				m.Wait()
			}()

			// While the goroutine is running, Wait does not complete.
			select {
			case <-done:
				t.Error("monitor is ready before its goroutine is finished (Wait)")
			default:
				// OK
			}
			select {
			case <-m.Done():
				t.Error("monitor is ready before its goroutine is finished (Done)")
			default:
				// OK
			}

			release(cli, m)
			select {
			case <-done:
				// OK
			case <-time.After(time.Second):
				t.Fatal("timeout waiting for monitor to complete (Wait)")
			}
			select {
			case <-m.Done():
				// OK
			case <-time.After(time.Second):
				t.Fatal("timeout waiting for monitor to complete (Done)")
			}
		}
	}
	t.Run("Close", testMon(t, func(_ *eventbus.Client, m eventbus.Monitor) { m.Close() }))
	t.Run("Wait", testMon(t, func(c *eventbus.Client, m eventbus.Monitor) { c.Close(); m.Wait() }))
}

func TestSlowSubs(t *testing.T) {
	t.Run("Subscriber", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			buf := swapLogBuf(t)

			b := eventbus.New()
			defer b.Close()

			pc := b.Client("pub")
			p := eventbus.Publish[EventA](pc)

			sc := b.Client("sub")
			s := eventbus.Subscribe[EventA](sc)

			go func() {
				time.Sleep(6 * time.Second) // trigger the slow check at 5s.
				t.Logf("Subscriber accepted %v", <-s.Events())
			}()

			p.Publish(EventA{12345})

			time.Sleep(7 * time.Second) // advance time...
			synctest.Wait()             // subscriber is done

			want := regexp.MustCompile(`^.* tailscale.com/util/eventbus_test bus_test.go:\d+: ` +
				`subscriber for eventbus_test.EventA is slow.*`)
			if got := buf.String(); !want.MatchString(got) {
				t.Errorf("Wrong log output\ngot:  %q\nwant: %s", got, want)
			}
		})
	})

	t.Run("SubscriberFunc", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			buf := swapLogBuf(t)

			b := eventbus.New()
			defer b.Close()

			pc := b.Client("pub")
			p := eventbus.Publish[EventB](pc)

			sc := b.Client("sub")
			eventbus.SubscribeFunc[EventB](sc, func(e EventB) {
				time.Sleep(6 * time.Second) // trigger the slow check at 5s.
				t.Logf("SubscriberFunc processed %v", e)
			})

			p.Publish(EventB{67890})

			time.Sleep(7 * time.Second) // advance time...
			synctest.Wait()             // subscriber is done

			want := regexp.MustCompile(`^.* tailscale.com/util/eventbus_test bus_test.go:\d+: ` +
				`subscriber for eventbus_test.EventB is slow.*`)
			if got := buf.String(); !want.MatchString(got) {
				t.Errorf("Wrong log output\ngot:  %q\nwant: %s", got, want)
			}
		})
	})
}

func TestRegression(t *testing.T) {
	bus := eventbus.New()
	t.Cleanup(bus.Close)

	t.Run("SubscribeClosed", func(t *testing.T) {
		c := bus.Client("test sub client")
		c.Close()

		var v any
		func() {
			defer func() { v = recover() }()
			eventbus.Subscribe[string](c)
		}()
		if v == nil {
			t.Fatal("Expected a panic from Subscribe on a closed client")
		} else {
			t.Logf("Got expected panic: %v", v)
		}
	})

	t.Run("PublishClosed", func(t *testing.T) {
		c := bus.Client("test pub client")
		c.Close()

		var v any
		func() {
			defer func() { v = recover() }()
			eventbus.Publish[string](c)
		}()
		if v == nil {
			t.Fatal("expected a panic from Publish on a closed client")
		} else {
			t.Logf("Got expected panic: %v", v)
		}
	})
}

func TestPublishWithMutex(t *testing.T) {
	testPublishWithMutex(t, 1024) // arbitrary large number of events
}

// testPublishWithMutex publishes the specified number of events,
// acquiring and releasing a mutex around each publish and each
// subscriber event receive.
//
// The test fails if it loses any events or times out due to a deadlock.
// Unfortunately, a goroutine waiting on a mutex held by a durably blocked
// goroutine is not itself considered durably blocked, so [synctest] cannot
// detect this deadlock on its own.
func testPublishWithMutex(t *testing.T, n int) {
	synctest.Test(t, func(t *testing.T) {
		b := eventbus.New()
		defer b.Close()

		c := b.Client("TestClient")

		evts := make([]any, n)
		for i := range evts {
			evts[i] = EventA{Counter: i}
		}
		exp := expectEvents(t, evts...)

		var mu sync.Mutex
		eventbus.SubscribeFunc[EventA](c, func(e EventA) {
			// Acquire the same mutex as the publisher.
			mu.Lock()
			mu.Unlock()

			// Mark event as received, so we can check for lost events.
			exp.Got(e)
		})

		p := eventbus.Publish[EventA](c)
		go func() {
			// Publish events, acquiring the mutex around each publish.
			for i := range n {
				mu.Lock()
				p.Publish(EventA{Counter: i})
				mu.Unlock()
			}
		}()

		synctest.Wait()

		if !exp.Empty() {
			t.Errorf("unexpected extra events: %+v", exp.want)
		}
	})
}

func TestPublishFromSubscriber(t *testing.T) {
	testPublishFromSubscriber(t, 1024) // arbitrary large number of events
}

// testPublishFromSubscriber publishes the specified number of EventA events.
// Each EventA causes the subscriber to publish an EventB.
// The test fails if it loses any events or if a deadlock occurs.
func testPublishFromSubscriber(t *testing.T, n int) {
	synctest.Test(t, func(t *testing.T) {
		b := eventbus.New()
		defer b.Close()

		c := b.Client("TestClient")

		// Ultimately we expect to receive n EventB events
		// published as a result of receiving n EventA events.
		evts := make([]any, n)
		for i := range evts {
			evts[i] = EventB{Counter: i}
		}
		exp := expectEvents(t, evts...)

		pubA := eventbus.Publish[EventA](c)
		pubB := eventbus.Publish[EventB](c)

		eventbus.SubscribeFunc[EventA](c, func(e EventA) {
			// Upon receiving EventA, publish EventB.
			pubB.Publish(EventB{Counter: e.Counter})
		})
		eventbus.SubscribeFunc[EventB](c, func(e EventB) {
			// Mark EventB as received.
			exp.Got(e)
		})

		for i := range n {
			pubA.Publish(EventA{Counter: i})
		}

		synctest.Wait()

		if !exp.Empty() {
			t.Errorf("unexpected extra events: %+v", exp.want)
		}
	})
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
		q.t.Errorf("queue got unexpected %v", v)
		return
	}
	if v != q.want[0] {
		q.t.Errorf("queue got %#v, want %#v", v, q.want[0])
		return
	}
	q.want = q.want[1:]
}

func (q *queueChecker) Empty() bool {
	return len(q.want) == 0
}

func swapLogBuf(t *testing.T) *bytes.Buffer {
	logBuf := new(bytes.Buffer)
	save := log.Writer()
	log.SetOutput(logBuf)
	t.Cleanup(func() { log.SetOutput(save) })
	return logBuf
}
