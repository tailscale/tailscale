// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package watch

import (
	"sync"
	"testing"
	"testing/synctest"
)

func TestInitialValue(t *testing.T) {
	ch := NewChannel(42)
	defer ch.Close()
	rx := ch.Receiver()
	defer rx.Close()

	// Changed should be immediately readable after creating a receiver.
	select {
	case <-rx.Changed():
	default:
		t.Fatal("Changed should be readable for initial value")
	}

	got := rx.Get()
	if got != 42 {
		t.Fatalf("got %d, want 42", got)
	}

	// After Get, Changed should not be readable.
	select {
	case <-rx.Changed():
		t.Fatal("Changed should not be readable after Get with no new sends")
	default:
	}
}

func TestSendAndReceive(t *testing.T) {
	ch := NewChannel(0)
	defer ch.Close()
	tx := ch.Sender()
	rx := ch.Receiver()
	defer rx.Close()

	// Drain the initial notification.
	<-rx.Changed()
	rx.Get()

	tx.Send(1)

	select {
	case <-rx.Changed():
	default:
		t.Fatal("Changed should be readable after Send")
	}

	got := rx.Get()
	if got != 1 {
		t.Fatalf("got %d, want 1", got)
	}
}

func TestOnlyLatestValueRetained(t *testing.T) {
	ch := NewChannel(0)
	defer ch.Close()
	tx := ch.Sender()
	rx := ch.Receiver()
	defer rx.Close()

	// Drain the initial notification.
	<-rx.Changed()
	rx.Get()

	// Send multiple values without reading in between.
	tx.Send(1)
	tx.Send(2)
	tx.Send(3)

	select {
	case <-rx.Changed():
	default:
		t.Fatal("Changed should be readable")
	}

	got := rx.Get()
	if got != 3 {
		t.Fatalf("got %d, want 3 (latest value)", got)
	}
}

func TestMultipleReceivers(t *testing.T) {
	ch := NewChannel("initial")
	defer ch.Close()
	tx := ch.Sender()
	rx1 := ch.Receiver()
	defer rx1.Close()
	rx2 := ch.Receiver()
	defer rx2.Close()

	// Both receivers should see the initial value.
	<-rx1.Changed()
	<-rx2.Changed()
	if got := rx1.Get(); got != "initial" {
		t.Fatalf("rx1 got %q, want %q", got, "initial")
	}
	if got := rx2.Get(); got != "initial" {
		t.Fatalf("rx2 got %q, want %q", got, "initial")
	}

	tx.Send("updated")

	<-rx1.Changed()
	<-rx2.Changed()
	if got := rx1.Get(); got != "updated" {
		t.Fatalf("rx1 got %q, want %q", got, "updated")
	}
	if got := rx2.Get(); got != "updated" {
		t.Fatalf("rx2 got %q, want %q", got, "updated")
	}
}

func TestMultipleSenders(t *testing.T) {
	ch := NewChannel(0)
	defer ch.Close()
	tx1 := ch.Sender()
	tx2 := ch.Sender()
	rx := ch.Receiver()
	defer rx.Close()

	<-rx.Changed()
	rx.Get()

	tx1.Send(10)
	<-rx.Changed()
	if got := rx.Get(); got != 10 {
		t.Fatalf("got %d, want 10", got)
	}

	tx2.Send(20)
	<-rx.Changed()
	if got := rx.Get(); got != 20 {
		t.Fatalf("got %d, want 20", got)
	}
}

func TestCloseSignalsDone(t *testing.T) {
	ch := NewChannel(0)
	rx := ch.Receiver()
	defer rx.Close()

	// Done should not be readable before close.
	select {
	case <-rx.Done():
		t.Fatal("Done should not be readable before Close")
	default:
	}

	ch.Close()

	// Done should now be readable.
	select {
	case <-rx.Done():
	default:
		t.Fatal("Done should be readable after Close")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	ch := NewChannel(0)
	ch.Close()
	ch.Close() // should not panic
}

func TestSendOnClosedPanics(t *testing.T) {
	ch := NewChannel(0)
	tx := ch.Sender()
	ch.Close()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on send to closed channel")
		}
	}()
	tx.Send(1)
}

func TestReceiverClose(t *testing.T) {
	ch := NewChannel(0)
	defer ch.Close()
	tx := ch.Sender()

	rx1 := ch.Receiver()
	rx2 := ch.Receiver()

	// Close rx1 and verify it's removed.
	rx1.Close()

	// Sending should still work and notify rx2 without issues.
	<-rx2.Changed()
	rx2.Get()
	tx.Send(5)
	<-rx2.Changed()
	if got := rx2.Get(); got != 5 {
		t.Fatalf("got %d, want 5", got)
	}

	rx2.Close()
}

func TestReceiverCloseIsIdempotent(t *testing.T) {
	ch := NewChannel(0)
	defer ch.Close()
	rx := ch.Receiver()
	rx.Close()
	rx.Close() // should not panic
}

func TestChangedIsLevelTriggered(t *testing.T) {
	ch := NewChannel(0)
	defer ch.Close()
	tx := ch.Sender()
	rx := ch.Receiver()
	defer rx.Close()

	<-rx.Changed()
	rx.Get()

	tx.Send(1)

	// Changed should be readable.
	select {
	case <-rx.Changed():
	default:
		t.Fatal("Changed should be readable")
	}

	// Even without calling Get, if we somehow drained the channel above,
	// the value is still unseen. But in our design, reading from Changed
	// drains the notification. We need to call Get to mark it seen.
	// Send again to test that the notification channel accumulates correctly.
	tx.Send(2)
	select {
	case <-rx.Changed():
	default:
		// This is expected because we read Changed above but didn't Get.
		// However, Send(2) should have poked again. But since we already
		// drained in the select above and the channel was re-poked by Send(2),
		// it should be readable.
		t.Fatal("Changed should be readable after second Send")
	}

	if got := rx.Get(); got != 2 {
		t.Fatalf("got %d, want 2", got)
	}
}

func TestConcurrentSendAndReceive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ch := NewChannel(0)
		defer ch.Close()

		const numSenders = 5
		const sendsPerSender = 100

		var wg sync.WaitGroup
		for i := range numSenders {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tx := ch.Sender()
				for j := range sendsPerSender {
					tx.Send(i*sendsPerSender + j + 1)
				}
			}()
		}

		rx := ch.Receiver()
		defer rx.Close()

		// Receive in a goroutine until the channel is closed.
		var lastSeen int
		var receiveCount int
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				select {
				case <-rx.Changed():
					v := rx.Get()
					if v != 0 {
						lastSeen = v
						receiveCount++
					}
				case <-rx.Done():
					return
				}
			}
		}()

		wg.Wait()
		ch.Close()
		<-done

		if lastSeen == 0 {
			t.Fatal("receiver should have seen at least one value")
		}
		// We can't assert receiveCount == numSenders*sendsPerSender because
		// intermediate values may be skipped. But we should have received
		// at least one value.
		t.Logf("received %d values, last seen: %d", receiveCount, lastSeen)
	})
}

func TestReceiverCreatedAfterSend(t *testing.T) {
	ch := NewChannel(0)
	defer ch.Close()
	tx := ch.Sender()

	tx.Send(99)

	// Create receiver after sends.
	rx := ch.Receiver()
	defer rx.Close()

	<-rx.Changed()
	got := rx.Get()
	if got != 99 {
		t.Fatalf("got %d, want 99", got)
	}
}

func TestStructValues(t *testing.T) {
	type Config struct {
		Host string
		Port int
	}

	initial := Config{Host: "localhost", Port: 8080}
	ch := NewChannel(initial)
	defer ch.Close()
	tx := ch.Sender()
	rx := ch.Receiver()
	defer rx.Close()

	<-rx.Changed()
	got := rx.Get()
	if got != initial {
		t.Fatalf("got %+v, want %+v", got, initial)
	}

	updated := Config{Host: "example.com", Port: 443}
	tx.Send(updated)
	<-rx.Changed()
	got = rx.Get()
	if got != updated {
		t.Fatalf("got %+v, want %+v", got, updated)
	}
}

func TestGetWithoutChanged(t *testing.T) {
	ch := NewChannel(42)
	defer ch.Close()
	tx := ch.Sender()
	rx := ch.Receiver()
	defer rx.Close()

	// Get can be called at any time to read the current value,
	// without waiting on Changed first.
	got := rx.Get()
	if got != 42 {
		t.Fatalf("got %d, want 42", got)
	}

	tx.Send(100)
	got = rx.Get()
	if got != 100 {
		t.Fatalf("got %d, want 100", got)
	}
}

func TestDoneReadableAfterClose(t *testing.T) {
	ch := NewChannel("")
	rx := ch.Receiver()
	defer rx.Close()

	ch.Close()

	// Both Done and Changed should be readable after close.
	select {
	case <-rx.Done():
		// OK
	default:
		t.Fatal("Done should be readable after close")
	}

	// Changed should also be poked by close so receivers wake up.
	select {
	case <-rx.Changed():
		// OK
	default:
		t.Fatal("Changed should be poked by close")
	}
}

func BenchmarkSendSingleReceiver(b *testing.B) {
	ch := NewChannel(0)
	defer ch.Close()
	tx := ch.Sender()
	rx := ch.Receiver()
	defer rx.Close()
	<-rx.Changed()
	rx.Get()

	b.ResetTimer()
	for i := range b.N {
		tx.Send(i)
		<-rx.Changed()
		rx.Get()
	}
}

func BenchmarkSendNoReceiver(b *testing.B) {
	ch := NewChannel(0)
	defer ch.Close()
	tx := ch.Sender()

	b.ResetTimer()
	for i := range b.N {
		tx.Send(i)
	}
}

func BenchmarkSendManyReceivers(b *testing.B) {
	ch := NewChannel(0)
	defer ch.Close()
	tx := ch.Sender()

	const numReceivers = 100
	receivers := make([]*Receiver[int], numReceivers)
	for i := range numReceivers {
		receivers[i] = ch.Receiver()
		<-receivers[i].Changed()
		receivers[i].Get()
	}
	defer func() {
		for _, rx := range receivers {
			rx.Close()
		}
	}()

	b.ResetTimer()
	for i := range b.N {
		tx.Send(i)
		for _, rx := range receivers {
			<-rx.Changed()
			rx.Get()
		}
	}
}
