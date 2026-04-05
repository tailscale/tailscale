// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package watch provides a multi-producer, multi-consumer watch channel.
//
// A watch channel retains only the most recent value. Consumers are
// notified when a new value is available, but there is no guarantee
// that they will observe every intermediate value. This makes it
// well-suited for broadcasting state that consumers need the latest
// version of, rather than a complete history.
//
// # Use cases
//
// Common use cases include:
//
//   - Broadcasting configuration changes to multiple goroutines
//   - Signaling program state transitions (e.g. transitioning to shutdown)
//   - Sharing a periodically-updated value with many readers
//
// # Usage
//
// Create a channel with an initial value using [NewChannel]:
//
//	ch := watch.NewChannel(initialConfig)
//
// Obtain senders and receivers from the channel. Multiple senders and
// receivers can coexist concurrently:
//
//	tx := ch.Sender()
//	rx := ch.Receiver()
//
// Send new values from any goroutine:
//
//	tx.Send(newConfig)
//
// Receive values by selecting on [Receiver.Changed]:
//
//	for {
//	    select {
//	    case <-rx.Changed():
//	        cfg := rx.Get()
//	        // handle new config
//	    case <-rx.Done():
//	        return
//	    }
//	}
//
// When the channel is no longer needed, close it to signal all receivers:
//
//	ch.Close()
//
// # Concurrency properties
//
// All types in this package are safe for concurrent use. The channel
// uses a mutex internally and 1-buffered notification channels per
// receiver to achieve efficient, non-blocking notification.
//
// Senders never block (beyond brief mutex acquisition). Receivers are
// notified via a level-triggered mechanism: [Receiver.Changed] remains
// readable as long as there is an unseen value, regardless of how many
// sends occurred since the last [Receiver.Get].
//
// Because only the latest value is retained, slow receivers will skip
// intermediate values. This is by design: consumers always get the
// most recent state, not a potentially stale historical value.
package watch
