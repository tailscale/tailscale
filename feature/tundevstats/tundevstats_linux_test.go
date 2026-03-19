// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tundevstats

import (
	"encoding/binary"
	"os"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"unsafe"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
)

func Test_getIfIndex(t *testing.T) {
	ifIndex, err := getIfIndex("lo")
	if err != nil {
		t.Fatal(err)
	}
	if ifIndex != 1 {
		// loopback ifIndex is effectively always 1 on Linux, see
		// LOOPBACK_IFINDEX in the kernel (net/flow.h).
		t.Fatalf("expected ifIndex of 1 for loopback, got: %d", ifIndex)
	}
}

type fakeDevice struct {
	name string
}

func (f *fakeDevice) File() *os.File                                                 { return nil }
func (f *fakeDevice) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) { return 0, nil }
func (f *fakeDevice) Write(bufs [][]byte, offset int) (int, error)                   { return 0, nil }
func (f *fakeDevice) MTU() (int, error)                                              { return 0, nil }
func (f *fakeDevice) Name() (string, error)                                          { return f.name, nil }
func (f *fakeDevice) Events() <-chan tun.Event                                       { return nil }
func (f *fakeDevice) Close() error                                                   { return nil }
func (f *fakeDevice) BatchSize() int                                                 { return 0 }

func Test_poller(t *testing.T) {
	getTXQDropsMetric().Set(0) // reset for test count > 1

	var drops atomic.Uint64
	// dial is a [nltest.Func] that returns an RTM_NEWSTATS response with [drops]
	// at the txDropped offset within the [rtnlLinkStats64] attribute payload.
	dial := func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) != 1 {
			t.Fatalf("unexpected number of netlink request messages: %d", len(req))
		}
		if req[0].Header.Type != unix.RTM_GETSTATS {
			t.Fatalf("unexpected netlink request message type: %d want: %d", req[0].Header.Type, unix.RTM_GETSTATS)
		}
		data := make([]byte, unsafe.Sizeof(ifStatsMsg{}))
		ae := netlink.NewAttributeEncoder()
		ae.Do(iflaStatsLink64, func() ([]byte, error) {
			ret := make([]byte, unsafe.Sizeof(rtnlLinkStats64{}))
			binary.NativeEndian.PutUint64(ret[56:], drops.Load())
			return ret, nil
		})
		attrs, err := ae.Encode()
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, attrs...)
		return []netlink.Message{
			{
				Header: netlink.Header{
					Type:     unix.RTM_NEWSTATS,
					Sequence: req[0].Header.Sequence,
				},
				Data: data,
			},
		}, nil
	}

	lo := &fakeDevice{name: "lo"}
	drops.Store(1)
	synctest.Test(t, func(t *testing.T) {
		closer, err := newPollerWithNetlinkDialer(lo, func(family int, config *netlink.Config) (*netlink.Conn, error) {
			return nltest.Dial(dial), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait() // first poll complete, poller.run() durably blocked in select
		if got := getTXQDropsMetric().Value(); got != 1 {
			t.Errorf("got drops: %d want: %d", got, 1)
		}
		drops.Store(2) // increment drops to 2
		time.Sleep(pollInterval)
		synctest.Wait() // second poll complete, poller.run() durably blocked in select again
		if got := getTXQDropsMetric().Value(); got != 2 {
			t.Errorf("got drops: %d want: %d", got, 2)
		}
		closer.Close()
		closer.Close() // multiple calls to Close() shouldn't panic
	})

}
