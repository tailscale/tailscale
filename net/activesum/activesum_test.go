package activesum

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

type testDatum struct {
	offset time.Duration
	bytes  uint64
	iface  string
}

var tests = []struct {
	name string
	data []testDatum
	want []Event
}{
	{
		name: "basic",
		data: []testDatum{
			{offset: 0, bytes: 128, iface: "eth0"},
			{offset: time.Millisecond, bytes: 512, iface: "eth0"},
			{offset: 2 * time.Millisecond, bytes: 256, iface: "eth0"},
			{offset: time.Second - 3*time.Millisecond, bytes: 128, iface: "eth0"},
			{offset: 2 * Idle, bytes: 128, iface: "eth0"},
			{offset: 2 * Idle, bytes: 50, iface: "eth0"},
			{offset: 0, bytes: 50, iface: "lte0"},
			{offset: time.Second, bytes: 50, iface: "eth0"},
			{offset: Idle - 1*time.Second, bytes: 50, iface: "eth0"},
			{offset: Idle - 1*time.Second, bytes: 50, iface: "eth0"},
			{offset: Idle - 1*time.Second, bytes: 50, iface: "eth0"},
			{offset: Idle - 1*time.Second, bytes: 50, iface: "eth0"},
		},
		want: []Event{
			{Start: start, Duration: time.Second, Bytes: 1024, Interface: "eth0"},
			{Start: start.Add(2*Idle + time.Second), Bytes: 128, Interface: "eth0"},
			{Start: start.Add(4*Idle + time.Second), Bytes: 50, Interface: "eth0"},
			{Start: start.Add(4*Idle + time.Second), Bytes: 50, Interface: "lte0"},
			{Start: start.Add(4*Idle + 2*time.Second), Duration: 1*time.Minute + 56*time.Second, Bytes: 250, Interface: "eth0"},
		},
	},
}

var start = time.Date(1999, time.December, 31, 11, 11, 11, 0, time.UTC)

func TestActiveSum(t *testing.T) {
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := start
			timeNow = func() time.Time { return now }
			timeSince = func(t time.Time) time.Duration { return now.Sub(t) }
			t.Cleanup(func() {
				timeNow = time.Now
				timeSince = time.Since
			})

			var got []Event
			a := &ActiveSum{EventFunc: func(ev Event) {
				got = append(got, ev)
			}}
			for _, d := range test.data {
				now = now.Add(d.offset)
				a.Record(d.bytes, d.iface)
			}
			a.Close()
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("events mismatch (-got +want):\n%s", cmp.Diff(got, test.want))
			}
		})
	}
}
