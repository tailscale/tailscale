package chaos

import (
	"cmp"
	"slices"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	xmaps "golang.org/x/exp/maps"
)

func TestTagsMetricLabel(t *testing.T) {
	tests := []struct {
		name       string
		tags       []string
		fullLabels bool
		want       string
	}{
		{
			name:       "empty1",
			tags:       []string{},
			fullLabels: true,
			want:       "",
		},
		{
			name:       "empty2",
			tags:       []string{},
			fullLabels: false,
			want:       "",
		},
		{
			name:       "one_trimmed",
			tags:       []string{"tag:foo15"},
			fullLabels: false,
			want:       "foo",
		},
		{
			name:       "one_full",
			tags:       []string{"tag:foo15"},
			fullLabels: true,
			want:       "foo15",
		},
		{
			name:       "two_trimmed",
			tags:       []string{"tag:foo15", "tag:bar"},
			fullLabels: false,
			want:       "foo,bar",
		},
		{
			name:       "one_full",
			tags:       []string{"tag:foo", "tag:bar0"},
			fullLabels: true,
			want:       "foo,bar0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tagsMetricLabel(tt.tags, tt.fullLabels); got != tt.want {
				t.Errorf("tagsMetricLabel(%v, %v) = %v, want %v", tt.tags, tt.fullLabels, got, tt.want)
			}
		})
	}
}

func TestUUIDConversion(t *testing.T) {
	tests := []uuid.UUID{
		uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
		uuid.MustParse("00000000-0000-0000-0000-000000000000"),
	}
	for _, tt := range tests {
		hostname := uuidToHostname(tt)
		got, err := hostnameToUUID(hostname)
		if err != nil {
			t.Errorf("hostnameToUUID(%q) error = %v", hostname, err)
			continue
		}
		if got != tt {
			t.Errorf("RoundTrip failed: uuidToHostname(%v) -> hostnameToUUID(%q) = %v, want %v", tt, hostname, got, tt)
		}
	}
}

func TestLatencyTracker(t *testing.T) {
	lt := newLatencyTracker()
	c := qt.New(t)

	u1 := uuid.UUID{0: 1 * 16}
	u2 := uuid.UUID{0: 2 * 16}
	u3 := uuid.UUID{0: 3 * 16}
	u4 := uuid.UUID{0: 4 * 16}
	u5 := uuid.UUID{0: 5 * 16}

	assertNeverSeenCount := func(first, all int) {
		t.Helper()
		c.Assert(testutil.ToFloat64(lt.countNeverSeen), qt.Equals, float64(first))
		c.Assert(testutil.ToFloat64(lt.countNotFullySeen), qt.Equals, float64(all))
	}

	assertUnseenCount := func(first, all int) {
		t.Helper()
		c.Assert(len(lt.unseenFirst), qt.Equals, first, qt.Commentf("first: %+v", lt.unseenFirst))
		c.Assert(len(lt.unseenAll), qt.Equals, all, qt.Commentf("first: %+v", lt.unseenAll))
		c.Assert(testutil.ToFloat64(lt.numUnseenFirst.WithLabelValues("foo")), qt.Equals, float64(first))
		c.Assert(testutil.ToFloat64(lt.numUnseenAll.WithLabelValues("foo")), qt.Equals, float64(all))
	}

	assertUnseenFirst := func(uuids ...uuid.UUID) {
		t.Helper()

		sortUUIDS(uuids)
		keys := xmaps.Keys(lt.unseenFirst)
		sortUUIDS(keys)
		c.Assert(uuids, qt.DeepEquals, keys)
	}
	assertUnseenAll := func(uuids ...uuid.UUID) {
		t.Helper()

		sortUUIDS(uuids)
		got := xmaps.Keys(lt.unseenAll)
		sortUUIDS(got)
		c.Assert(uuids, qt.DeepEquals, got)
	}

	lt.Start(u1, "foo")
	assertUnseenCount(1, 1)
	assertNeverSeenCount(0, 0)

	lt.Start(u2, "foo")
	lt.Start(u3, "foo")
	lt.Start(u4, "foo")
	lt.Start(u5, "foo")
	assertUnseenCount(5, 5)
	assertNeverSeenCount(0, 0)

	// u1 saw u2 and u3
	lt.processUpdate(visibilityUpdate{
		t:     time.Now(),
		self:  u1,
		peers: map[uuid.UUID]bool{u2: true, u3: true},
	})
	assertUnseenCount(3, 4)
	assertNeverSeenCount(0, 0)
	assertUnseenFirst(u1, u4, u5)
	assertUnseenAll(u2, u3, u4, u5)

	// u2 saw u1 and u3
	lt.processUpdate(visibilityUpdate{
		t:     time.Now(),
		self:  u2,
		peers: map[uuid.UUID]bool{u1: true, u3: true},
	})
	// u3 saw u1 and u2
	lt.processUpdate(visibilityUpdate{
		t:     time.Now(),
		self:  u3,
		peers: map[uuid.UUID]bool{u1: true, u2: true},
	})
	assertUnseenCount(2, 2)
	assertNeverSeenCount(0, 0)
	assertUnseenFirst(u4, u5)
	assertUnseenAll(u4, u5)

	// u3 saw u4
	lt.processUpdate(visibilityUpdate{
		t:     time.Now(),
		self:  u3,
		peers: map[uuid.UUID]bool{u4: true},
	})
	assertUnseenCount(1, 2)
	assertNeverSeenCount(0, 0)
	assertUnseenFirst(u5)
	assertUnseenAll(u4, u5)

	// u4 and u5 are gone.
	lt.processUpdate(visibilityUpdate{t: time.Now(), self: u4, deleted: true})
	lt.processUpdate(visibilityUpdate{t: time.Now(), self: u5, deleted: true})
	assertUnseenCount(0, 0)
	assertNeverSeenCount(1, 2)
}

func sortUUIDS(uuids []uuid.UUID) {
	slices.SortFunc(uuids, func(a, b uuid.UUID) int {
		for i := range len(uuid.UUID{}) {
			if a[i] == b[i] {
				continue
			}
			return cmp.Compare(a[i], b[i])
		}
		return 0
	})
}
