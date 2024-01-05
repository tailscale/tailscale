package main

import (
	"bytes"
	"context"
	"encoding/json"
	"expvar"
	"strings"
	"testing"
	"time"
)

var allStats = []*expvar.Int{
	stunIPv4,
	stunIPv6,
	stunNotSTUN,
	stunReadError,
	stunSuccess,
	stunWriteError,
}

func TestStunStats(t *testing.T) {
	doneCtx, cancel := context.WithCancel(context.Background())
	cancel()

	var buf bytes.Buffer

	for _, s := range allStats {
		s.Set(5)
	}

	printSTUNStats(doneCtx, &buf, time.Millisecond)

	for _, s := range allStats {
		s.Set(10)
	}

	readSTUNStats(doneCtx, &buf)

	for _, s := range allStats {
		if s.Value() != 5 {
			t.Errorf("expected %d, got %d", 5, s.Value())
		}
	}
}

func TestStatsEntryContainsAllFields(t *testing.T) {
	s := stats.String()
	var e statsEntry
	d := json.NewDecoder(strings.NewReader(s))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		t.Fatal(err)
	}
}
