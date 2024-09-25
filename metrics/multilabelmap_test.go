// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package metrics

import (
	"bytes"
	"encoding/json"
	"expvar"
	"fmt"
	"io"
	"testing"
)

type L2 struct {
	Foo string `prom:"foo"`
	Bar string `prom:"bar"`
}

func TestMultilabelMap(t *testing.T) {
	m := new(MultiLabelMap[L2])
	m.Add(L2{"a", "b"}, 2)
	m.Add(L2{"b", "c"}, 4)
	m.Add(L2{"b", "b"}, 3)
	m.Add(L2{"a", "a"}, 1)

	m.SetFloat(L2{"sf", "sf"}, 3.5)
	m.SetFloat(L2{"sf", "sf"}, 5.5)
	m.Set(L2{"sfunc", "sfunc"}, expvar.Func(func() any { return 3 }))
	m.SetInt(L2{"si", "si"}, 3)
	m.SetInt(L2{"si", "si"}, 5)

	cur := func() string {
		var buf bytes.Buffer
		m.Do(func(kv KeyValue[L2]) {
			if buf.Len() > 0 {
				buf.WriteString(",")
			}
			fmt.Fprintf(&buf, "%s/%s=%v", kv.Key.Foo, kv.Key.Bar, kv.Value)
		})
		return buf.String()
	}

	if g, w := cur(), "a/a=1,a/b=2,b/b=3,b/c=4,sf/sf=5.5,sfunc/sfunc=3,si/si=5"; g != w {
		t.Errorf("got %q; want %q", g, w)
	}

	var buf bytes.Buffer
	m.WritePrometheus(&buf, "metricname")
	const want = `metricname{foo="a",bar="a"} 1
metricname{foo="a",bar="b"} 2
metricname{foo="b",bar="b"} 3
metricname{foo="b",bar="c"} 4
metricname{foo="sf",bar="sf"} 5.5
metricname{foo="sfunc",bar="sfunc"} 3
metricname{foo="si",bar="si"} 5
`
	if got := buf.String(); got != want {
		t.Errorf("promtheus output = %q; want %q", got, want)
	}

	m.Delete(L2{"b", "b"})

	if g, w := cur(), "a/a=1,a/b=2,b/c=4,sf/sf=5.5,sfunc/sfunc=3,si/si=5"; g != w {
		t.Errorf("got %q; want %q", g, w)
	}

	allocs := testing.AllocsPerRun(1000, func() {
		m.Add(L2{"a", "a"}, 1)
	})
	if allocs > 0 {
		t.Errorf("allocs = %v; want 0", allocs)
	}
	m.Init()
	if g, w := cur(), ""; g != w {
		t.Errorf("got %q; want %q", g, w)
	}

	writeAllocs := testing.AllocsPerRun(1000, func() {
		m.WritePrometheus(io.Discard, "test")
	})
	if writeAllocs > 0 {
		t.Errorf("writeAllocs = %v; want 0", writeAllocs)
	}
}

func TestMultiLabelMapTypes(t *testing.T) {
	type LabelTypes struct {
		S string
		B bool
		I int
		U uint
	}

	m := new(MultiLabelMap[LabelTypes])
	m.Type = "counter"
	m.Help = "some good stuff"
	m.Add(LabelTypes{"a", true, -1, 2}, 3)
	var buf bytes.Buffer
	m.WritePrometheus(&buf, "metricname")
	const want = `# TYPE metricname counter
# HELP metricname some good stuff
metricname{s="a",b="true",i="-1",u="2"} 3
`
	if got := buf.String(); got != want {
		t.Errorf("got %q; want %q", got, want)
	}

	writeAllocs := testing.AllocsPerRun(1000, func() {
		m.WritePrometheus(io.Discard, "test")
	})
	if writeAllocs > 0 {
		t.Errorf("writeAllocs = %v; want 0", writeAllocs)
	}
}

func BenchmarkMultiLabelWriteAllocs(b *testing.B) {
	b.ReportAllocs()

	m := new(MultiLabelMap[L2])
	m.Add(L2{"a", "b"}, 2)
	m.Add(L2{"b", "c"}, 4)
	m.Add(L2{"b", "b"}, 3)
	m.Add(L2{"a", "a"}, 1)

	var w io.Writer = io.Discard

	b.ResetTimer()
	for range b.N {
		m.WritePrometheus(w, "test")
	}
}

func TestMultiLabelMapExpvar(t *testing.T) {
	m := new(MultiLabelMap[L2])
	m.Add(L2{"a", "b"}, 2)
	m.Add(L2{"b", "c"}, 4)

	em := new(expvar.Map)
	em.Set("multi", m)

	// Ensure that the String method is valid JSON to ensure that it can be
	// used by expvar.
	encoded := []byte(em.String())
	if !json.Valid(encoded) {
		t.Fatalf("invalid JSON: %s", encoded)
	}

	t.Logf("em = %+v", em)
}
