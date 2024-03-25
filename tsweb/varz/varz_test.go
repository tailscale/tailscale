// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package varz

import (
	"expvar"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"tailscale.com/metrics"
	"tailscale.com/tstest"
	"tailscale.com/version"
)

func TestVarzHandler(t *testing.T) {
	t.Run("globals_log", func(t *testing.T) {
		rec := httptest.NewRecorder()
		Handler(rec, httptest.NewRequest("GET", "/", nil))
		t.Logf("Got: %s", rec.Body.Bytes())
	})

	half := new(expvar.Float)
	half.Set(0.5)

	type L2 struct {
		Foo string `prom:"foo"`
		Bar string `prom:"bar"`
	}

	tests := []struct {
		name string
		k    string // key name
		v    expvar.Var
		want string
	}{
		{
			"int",
			"foo",
			new(expvar.Int),
			"# TYPE foo counter\nfoo 0\n",
		},
		{
			"dash_in_metric_name",
			"counter_foo-bar",
			new(expvar.Int),
			"# TYPE foo_bar counter\nfoo_bar 0\n",
		},
		{
			"slash_in_metric_name",
			"counter_foo/bar",
			new(expvar.Int),
			"# TYPE foo_bar counter\nfoo_bar 0\n",
		},
		{
			"metric_name_start_digit",
			"0abc",
			new(expvar.Int),
			"# TYPE _0abc counter\n_0abc 0\n",
		},
		{
			"metric_name_have_bogus_bytes",
			"abc\x10defügh",
			new(expvar.Int),
			"# TYPE abcdefgh counter\nabcdefgh 0\n",
		},
		{
			"int_with_type_counter",
			"counter_foo",
			new(expvar.Int),
			"# TYPE foo counter\nfoo 0\n",
		},
		{
			"int_with_type_gauge",
			"gauge_foo",
			new(expvar.Int),
			"# TYPE foo gauge\nfoo 0\n",
		},
		{
			// For a float = 0.0, Prometheus client_golang outputs "0"
			"float_zero",
			"foo",
			new(expvar.Float),
			"# TYPE foo gauge\nfoo 0\n",
		},
		{
			"float_point_5",
			"foo",
			half,
			"# TYPE foo gauge\nfoo 0.5\n",
		},
		{
			"float_with_type_counter",
			"counter_foo",
			half,
			"# TYPE foo counter\nfoo 0.5\n",
		},
		{
			"float_with_type_gauge",
			"gauge_foo",
			half,
			"# TYPE foo gauge\nfoo 0.5\n",
		},
		{
			"metrics_set",
			"s",
			&metrics.Set{
				Map: *(func() *expvar.Map {
					m := new(expvar.Map)
					m.Init()
					m.Add("foo", 1)
					m.Add("bar", 2)
					return m
				})(),
			},
			"# TYPE s_bar counter\ns_bar 2\n# TYPE s_foo counter\ns_foo 1\n",
		},
		{
			"metrics_set_TODO_gauge_type",
			"gauge_s", // TODO(bradfitz): arguably a bug; should pass down type
			&metrics.Set{
				Map: *(func() *expvar.Map {
					m := new(expvar.Map)
					m.Init()
					m.Add("foo", 1)
					m.Add("bar", 2)
					return m
				})(),
			},
			"# TYPE s_bar counter\ns_bar 2\n# TYPE s_foo counter\ns_foo 1\n",
		},
		{
			"expvar_map_untyped",
			"api_status_code",
			func() *expvar.Map {
				m := new(expvar.Map)
				m.Init()
				m.Add("2xx", 100)
				m.Add("5xx", 2)
				return m
			}(),
			"api_status_code_2xx 100\napi_status_code_5xx 2\n",
		},
		{
			"func_float64",
			"counter_x",
			expvar.Func(func() any { return float64(1.2) }),
			"# TYPE x counter\nx 1.2\n",
		},
		{
			"func_float64_gauge",
			"gauge_y",
			expvar.Func(func() any { return float64(1.2) }),
			"# TYPE y gauge\ny 1.2\n",
		},
		{
			"func_float64_untyped",
			"z",
			expvar.Func(func() any { return float64(1.2) }),
			"z 1.2\n",
		},
		{
			"metrics_label_map",
			"counter_m",
			&metrics.LabelMap{
				Label: "label",
				Map: *(func() *expvar.Map {
					m := new(expvar.Map)
					m.Init()
					m.Add("foo", 1)
					m.Add("bar", 2)
					return m
				})(),
			},
			"# TYPE m counter\nm{label=\"bar\"} 2\nm{label=\"foo\"} 1\n",
		},
		{
			"metrics_label_map_untyped",
			"control_save_config",
			(func() *metrics.LabelMap {
				m := &metrics.LabelMap{Label: "reason"}
				m.Add("new", 1)
				m.Add("updated", 1)
				m.Add("fun", 1)
				return m
			})(),
			"control_save_config{reason=\"fun\"} 1\ncontrol_save_config{reason=\"new\"} 1\ncontrol_save_config{reason=\"updated\"} 1\n",
		},
		{
			"metrics_label_map_unlabeled",
			"foo",
			(func() *metrics.LabelMap {
				m := &metrics.LabelMap{Label: ""}
				m.Add("a", 1)
				return m
			})(),
			"foo{label=\"a\"} 1\n",
		},
		{
			"metrics_multilabel_map",
			"foo",
			(func() *metrics.MultiLabelMap[L2] {
				m := new(metrics.MultiLabelMap[L2])
				m.Add(L2{"a", "b"}, 1)
				m.Add(L2{"c", "d"}, 2)
				return m
			})(),
			"foo{foo=\"a\",bar=\"b\"} 1\n" +
				"foo{foo=\"c\",bar=\"d\"} 2\n",
		},
		{
			"expvar_label_map",
			"counter_labelmap_keyname_m",
			func() *expvar.Map {
				m := new(expvar.Map)
				m.Init()
				m.Add("foo", 1)
				m.Add("bar", 2)
				return m
			}(),
			"# TYPE m counter\nm{keyname=\"bar\"} 2\nm{keyname=\"foo\"} 1\n",
		},
		{
			"struct_reflect",
			"foo",
			someExpVarWithJSONAndPromTypes(),
			strings.TrimSpace(`
# TYPE foo_AUint16 counter
foo_AUint16 65535
# TYPE foo_AnInt8 counter
foo_AnInt8 127
# TYPE foo_curTemp gauge
foo_curTemp 20.6
# TYPE foo_curX gauge
foo_curX 3
# TYPE foo_nestptr_bar counter
foo_nestptr_bar 20
# TYPE foo_nestptr_foo gauge
foo_nestptr_foo 10
# TYPE foo_nestvalue_bar counter
foo_nestvalue_bar 2
# TYPE foo_nestvalue_foo gauge
foo_nestvalue_foo 1
# TYPE foo_totalY counter
foo_totalY 4
`) + "\n",
		},
		{
			"struct_reflect_nil_root",
			"foo",
			expvarAdapter{(*SomeStats)(nil)},
			"",
		},
		{
			"func_returning_int",
			"num_goroutines",
			expvar.Func(func() any { return 123 }),
			"num_goroutines 123\n",
		},
		{
			"string_version_var",
			"foo_version",
			expvar.Func(func() any { return "1.2.3-foo15" }),
			"foo_version{version=\"1.2.3-foo15\"} 1\n",
		},
		{
			"field_ordering",
			"foo",
			someExpVarWithFieldNamesSorting(),
			strings.TrimSpace(`
# TYPE foo_bar_a gauge
foo_bar_a 1
# TYPE foo_bar_b counter
foo_bar_b 1
# TYPE foo_foo_a gauge
foo_foo_a 1
# TYPE foo_foo_b counter
foo_foo_b 1
`) + "\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tstest.Replace(t, &expvarDo, func(f func(expvar.KeyValue)) {
				f(expvar.KeyValue{Key: tt.k, Value: tt.v})
			})
			rec := httptest.NewRecorder()
			Handler(rec, httptest.NewRequest("GET", "/", nil))
			if got := rec.Body.Bytes(); string(got) != tt.want {
				t.Errorf("mismatch\n got: %q\n%s\nwant: %q\n%s\n", got, got, tt.want, tt.want)
			}
		})
	}
}

type SomeNested struct {
	FooG int64 `json:"foo" metrictype:"gauge"`
	BarC int64 `json:"bar" metrictype:"counter"`
	Omit int   `json:"-" metrictype:"counter"`
}

type SomeStats struct {
	Nested       SomeNested  `json:"nestvalue"`
	NestedPtr    *SomeNested `json:"nestptr"`
	NestedNilPtr *SomeNested `json:"nestnilptr"`
	CurX         int         `json:"curX" metrictype:"gauge"`
	NoMetricType int         `json:"noMetric" metrictype:""`
	TotalY       int64       `json:"totalY,omitempty" metrictype:"counter"`
	CurTemp      float64     `json:"curTemp" metrictype:"gauge"`
	AnInt8       int8        `metrictype:"counter"`
	AUint16      uint16      `metrictype:"counter"`
}

// someExpVarWithJSONAndPromTypes returns an expvar.Var that
// implements PrometheusMetricsReflectRooter for TestVarzHandler.
func someExpVarWithJSONAndPromTypes() expvar.Var {
	st := &SomeStats{
		Nested: SomeNested{
			FooG: 1,
			BarC: 2,
			Omit: 3,
		},
		NestedPtr: &SomeNested{
			FooG: 10,
			BarC: 20,
		},
		CurX:    3,
		TotalY:  4,
		CurTemp: 20.6,
		AnInt8:  127,
		AUint16: 65535,
	}
	return expvarAdapter{st}
}

type expvarAdapter struct {
	st *SomeStats
}

func (expvarAdapter) String() string { return "{}" } // expvar JSON; unused in test

func (a expvarAdapter) PrometheusMetricsReflectRoot() any {
	return a.st
}

// SomeTestOfFieldNamesSorting demonstrates field
// names that are not in sorted in declaration order, to verify
// that we sort based on field name
type SomeTestOfFieldNamesSorting struct {
	FooAG int64 `json:"foo_a" metrictype:"gauge"`
	BarAG int64 `json:"bar_a" metrictype:"gauge"`
	FooBC int64 `json:"foo_b" metrictype:"counter"`
	BarBC int64 `json:"bar_b" metrictype:"counter"`
}

// someExpVarWithFieldNamesSorting returns an expvar.Var that
// implements PrometheusMetricsReflectRooter for TestVarzHandler.
func someExpVarWithFieldNamesSorting() expvar.Var {
	st := &SomeTestOfFieldNamesSorting{
		FooAG: 1,
		BarAG: 1,
		FooBC: 1,
		BarBC: 1,
	}
	return expvarAdapter2{st}
}

type expvarAdapter2 struct {
	st *SomeTestOfFieldNamesSorting
}

func (expvarAdapter2) String() string { return "{}" } // expvar JSON; unused in test

func (a expvarAdapter2) PrometheusMetricsReflectRoot() any {
	return a.st
}

func TestSortedStructAllocs(t *testing.T) {
	f := reflect.ValueOf(struct {
		Foo int
		Bar int
		Baz int
	}{})
	n := testing.AllocsPerRun(1000, func() {
		foreachExportedStructField(f, func(fieldOrJSONName, metricType string, rv reflect.Value) {
			// Nothing.
		})
	})
	if n != 0 {
		t.Errorf("allocs = %v; want 0", n)
	}
}

func TestVarzHandlerSorting(t *testing.T) {
	tstest.Replace(t, &expvarDo, func(f func(expvar.KeyValue)) {
		f(expvar.KeyValue{Key: "counter_zz", Value: new(expvar.Int)})
		f(expvar.KeyValue{Key: "gauge_aa", Value: new(expvar.Int)})
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	Handler(rec, req)
	got := rec.Body.Bytes()
	const want = "# TYPE aa gauge\naa 0\n# TYPE zz counter\nzz 0\n"
	if string(got) != want {
		t.Errorf("got %q; want %q", got, want)
	}
	rec = new(httptest.ResponseRecorder) // without a body

	// Lock in the current number of allocs, to prevent it from growing.
	if !version.IsRace() {
		allocs := int(testing.AllocsPerRun(1000, func() {
			Handler(rec, req)
		}))
		if max := 13; allocs > max {
			t.Errorf("allocs = %v; want max %v", allocs, max)
		}
	}
}
