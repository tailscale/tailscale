// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package varz contains code to export metrics in Prometheus format.
package varz

import (
	"cmp"
	"expvar"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"tailscale.com/metrics"
	"tailscale.com/version"
)

// StaticStringVar returns a new expvar.Var that always returns s.
func StaticStringVar(s string) expvar.Var {
	var v any = s // box s into an interface just once
	return expvar.Func(func() any { return v })
}

func init() {
	expvar.Publish("process_start_unix_time", expvar.Func(func() any { return timeStart.Unix() }))
	expvar.Publish("version", StaticStringVar(version.Long()))
	expvar.Publish("go_version", StaticStringVar(runtime.Version()))
	expvar.Publish("counter_uptime_sec", expvar.Func(func() any { return int64(Uptime().Seconds()) }))
	expvar.Publish("gauge_goroutines", expvar.Func(func() any { return runtime.NumGoroutine() }))
}

const (
	gaugePrefix     = "gauge_"
	counterPrefix   = "counter_"
	labelMapPrefix  = "labelmap_"
	histogramPrefix = "histogram_"
)

// prefixesToTrim contains key prefixes to remove when exporting and sorting metrics.
var prefixesToTrim = []string{gaugePrefix, counterPrefix, labelMapPrefix, histogramPrefix}

var timeStart = time.Now()

func Uptime() time.Duration { return time.Since(timeStart).Round(time.Second) }

// WritePrometheusExpvar writes kv to w in Prometheus metrics format.
//
// See VarzHandler for conventions. This is exported primarily for
// people to test their varz.
func WritePrometheusExpvar(w io.Writer, kv expvar.KeyValue) {
	writePromExpVar(w, "", kv)
}

type prometheusMetricDetails struct {
	Name  string
	Type  string
	Label string
}

var prometheusMetricCache sync.Map // string => *prometheusMetricDetails

func prometheusMetric(prefix string, key string) (string, string, string) {
	cachekey := prefix + key
	if v, ok := prometheusMetricCache.Load(cachekey); ok {
		d := v.(*prometheusMetricDetails)
		return d.Name, d.Type, d.Label
	}
	var typ string
	var label string
	switch {
	case strings.HasPrefix(key, gaugePrefix):
		typ = "gauge"
		key = strings.TrimPrefix(key, gaugePrefix)
	case strings.HasPrefix(key, counterPrefix):
		typ = "counter"
		key = strings.TrimPrefix(key, counterPrefix)
	case strings.HasPrefix(key, histogramPrefix):
		typ = "histogram"
		key = strings.TrimPrefix(key, histogramPrefix)
	}
	if strings.HasPrefix(key, labelMapPrefix) {
		key = strings.TrimPrefix(key, labelMapPrefix)
		if a, b, ok := strings.Cut(key, "_"); ok {
			label, key = a, b
		}
	}

	// Convert the metric to a valid Prometheus metric name.
	// "Metric names may contain ASCII letters, digits, underscores, and colons.
	// It must match the regex [a-zA-Z_:][a-zA-Z0-9_:]*"
	mapInvalidMetricRunes := func(r rune) rune {
		if r >= 'a' && r <= 'z' ||
			r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' ||
			r == '_' || r == ':' {
			return r
		}
		if r < utf8.RuneSelf && unicode.IsPrint(r) {
			return '_'
		}
		return -1
	}
	metricName := strings.Map(mapInvalidMetricRunes, prefix+key)
	if metricName == "" || unicode.IsDigit(rune(metricName[0])) {
		metricName = "_" + metricName
	}

	d := &prometheusMetricDetails{
		Name:  metricName,
		Type:  typ,
		Label: label,
	}
	prometheusMetricCache.Store(cachekey, d)
	return d.Name, d.Type, d.Label
}

func writePromExpVar(w io.Writer, prefix string, kv expvar.KeyValue) {
	key := kv.Key
	name, typ, label := prometheusMetric(prefix, key)

	switch v := kv.Value.(type) {
	case *expvar.Int:
		fmt.Fprintf(w, "# TYPE %s %s\n%s %v\n", name, cmp.Or(typ, "counter"), name, v.Value())
		return
	case *expvar.Float:
		fmt.Fprintf(w, "# TYPE %s %s\n%s %v\n", name, cmp.Or(typ, "gauge"), name, v.Value())
		return
	case *metrics.Set:
		v.Do(func(kv expvar.KeyValue) {
			writePromExpVar(w, name+"_", kv)
		})
		return
	case PrometheusWriter:
		v.WritePrometheus(w, name)
		return
	case PrometheusMetricsReflectRooter:
		root := v.PrometheusMetricsReflectRoot()
		rv := reflect.ValueOf(root)
		if rv.Type().Kind() == reflect.Ptr {
			if rv.IsNil() {
				return
			}
			rv = rv.Elem()
		}
		if rv.Type().Kind() != reflect.Struct {
			fmt.Fprintf(w, "# skipping expvar %q; unknown root type\n", name)
			return
		}
		foreachExportedStructField(rv, func(fieldOrJSONName, metricType string, rv reflect.Value) {
			mname := name + "_" + fieldOrJSONName
			switch rv.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				fmt.Fprintf(w, "# TYPE %s %s\n%s %v\n", mname, metricType, mname, rv.Int())
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
				fmt.Fprintf(w, "# TYPE %s %s\n%s %v\n", mname, metricType, mname, rv.Uint())
			case reflect.Float32, reflect.Float64:
				fmt.Fprintf(w, "# TYPE %s %s\n%s %v\n", mname, metricType, mname, rv.Float())
			case reflect.Struct:
				if rv.CanAddr() {
					// Slight optimization, not copying big structs if they're addressable:
					writePromExpVar(w, name+"_", expvar.KeyValue{Key: fieldOrJSONName, Value: expVarPromStructRoot{rv.Addr().Interface()}})
				} else {
					writePromExpVar(w, name+"_", expvar.KeyValue{Key: fieldOrJSONName, Value: expVarPromStructRoot{rv.Interface()}})
				}
			}
			return
		})
		return
	}

	if typ == "" {
		var funcRet string
		if f, ok := kv.Value.(expvar.Func); ok {
			v := f()
			if ms, ok := v.(runtime.MemStats); ok && name == "memstats" {
				writeMemstats(w, &ms)
				return
			}
			if vs, ok := v.(string); ok && strings.HasSuffix(name, "version") {
				fmt.Fprintf(w, "%s{version=%q} 1\n", name, vs)
				return
			}
			switch v := v.(type) {
			case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, uintptr, float32, float64:
				fmt.Fprintf(w, "%s %v\n", name, v)
				return
			}
			funcRet = fmt.Sprintf(" returning %T", v)
		}
		switch kv.Value.(type) {
		default:
			fmt.Fprintf(w, "# skipping expvar %q (Go type %T%s) with undeclared Prometheus type\n", name, kv.Value, funcRet)
			return
		case *metrics.LabelMap, *expvar.Map:
			// Permit typeless LabelMap and expvar.Map for
			// compatibility with old expvar-registered
			// metrics.LabelMap.
		}
	}

	switch v := kv.Value.(type) {
	case expvar.Func:
		val := v()
		switch val.(type) {
		case float64, int64, int:
			fmt.Fprintf(w, "# TYPE %s %s\n%s %v\n", name, typ, name, val)
		default:
			fmt.Fprintf(w, "# skipping expvar func %q returning unknown type %T\n", name, val)
		}

	case *metrics.LabelMap:
		if typ != "" {
			fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
		}
		// IntMap uses expvar.Map on the inside, which presorts
		// keys. The output ordering is deterministic.
		v.Do(func(kv expvar.KeyValue) {
			fmt.Fprintf(w, "%s{%s=%q} %v\n", name, cmp.Or(v.Label, "label"), kv.Key, kv.Value)
		})
	case *metrics.Histogram:
		v.PromExport(w, name)
	case *expvar.Map:
		if label != "" && typ != "" {
			fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
			v.Do(func(kv expvar.KeyValue) {
				fmt.Fprintf(w, "%s{%s=%q} %v\n", name, label, kv.Key, kv.Value)
			})
		} else {
			v.Do(func(kv expvar.KeyValue) {
				fmt.Fprintf(w, "%s_%s %v\n", name, kv.Key, kv.Value)
			})
		}
	}
}

// PrometheusWriter is the interface implemented by metrics that can write
// themselves into Prometheus exposition format.
//
// As of 2024-03-25, this is only *metrics.MultiLabelMap.
type PrometheusWriter interface {
	WritePrometheus(w io.Writer, name string)
}

var sortedKVsPool = &sync.Pool{New: func() any { return new(sortedKVs) }}

// sortedKV is a KeyValue with a sort key.
type sortedKV struct {
	expvar.KeyValue
	sortKey string // KeyValue.Key with type prefix removed
}

type sortedKVs struct {
	kvs []sortedKV
}

// Handler is an HTTP handler to write expvar values into the
// prometheus export format:
//
//	https://github.com/prometheus/docs/blob/master/content/docs/instrumenting/exposition_formats.md
//
// It makes the following assumptions:
//
//   - *expvar.Int are counters (unless marked as a gauge_; see below)
//   - a *tailscale/metrics.Set is descended into, joining keys with
//     underscores. So use underscores as your metric names.
//   - an expvar named starting with "gauge_" or "counter_" is of that
//     Prometheus type, and has that prefix stripped.
//   - anything else is untyped and thus not exported.
//   - expvar.Func can return an int or int64 (for now) and anything else
//     is not exported.
//
// This will evolve over time, or perhaps be replaced.
func Handler(w http.ResponseWriter, r *http.Request) {
	ExpvarDoHandler(expvarDo)(w, r)
}

// ExpvarDoHandler handler returns a Handler like above, but takes an optional
// expvar.Do func allow the usage of alternative containers of metrics, other
// than the global expvar.Map.
func ExpvarDoHandler(expvarDoFunc func(f func(expvar.KeyValue))) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain;version=0.0.4;charset=utf-8")

		s := sortedKVsPool.Get().(*sortedKVs)
		defer sortedKVsPool.Put(s)
		s.kvs = s.kvs[:0]
		expvarDoFunc(func(kv expvar.KeyValue) {
			s.kvs = append(s.kvs, sortedKV{kv, removeTypePrefixes(kv.Key)})
		})
		sort.Slice(s.kvs, func(i, j int) bool {
			return s.kvs[i].sortKey < s.kvs[j].sortKey
		})
		for _, e := range s.kvs {
			writePromExpVar(w, "", e.KeyValue)
		}
	}
}

// PrometheusMetricsReflectRooter is an optional interface that expvar.Var implementations
// can implement to indicate that they should be walked recursively with reflect to find
// sets of fields to export.
type PrometheusMetricsReflectRooter interface {
	expvar.Var

	// PrometheusMetricsReflectRoot returns the struct or struct pointer to walk.
	PrometheusMetricsReflectRoot() any
}

var expvarDo = expvar.Do // pulled out for tests

func writeMemstats(w io.Writer, ms *runtime.MemStats) {
	out := func(name, typ string, v uint64, help string) {
		if help != "" {
			fmt.Fprintf(w, "# HELP memstats_%s %s\n", name, help)
		}
		fmt.Fprintf(w, "# TYPE memstats_%s %s\nmemstats_%s %v\n", name, typ, name, v)
	}
	g := func(name string, v uint64, help string) { out(name, "gauge", v, help) }
	c := func(name string, v uint64, help string) { out(name, "counter", v, help) }
	g("heap_alloc", ms.HeapAlloc, "current bytes of allocated heap objects (up/down smoothly)")
	c("total_alloc", ms.TotalAlloc, "cumulative bytes allocated for heap objects")
	g("sys", ms.Sys, "total bytes of memory obtained from the OS")
	c("mallocs", ms.Mallocs, "cumulative count of heap objects allocated")
	c("frees", ms.Frees, "cumulative count of heap objects freed")
	c("num_gc", uint64(ms.NumGC), "number of completed GC cycles")
}

// sortedStructField is metadata about a struct field used both for sorting once
// (by structTypeSortedFields) and at serving time (by
// foreachExportedStructField).
type sortedStructField struct {
	Index           int    // index of struct field in struct
	Name            string // struct field name, or "json" name
	SortName        string // Name with "foo_" type prefixes removed
	MetricType      string // the "metrictype" struct tag
	StructFieldType *reflect.StructField
}

var structSortedFieldsCache sync.Map // reflect.Type => []sortedStructField

// structTypeSortedFields returns the sorted fields of t, caching as needed.
func structTypeSortedFields(t reflect.Type) []sortedStructField {
	if v, ok := structSortedFieldsCache.Load(t); ok {
		return v.([]sortedStructField)
	}
	fields := make([]sortedStructField, 0, t.NumField())
	for i, n := 0, t.NumField(); i < n; i++ {
		sf := t.Field(i)
		name := sf.Name
		if v := sf.Tag.Get("json"); v != "" {
			v, _, _ = strings.Cut(v, ",")
			if v == "-" {
				// Skip it, regardless of its metrictype.
				continue
			}
			if v != "" {
				name = v
			}
		}
		fields = append(fields, sortedStructField{
			Index:           i,
			Name:            name,
			SortName:        removeTypePrefixes(name),
			MetricType:      sf.Tag.Get("metrictype"),
			StructFieldType: &sf,
		})
	}
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].SortName < fields[j].SortName
	})
	structSortedFieldsCache.Store(t, fields)
	return fields
}

// removeTypePrefixes returns s with the first "foo_" prefix in prefixesToTrim
// removed.
func removeTypePrefixes(s string) string {
	for _, prefix := range prefixesToTrim {
		if trimmed, ok := strings.CutPrefix(s, prefix); ok {
			return trimmed
		}
	}
	return s
}

// foreachExportedStructField iterates over the fields in sorted order of
// their name, after removing metric prefixes. This is not necessarily the
// order they were declared in the struct
func foreachExportedStructField(rv reflect.Value, f func(fieldOrJSONName, metricType string, rv reflect.Value)) {
	t := rv.Type()
	for _, ssf := range structTypeSortedFields(t) {
		sf := ssf.StructFieldType
		if ssf.MetricType != "" || sf.Type.Kind() == reflect.Struct {
			f(ssf.Name, ssf.MetricType, rv.Field(ssf.Index))
		} else if sf.Type.Kind() == reflect.Ptr && sf.Type.Elem().Kind() == reflect.Struct {
			fv := rv.Field(ssf.Index)
			if !fv.IsNil() {
				f(ssf.Name, ssf.MetricType, fv.Elem())
			}
		}
	}
}

type expVarPromStructRoot struct{ v any }

func (r expVarPromStructRoot) PrometheusMetricsReflectRoot() any { return r.v }
func (r expVarPromStructRoot) String() string                    { panic("unused") }

var (
	_ PrometheusMetricsReflectRooter = expVarPromStructRoot{}
	_ expvar.Var                     = expVarPromStructRoot{}
)
