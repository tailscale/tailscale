// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_jsonv2

package views

import (
	"encoding/json"
	"testing"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/google/go-cmp/cmp"
)

func TestByteSlice_MarshalJSONV2(t *testing.T) {
	compareJSONv1v2(t, ByteSliceOf([]byte{}))
	compareJSONv1v2(t, ByteSliceOf(alwaysMarshalSliceV1[byte]([]byte{255})))
}

func TestSliceView_MarshalJSONV2(t *testing.T) {
	compareJSONv1v2(t, SliceOfViews([]*testobj{
		{1},
		{"a"},
		{alwaysMarshalSliceV1[bool]([]bool{true, false})},
	}))
}

func TestSlice_MarshalJSONV2(t *testing.T) {
	compareJSONv1v2(t, SliceOf([]int{1, 2, 3}))
	compareJSONv1v2(t, SliceOf(alwaysMarshalSliceV1[int]([]int{4, 5, 6})))
}

func TestMapSlice_MarshalJSONV2(t *testing.T) {
	compareJSONv1v2(t, MapSliceOf(map[string][]int{"a": {1, 2, 3}}))
	compareJSONv1v2(t, MapSliceOf(map[string][]alwaysMarshalSliceV1[int]{"a": {{1, 2, 3}}}))
}

func TestMap_MarshalJSONV2(t *testing.T) {
	compareJSONv1v2(t, MapOf(map[string]int{"a": 1, "b": 2}))
	compareJSONv1v2(t, MapOf(map[string]alwaysMarshalSliceV1[int]{"a": {1, 2, 3}}))
}

func TestValuePointer_MarshalJSONV2(t *testing.T) {
	compareJSONv1v2(t, ValuePointerOf(&testobj{}))
	compareJSONv1v2(t, ValuePointerOf(&alwaysMarshalSliceV1[int]{1, 2, 3}))
}

type testobj struct{ V any }

func (o *testobj) Clone() *testobj   { return o }
func (o *testobj) View() testobjView { return testobjView{o} }

type testobjView struct{ O *testobj }

func (v testobjView) Valid() bool        { return v.O != nil }
func (v testobjView) AsStruct() *testobj { return v.O }

var (
	_ ViewCloner[*testobj, testobjView] = (*testobj)(nil)
	_ StructView[*testobj]              = testobjView{}
)

type alwaysMarshalSliceV1[T any] []T

func (m alwaysMarshalSliceV1[T]) MarshalJSON() ([]byte, error) {
	return []byte(`"v1"`), nil
}

func compareJSONv1v2(t testing.TB, v any) {
	t.Helper()
	b1, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal(%T) failed: %s", v, err)
	}
	b2, err := jsonv2.Marshal(v, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("jsonv2.Marshal(%T) failed: %s", v, err)
	}
	t.Logf("%T:\nv1: %s\nv2: %s", v, b1, b2)

	if d := cmp.Diff(string(b1), string(b2)); d != "" {
		t.Fatalf("json %T diff (-v1 +v2)\n%s", v, d)
	}
}
