// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package source

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/setting"
)

// hujsonStandardize is set to hujson.Standardize by json_policy_store_hujson.go
// on platforms that have HuJSON support compiled in. When non-nil, the JSON
// policy file may use HuJSON (comments and trailing commas); when nil, the
// file must be pure standard JSON.
var hujsonStandardize func([]byte) ([]byte, error)

var _ Store = (*JSONPolicyStore)(nil)

// JSONPolicyStore is a [Store] backed by a JSON object that maps policy
// setting keys to values. It is a read-only snapshot; the underlying map
// is captured at construction time and never re-read.
//
// JSON values are mapped to policy setting types as follows:
//   - strings map to [setting.StringValue], [setting.PreferenceOptionValue],
//     [setting.VisibilityValue], and [setting.DurationValue]. For
//     [setting.DurationValue], the string is parsed by [time.ParseDuration]
//     elsewhere in the package (e.g. "24h", "5m").
//   - booleans map to [setting.BooleanValue].
//   - numbers map to [setting.IntegerValue]. Negative or non-integer values
//     are rejected with [setting.ErrTypeMismatch].
//   - arrays of strings map to [setting.StringListValue].
type JSONPolicyStore struct {
	m map[string]any
}

// NewJSONPolicyStore returns a new [JSONPolicyStore] backed by the given map.
// A nil or empty map results in a store that reports every key as
// [setting.ErrNotConfigured].
func NewJSONPolicyStore(m map[string]any) *JSONPolicyStore {
	return &JSONPolicyStore{m: m}
}

// NewJSONPolicyStoreFromFile reads the file at path and returns a new
// [JSONPolicyStore] backed by its contents. The file must contain a JSON
// object at its top level. JSON numbers are decoded as [json.Number] to
// preserve precision for [setting.IntegerValue] settings.
func NewJSONPolicyStoreFromFile(path string) (*JSONPolicyStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return NewJSONPolicyStoreFromBytes(data)
}

// NewJSONPolicyStoreFromBytes is like [NewJSONPolicyStoreFromFile] but reads
// from data instead of a file. When HuJSON support is linked into the build,
// data may be HuJSON (comments and trailing commas allowed); otherwise it
// must be pure standard JSON.
func NewJSONPolicyStoreFromBytes(data []byte) (*JSONPolicyStore, error) {
	if buildfeatures.HasHuJSONConf && hujsonStandardize != nil {
		std, err := hujsonStandardize(data)
		if err != nil {
			return nil, fmt.Errorf("syspolicy: parsing HuJSON/JSON: %w", err)
		}
		data = std
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("syspolicy: parsing JSON: %w", err)
	}
	return &JSONPolicyStore{m: m}, nil
}

// ReadString implements [Store].
func (s *JSONPolicyStore) ReadString(key pkey.Key) (string, error) {
	v, ok := s.m[string(key)]
	if !ok {
		return "", setting.ErrNotConfigured
	}
	str, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: %q is %T, want string", setting.ErrTypeMismatch, key, v)
	}
	return str, nil
}

// ReadBoolean implements [Store].
func (s *JSONPolicyStore) ReadBoolean(key pkey.Key) (bool, error) {
	v, ok := s.m[string(key)]
	if !ok {
		return false, setting.ErrNotConfigured
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%w: %q is %T, want bool", setting.ErrTypeMismatch, key, v)
	}
	return b, nil
}

// ReadUInt64 implements [Store].
func (s *JSONPolicyStore) ReadUInt64(key pkey.Key) (uint64, error) {
	v, ok := s.m[string(key)]
	if !ok {
		return 0, setting.ErrNotConfigured
	}
	switch n := v.(type) {
	case json.Number:
		u, err := strconv.ParseUint(n.String(), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%w: %q is not a uint64: %v", setting.ErrTypeMismatch, key, err)
		}
		return u, nil
	case float64:
		if n < 0 || n > math.MaxUint64 || n != math.Trunc(n) {
			return 0, fmt.Errorf("%w: %q (%v) is not a uint64", setting.ErrTypeMismatch, key, n)
		}
		return uint64(n), nil
	default:
		return 0, fmt.Errorf("%w: %q is %T, want number", setting.ErrTypeMismatch, key, v)
	}
}

// ReadStringArray implements [Store].
func (s *JSONPolicyStore) ReadStringArray(key pkey.Key) ([]string, error) {
	v, ok := s.m[string(key)]
	if !ok {
		return nil, setting.ErrNotConfigured
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: %q is %T, want array", setting.ErrTypeMismatch, key, v)
	}
	res := make([]string, len(arr))
	for i, e := range arr {
		str, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("%w: %q[%d] is %T, want string", setting.ErrTypeMismatch, key, i, e)
		}
		res[i] = str
	}
	return res, nil
}

// Validate checks that every key in the parsed JSON corresponds to a
// registered policy setting (per [setting.Definitions]) and that its value
// can be successfully decoded as the registered setting's type. It joins
// all problems into a single error so callers see every issue at once
// instead of one per startup-then-runtime cycle.
//
// Validate triggers registration of any deferred setting definitions, so
// it should only be called after all init-time registrations have run.
func (s *JSONPolicyStore) Validate() error {
	defs, err := setting.Definitions()
	if err != nil {
		return err
	}
	byKey := make(map[pkey.Key]*setting.Definition, len(defs))
	for _, d := range defs {
		byKey[d.Key()] = d
	}

	keys := make([]string, 0, len(s.m))
	for k := range s.m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var errs []error
	for _, k := range keys {
		def, ok := byKey[pkey.Key(k)]
		if !ok {
			errs = append(errs, fmt.Errorf("unknown policy setting %q", k))
			continue
		}
		if err := s.validateValue(def); err != nil {
			errs = append(errs, fmt.Errorf("%q: %w", k, err))
		}
	}
	return errors.Join(errs...)
}

// validateValue is like [readPolicySettingValue] but is stricter for the
// enum-like [setting.PreferenceOptionValue] and [setting.VisibilityValue]
// types: their runtime UnmarshalText silently coerces unknown strings to a
// default, which is fine at read time but defeats the point of load-time
// validation, so this checks the raw string against the known values.
func (s *JSONPolicyStore) validateValue(def *setting.Definition) error {
	key := def.Key()
	switch def.Type() {
	case setting.PreferenceOptionValue:
		str, err := s.ReadString(key)
		if err != nil {
			return err
		}
		switch str {
		case "always", "never", "user-decides":
			return nil
		}
		return fmt.Errorf(`%w: %q is not a valid PreferenceOption ("always", "never", or "user-decides")`, setting.ErrTypeMismatch, str)
	case setting.VisibilityValue:
		str, err := s.ReadString(key)
		if err != nil {
			return err
		}
		switch str {
		case "show", "hide":
			return nil
		}
		return fmt.Errorf(`%w: %q is not a valid Visibility ("show" or "hide")`, setting.ErrTypeMismatch, str)
	default:
		_, err := readPolicySettingValue(s, def)
		return err
	}
}
