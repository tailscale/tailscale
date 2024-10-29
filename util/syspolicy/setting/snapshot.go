// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package setting

import (
	"errors"
	"iter"
	"maps"
	"slices"
	"strings"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	xmaps "golang.org/x/exp/maps"
	"tailscale.com/util/deephash"
)

// Snapshot is an immutable collection of ([Key], [RawItem]) pairs, representing
// a set of policy settings applied at a specific moment in time.
// A nil pointer to [Snapshot] is valid.
type Snapshot struct {
	m       map[Key]RawItem
	sig     deephash.Sum // of m
	summary Summary
}

// NewSnapshot returns a new [Snapshot] with the specified items and options.
func NewSnapshot(items map[Key]RawItem, opts ...SummaryOption) *Snapshot {
	return &Snapshot{m: xmaps.Clone(items), sig: deephash.Hash(&items), summary: SummaryWith(opts...)}
}

// All returns an iterator over policy settings in s. The iteration order is not
// specified and is not guaranteed to be the same from one call to the next.
func (s *Snapshot) All() iter.Seq2[Key, RawItem] {
	if s == nil {
		return func(yield func(Key, RawItem) bool) {}
	}
	return maps.All(s.m)
}

// Get returns the value of the policy setting with the specified key
// or nil if it is not configured or has an error.
func (s *Snapshot) Get(k Key) any {
	v, _ := s.GetErr(k)
	return v
}

// GetErr returns the value of the policy setting with the specified key,
// [ErrNotConfigured] if it is not configured, or an error returned by
// the policy Store if the policy setting could not be read.
func (s *Snapshot) GetErr(k Key) (any, error) {
	if s != nil {
		if s, ok := s.m[k]; ok {
			return s.Value(), s.Error()
		}
	}
	return nil, ErrNotConfigured
}

// GetSetting returns the untyped policy setting with the specified key and true
// if a policy setting with such key has been configured;
// otherwise, it returns zero, false.
func (s *Snapshot) GetSetting(k Key) (setting RawItem, ok bool) {
	setting, ok = s.m[k]
	return setting, ok
}

// Equal reports whether s and s2 are equal.
func (s *Snapshot) Equal(s2 *Snapshot) bool {
	if s == s2 {
		return true
	}
	if !s.EqualItems(s2) {
		return false
	}
	return s.Summary() == s2.Summary()
}

// EqualItems reports whether items in s and s2 are equal.
func (s *Snapshot) EqualItems(s2 *Snapshot) bool {
	if s == s2 {
		return true
	}
	if s.Len() != s2.Len() {
		return false
	}
	if s.Len() == 0 {
		return true
	}
	return s.sig == s2.sig
}

// Keys return an iterator over keys in s. The iteration order is not specified
// and is not guaranteed to be the same from one call to the next.
func (s *Snapshot) Keys() iter.Seq[Key] {
	if s.m == nil {
		return func(yield func(Key) bool) {}
	}
	return maps.Keys(s.m)
}

// Len reports the number of [RawItem]s in s.
func (s *Snapshot) Len() int {
	if s == nil {
		return 0
	}
	return len(s.m)
}

// Summary returns information about s as a whole rather than about specific [RawItem]s in it.
func (s *Snapshot) Summary() Summary {
	if s == nil {
		return Summary{}
	}
	return s.summary
}

// String implements [fmt.Stringer]
func (s *Snapshot) String() string {
	if s.Len() == 0 && s.Summary().IsEmpty() {
		return "{Empty}"
	}
	var sb strings.Builder
	if !s.summary.IsEmpty() {
		sb.WriteRune('{')
		if s.Len() == 0 {
			sb.WriteString("Empty, ")
		}
		sb.WriteString(s.summary.String())
		sb.WriteRune('}')
	}
	for _, k := range slices.Sorted(s.Keys()) {
		if sb.Len() != 0 {
			sb.WriteRune('\n')
		}
		sb.WriteString(string(k))
		sb.WriteString(" = ")
		sb.WriteString(s.m[k].String())
	}
	return sb.String()
}

// snapshotJSON holds JSON-marshallable data for [Snapshot].
type snapshotJSON struct {
	Summary  Summary         `json:",omitzero"`
	Settings map[Key]RawItem `json:",omitempty"`
}

// MarshalJSONV2 implements [jsonv2.MarshalerV2].
func (s *Snapshot) MarshalJSONV2(out *jsontext.Encoder, opts jsonv2.Options) error {
	data := &snapshotJSON{}
	if s != nil {
		data.Summary = s.summary
		data.Settings = s.m
	}
	return jsonv2.MarshalEncode(out, data, opts)
}

// UnmarshalJSONV2 implements [jsonv2.UnmarshalerV2].
func (s *Snapshot) UnmarshalJSONV2(in *jsontext.Decoder, opts jsonv2.Options) error {
	if s == nil {
		return errors.New("s must not be nil")
	}
	data := &snapshotJSON{}
	if err := jsonv2.UnmarshalDecode(in, data, opts); err != nil {
		return err
	}
	*s = Snapshot{m: data.Settings, sig: deephash.Hash(&data.Settings), summary: data.Summary}
	return nil
}

// MarshalJSON implements [json.Marshaler].
func (s *Snapshot) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(s) // uses MarshalJSONV2
}

// UnmarshalJSON implements [json.Unmarshaler].
func (s *Snapshot) UnmarshalJSON(b []byte) error {
	return jsonv2.Unmarshal(b, s) // uses UnmarshalJSONV2
}

// MergeSnapshots returns a [Snapshot] that contains all [RawItem]s
// from snapshot1 and snapshot2 and the [Summary] with the narrower [PolicyScope].
// If there's a conflict between policy settings in the two snapshots,
// the policy settings from the snapshot with the broader scope take precedence.
// In other words, policy settings configured for the [DeviceScope] win
// over policy settings configured for a user scope.
func MergeSnapshots(snapshot1, snapshot2 *Snapshot) *Snapshot {
	scope1, ok1 := snapshot1.Summary().Scope().GetOk()
	scope2, ok2 := snapshot2.Summary().Scope().GetOk()
	if ok1 && ok2 && scope1.StrictlyContains(scope2) {
		// Swap snapshots if snapshot1 has higher precedence than snapshot2.
		snapshot1, snapshot2 = snapshot2, snapshot1
	}
	if snapshot2.Len() == 0 {
		return snapshot1
	}
	summaryOpts := make([]SummaryOption, 0, 2)
	if scope, ok := snapshot1.Summary().Scope().GetOk(); ok {
		// Use the scope from snapshot1, if present, which is the more specific snapshot.
		summaryOpts = append(summaryOpts, scope)
	}
	if snapshot1.Len() == 0 {
		if origin, ok := snapshot2.Summary().Origin().GetOk(); ok {
			// Use the origin from snapshot2 if snapshot1 is empty.
			summaryOpts = append(summaryOpts, origin)
		}
		return &Snapshot{snapshot2.m, snapshot2.sig, SummaryWith(summaryOpts...)}
	}
	m := make(map[Key]RawItem, snapshot1.Len()+snapshot2.Len())
	xmaps.Copy(m, snapshot1.m)
	xmaps.Copy(m, snapshot2.m) // snapshot2 has higher precedence
	return &Snapshot{m, deephash.Hash(&m), SummaryWith(summaryOpts...)}
}
