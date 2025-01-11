package ipn

import (
	"encoding/json"
	"testing"
)

func TestState_String(t *testing.T) {
	tests := []struct {
		s string
		v State
	}{
		{s: "NoState", v: NoState},
		{s: "InUseOtherUser", v: InUseOtherUser},
		{s: "NeedsLogin", v: NeedsLogin},
		{s: "NeedsMachineAuth", v: NeedsMachineAuth},
		{s: "Stopped", v: Stopped},
		{s: "Starting", v: Starting},
		{s: "Running", v: Running},
	}
	for _, tc := range tests {
		if tc.v.String() != tc.s {
			t.Errorf("got %s; want %s", tc.v.String(), tc.s)
		}

		v, err := ParseState(tc.s)
		if v != tc.v {
			t.Errorf("got %v; want %v", v, tc.v)
		}
		if err != nil {
			t.Error(err)
		}
	}

	t.Run("parse unknown", func(t *testing.T) {
		vals := [...]string{"", "unknown"}

		for _, s := range vals {
			v, err := ParseState(s)
			if v != NoState {
				t.Errorf("got %v; want %v", v, NoState)
			}
			if err == nil {
				t.Error("exepected error")
			}
		}
	})
}

func TestState_JSON(t *testing.T) {
	type V struct {
		S State
	}

	tests := []struct {
		S State
		b []byte
	}{
		{NoState, []byte(`{"S":0}`)},
		{InUseOtherUser, []byte(`{"S":1}`)},
		{NeedsLogin, []byte(`{"S":2}`)},
		{NeedsMachineAuth, []byte(`{"S":3}`)},
		{Stopped, []byte(`{"S":4}`)},
		{Starting, []byte(`{"S":5}`)},
		{Running, []byte(`{"S":6}`)},
	}

	for _, test := range tests {
		b, err := json.Marshal(V{S: test.S})
		if err != nil {
			t.Errorf("cannot encode: %s", err)
		}
		if string(b) != string(test.b) {
			t.Errorf("got %s; want %s", b, test.b)
		}

		var d V
		if err := json.Unmarshal(b, &d); err != nil {
			t.Errorf("cannot decode: %s", err)
		}
		if d.S != test.S {
			t.Errorf("got %v; want %v", d.S, test.S)
		}
	}
}
