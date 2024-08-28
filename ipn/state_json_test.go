package ipn

import (
	"encoding/json"
	"testing"
)

func TestState_JSON(t *testing.T) {
	t.Run("when json struct with fields and json tags values, then encoding using int", func(t *testing.T) {
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
	})
}
