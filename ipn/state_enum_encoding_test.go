// Code generated by go-enum-encoding; DO NOT EDIT.

package ipn

import (
	"errors"
	"fmt"
	"testing"
)

func ExampleState_MarshalTextName() {
	for _, v := range []State{NoState, InUseOtherUser, NeedsLogin, NeedsMachineAuth, Stopped, Starting, Running} {
		b, _ := v.MarshalTextName()
		fmt.Printf("%s ", string(b))
	}
	// Output: NoState InUseOtherUser NeedsLogin NeedsMachineAuth Stopped Starting Running
}

func ExampleState_UnmarshalTextName() {
	for _, s := range []string{"NoState", "InUseOtherUser", "NeedsLogin", "NeedsMachineAuth", "Stopped", "Starting", "Running"} {
		var v State
		if err := (&v).UnmarshalTextName([]byte(s)); err != nil {
			fmt.Println(err)
		}
	}
}

func TestState_MarshalTextName_UnmarshalTextName(t *testing.T) {
	for _, v := range []State{NoState, InUseOtherUser, NeedsLogin, NeedsMachineAuth, Stopped, Starting, Running} {
		b, err := v.MarshalTextName()
		if err != nil {
			t.Errorf("cannot encode: %s", err)
		}

		var d State
		if err := (&d).UnmarshalTextName(b); err != nil {
			t.Errorf("cannot decode: %s", err)
		}

		if d != v {
			t.Errorf("exp(%v) != got(%v)", v, d)
		}
	}

	t.Run("when unknown value, then error", func(t *testing.T) {
		s := `something`
		var v State
		err := (&v).UnmarshalTextName([]byte(s))
		if err == nil {
			t.Errorf("must be error")
		}
		if !errors.Is(err, ErrUnknownState) {
			t.Errorf("wrong error: %s", err)
		}
	})
}

func BenchmarkState_MarshalTextName(b *testing.B) {
	var v []byte
	var err error
	for i := 0; i < b.N; i++ {
		for _, c := range []State{NoState, InUseOtherUser, NeedsLogin, NeedsMachineAuth, Stopped, Starting, Running} {
			if v, err = c.MarshalTextName(); err != nil {
				b.Fatal("empty")
			}
		}
	}
	if len(v) > 1000 {
		b.Fatal("noop")
	}
}

func BenchmarkState_UnmarshalTextName(b *testing.B) {
	var x State
	for i := 0; i < b.N; i++ {
		for _, c := range []string{"NoState", "InUseOtherUser", "NeedsLogin", "NeedsMachineAuth", "Stopped", "Starting", "Running"} {
			if err := x.UnmarshalTextName([]byte(c)); err != nil {
				b.Fatal("cannot decode")
			}
		}
	}
}
