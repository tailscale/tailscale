package ssh

import (
	"testing"
)

func TestKeysEqual(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("The code did panic")
		}
	}()

	if KeysEqual(nil, nil) {
		t.Error("two nil keys should not return true")
	}
}
