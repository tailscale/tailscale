//go:build glidertests
// +build glidertests

package ssh

import "testing"

func TestSetPermissions(t *testing.T) {
	t.Parallel()
	permsExt := map[string]string{
		"foo": "bar",
	}
	session, _, cleanup := newTestSessionWithOptions(t, &Server{
		Handler: func(s Session) {
			if _, ok := s.Permissions().Extensions["foo"]; !ok {
				t.Fatalf("got %#v; want %#v", s.Permissions().Extensions, permsExt)
			}
		},
	}, nil, PasswordAuth(func(ctx Context, password string) bool {
		ctx.Permissions().Extensions = permsExt
		return true
	}))
	defer cleanup()
	if err := session.Run(""); err != nil {
		t.Fatal(err)
	}
}

func TestSetValue(t *testing.T) {
	t.Parallel()
	value := map[string]string{
		"foo": "bar",
	}
	key := "testValue"
	session, _, cleanup := newTestSessionWithOptions(t, &Server{
		Handler: func(s Session) {
			v := s.Context().Value(key).(map[string]string)
			if v["foo"] != value["foo"] {
				t.Fatalf("got %#v; want %#v", v, value)
			}
		},
	}, nil, PasswordAuth(func(ctx Context, password string) bool {
		ctx.SetValue(key, value)
		return true
	}))
	defer cleanup()
	if err := session.Run(""); err != nil {
		t.Fatal(err)
	}
}
