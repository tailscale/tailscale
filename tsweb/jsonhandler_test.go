// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsweb

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type Data struct {
	Name  string
	Price int
}

type Response struct {
	Status string
	Error  string
	Data   *Data
}

func TestNewJSONHandler(t *testing.T) {
	checkStatus := func(w *httptest.ResponseRecorder, status string) *Response {
		d := &Response{
			Data: &Data{},
		}

		t.Logf("%s", w.Body.Bytes())
		err := json.Unmarshal(w.Body.Bytes(), d)
		if err != nil {
			t.Logf(err.Error())
			return nil
		}

		if d.Status == status {
			t.Logf("ok: %s", d.Status)
		} else {
			t.Fatalf("wrong status: %s %s", d.Status, status)
		}

		return d
	}

	// 2 1
	h21 := JSONHandler(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	t.Run("2 1 simple", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		h21.ServeHTTP(w, r)
		checkStatus(w, "success")
	})

	// 2 2
	h22 := JSONHandler(func(w http.ResponseWriter, r *http.Request) (*Data, error) {
		return &Data{Name: "tailscale"}, nil
	})
	t.Run("2 2 get data", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		h22.ServeHTTP(w, r)
		checkStatus(w, "success")
	})

	// 3 1
	h31 := JSONHandler(func(w http.ResponseWriter, r *http.Request, d *Data) error {
		if d.Name == "" {
			return errors.New("name is empty")
		}

		return nil
	})
	t.Run("3 1 post data", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{"Name": "tailscale"}`))
		h31.ServeHTTP(w, r)
		checkStatus(w, "success")
	})

	t.Run("3 1 bad json", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{`))
		h31.ServeHTTP(w, r)
		checkStatus(w, "error")
	})

	t.Run("3 1 post data error", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
		h31.ServeHTTP(w, r)
		resp := checkStatus(w, "error")
		if resp.Error != "name is empty" {
			t.Fatalf("wrong error")
		}
	})

	// 3 2
	h32 := JSONHandler(func(w http.ResponseWriter, r *http.Request, d *Data) (*Data, error) {
		if d.Price == 0 {
			return nil, errors.New("price is empty")
		}

		return &Data{Price: d.Price * 2}, nil
	})
	t.Run("3 2 post data", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{"Price": 10}`))
		h32.ServeHTTP(w, r)
		resp := checkStatus(w, "success")
		t.Log(resp.Data)
		if resp.Data.Price != 20 {
			t.Fatalf("wrong price: %d %d", resp.Data.Price, 10)
		}
	})

	t.Run("3 2 post data error", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
		h32.ServeHTTP(w, r)
		resp := checkStatus(w, "error")
		if resp.Error != "price is empty" {
			t.Fatalf("wrong error")
		}
	})

	// fn check
	shouldPanic := func() {
		r := recover()
		if r == nil {
			t.Fatalf("should panic")
		}
		t.Log(r)
	}

	t.Run("2 0 panic", func(t *testing.T) {
		defer shouldPanic()
		JSONHandler(func(w http.ResponseWriter, r *http.Request) {})
	})

	t.Run("2 1 panic return value", func(t *testing.T) {
		defer shouldPanic()
		JSONHandler(func(w http.ResponseWriter, r *http.Request) string {
			return ""
		})
	})

	t.Run("2 1 panic arguments", func(t *testing.T) {
		defer shouldPanic()
		JSONHandler(func(r *http.Request, w http.ResponseWriter) error {
			return nil
		})
	})

	t.Run("3 1 panic arguments", func(t *testing.T) {
		defer shouldPanic()
		JSONHandler(func(name string, r *http.Request, w http.ResponseWriter) error {
			return nil
		})
	})

	t.Run("3 2 panic return value", func(t *testing.T) {
		defer shouldPanic()
		//lint:ignore ST1008 intentional
		JSONHandler(func(name string, r *http.Request, w http.ResponseWriter) (error, string) {
			return nil, "panic"
		})
	})

	t.Run("2 2 forbidden", func(t *testing.T) {
		code := http.StatusForbidden
		body := []byte("forbidden")
		h := JSONHandler(func(w http.ResponseWriter, r *http.Request) (*Data, error) {
			w.WriteHeader(code)
			w.Write(body)
			return nil, nil
		})

		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("wrong code: %d %d", w.Code, code)
		}
		if !bytes.Equal(w.Body.Bytes(), []byte("forbidden")) {
			t.Fatalf("wrong body: %s %s", w.Body.Bytes(), body)
		}
	})
}
