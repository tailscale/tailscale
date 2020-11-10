// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsweb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
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
	checkStatus := func(w *httptest.ResponseRecorder, status string, code int) *Response {
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
			t.Fatalf("wrong status: got: %s, want: %s", d.Status, status)
		}

		if w.Code != code {
			t.Fatalf("wrong status code: got: %d, want: %d", w.Code, code)
		}

		if w.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("wrong content type: %s", w.Header().Get("Content-Type"))
		}

		return d
	}

	h21 := JSONHandlerFunc(func(r *http.Request) (int, interface{}, error) {
		return http.StatusOK, nil, nil
	})

	t.Run("200 simple", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		h21.ServeHTTPReturn(w, r)
		checkStatus(w, "success", http.StatusOK)
	})

	t.Run("403 HTTPError", func(t *testing.T) {
		h := JSONHandlerFunc(func(r *http.Request) (int, interface{}, error) {
			return 0, nil, Error(http.StatusForbidden, "forbidden", nil)
		})

		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		h.ServeHTTPReturn(w, r)
		checkStatus(w, "error", http.StatusForbidden)
	})

	h22 := JSONHandlerFunc(func(r *http.Request) (int, interface{}, error) {
		return http.StatusOK, &Data{Name: "tailscale"}, nil
	})

	t.Run("200 get data", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		h22.ServeHTTPReturn(w, r)
		checkStatus(w, "success", http.StatusOK)
	})

	h31 := JSONHandlerFunc(func(r *http.Request) (int, interface{}, error) {
		body := new(Data)
		if err := json.NewDecoder(r.Body).Decode(body); err != nil {
			return 0, nil, Error(http.StatusBadRequest, err.Error(), err)
		}

		if body.Name == "" {
			return 0, nil, Error(http.StatusBadRequest, "name is empty", nil)
		}

		return http.StatusOK, nil, nil
	})
	t.Run("200 post data", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{"Name": "tailscale"}`))
		h31.ServeHTTPReturn(w, r)
		checkStatus(w, "success", http.StatusOK)
	})

	t.Run("400 bad json", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{`))
		h31.ServeHTTPReturn(w, r)
		checkStatus(w, "error", http.StatusBadRequest)
	})

	t.Run("400 post data error", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
		h31.ServeHTTPReturn(w, r)
		resp := checkStatus(w, "error", http.StatusBadRequest)
		if resp.Error != "name is empty" {
			t.Fatalf("wrong error")
		}
	})

	h32 := JSONHandlerFunc(func(r *http.Request) (int, interface{}, error) {
		body := new(Data)
		if err := json.NewDecoder(r.Body).Decode(body); err != nil {
			return 0, nil, Error(http.StatusBadRequest, err.Error(), err)
		}
		if body.Name == "root" {
			return 0, nil, fmt.Errorf("invalid name")
		}
		if body.Price == 0 {
			return 0, nil, Error(http.StatusBadRequest, "price is empty", nil)
		}

		return http.StatusOK, &Data{Price: body.Price * 2}, nil
	})

	t.Run("200 post data", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{"Price": 10}`))
		h32.ServeHTTPReturn(w, r)
		resp := checkStatus(w, "success", http.StatusOK)
		t.Log(resp.Data)
		if resp.Data.Price != 20 {
			t.Fatalf("wrong price: %d %d", resp.Data.Price, 10)
		}
	})

	t.Run("400 post data error", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
		h32.ServeHTTPReturn(w, r)
		resp := checkStatus(w, "error", http.StatusBadRequest)
		if resp.Error != "price is empty" {
			t.Fatalf("wrong error")
		}
	})

	t.Run("500 internal server error (unspecified error, not of type HTTPError)", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{"Name": "root"}`))
		h32.ServeHTTPReturn(w, r)
		resp := checkStatus(w, "error", http.StatusInternalServerError)
		if resp.Error != "internal server error" {
			t.Fatalf("wrong error")
		}
	})

	t.Run("500 misuse", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", nil)
		JSONHandlerFunc(func(r *http.Request) (int, interface{}, error) {
			return http.StatusOK, make(chan int), nil
		}).ServeHTTPReturn(w, r)
		resp := checkStatus(w, "error", http.StatusInternalServerError)
		if resp.Error != "json marshal error" {
			t.Fatalf("wrong error")
		}
	})

	t.Run("500 empty status code", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", nil)
		JSONHandlerFunc(func(r *http.Request) (status int, data interface{}, err error) {
			return
		}).ServeHTTPReturn(w, r)
		checkStatus(w, "error", http.StatusInternalServerError)
	})

	t.Run("403 forbidden, status returned by JSONHandlerFunc and HTTPError agree", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", nil)
		JSONHandlerFunc(func(r *http.Request) (int, interface{}, error) {
			return http.StatusForbidden, nil, Error(http.StatusForbidden, "403 forbidden", nil)
		}).ServeHTTPReturn(w, r)
		want := &Response{
			Status: "error",
			Data:   &Data{},
			Error:  "403 forbidden",
		}
		got := checkStatus(w, "error", http.StatusForbidden)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Fatalf(diff)
		}
	})

	t.Run("403 forbidden, status returned by JSONHandlerFunc and HTTPError do not agree", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", nil)
		err := JSONHandlerFunc(func(r *http.Request) (int, interface{}, error) {
			return http.StatusInternalServerError, nil, Error(http.StatusForbidden, "403 forbidden", nil)
		}).ServeHTTPReturn(w, r)
		if !strings.HasPrefix(err.Error(), "[unexpected]") {
			t.Fatalf("returned error should have `[unexpected]` to note the disagreeing status codes: %v", err)
		}
		want := &Response{
			Status: "error",
			Data:   &Data{},
			Error:  "403 forbidden",
		}
		got := checkStatus(w, "error", http.StatusForbidden)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Fatalf("(-want,+got):\n%s", diff)
		}
	})
}
