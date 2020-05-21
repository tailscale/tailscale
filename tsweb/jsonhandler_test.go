// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsweb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestJSONHandler(t *testing.T) {
	jh := JSONHandlerFunc(func(w http.ResponseWriter, r *http.Request, data map[string]interface{}) (interface{}, error) {
		if fail, hasFail := data["fail"]; hasFail {
			var failWithCode int
			switch f := fail.(type) {
			case float64:
				failWithCode = int(f)
			case string:
				var err error
				failWithCode, err = strconv.Atoi(f)
				if err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatalf("unknown 'fail' value: %s (%T)", fail, fail)
			}
			if failWithCode != 0 {
				return nil, HTTPError{Code: failWithCode, Msg: "asked to fail"}
			}
			delete(data, "fail")
		}
		return data, nil
	})

	checkSuccess := func(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
		t.Helper()
		if w.Code != 200 {
			t.Errorf("w.Code=%d, want 200", w.Code)
		}
		res := make(map[string]interface{})
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("cannot decode response: %v\nbytes: %s", err, w.Body.Bytes())
		}
		if success, _ := res["success"].(bool); !success {
			b, err := json.MarshalIndent(res, "", "\t")
			if err != nil {
				t.Fatalf("cannor remarshal: %v", err)
			}
			t.Fatalf("success=false in: %s", b)
		}
		if data, hasData := res["data"]; hasData {
			return data.(map[string]interface{})
		}
		return nil
	}

	t.Run("passthrough", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{"num": 1}`))
		StdJSONHandler(jh, t.Logf).ServeHTTP(w, r)
		data := checkSuccess(t, w)
		if data["num"] != 1.0 {
			t.Errorf(`data["num"]=%v, want 1`, data["num"])
		}
	})

	t.Run("bad json", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{w}`))
		StdJSONHandler(jh, t.Logf).ServeHTTP(w, r)
		const wantCode = http.StatusBadRequest
		if w.Code != wantCode {
			t.Errorf("w.Code=%d, want %d", w.Code, wantCode)
		}
		want := `{"success":false,"error":"json decode request: invalid character 'w' looking for beginning of object key string"}`
		if got := strings.TrimSpace(w.Body.String()); got != want {
			t.Fatalf("bad response:\ngot:  %s\nwant: %s", got, want)
		}
	})

	t.Run("asked to fail", func(t *testing.T) {
		wantCode := http.StatusUnauthorized
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(fmt.Sprintf(`{"fail": %d}`, wantCode)))
		StdJSONHandler(jh, t.Logf).ServeHTTP(w, r)
		if w.Code != wantCode {
			t.Errorf("w.Code=%d, want %d", w.Code, wantCode)
		}
		want := `{"success":false,"error":"asked to fail"}`
		if got := strings.TrimSpace(w.Body.String()); got != want {
			t.Fatalf("bad response:\ngot:  %s\nwant: %s", got, want)
		}
	})

	t.Run("form data", func(t *testing.T) {
		v := url.Values{"num": []string{"42"}}
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(v.Encode()))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		StdJSONHandler(jh, t.Logf).ServeHTTP(w, r)
		data := checkSuccess(t, w)
		if data["num"] != "42" {
			t.Errorf(`data["num"]=%v (%T), want 42`, data["num"], data["num"])
		}
	})

	silent := JSONHandlerFunc(func(http.ResponseWriter, *http.Request, map[string]interface{}) (interface{}, error) {
		return nil, nil
	})
	t.Run("silent POST ok", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", nil)
		StdJSONHandler(silent, t.Logf).ServeHTTP(w, r)
		checkSuccess(t, w)
	})
	t.Run("silent GET ok", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		StdJSONHandler(silent, t.Logf).ServeHTTP(w, r)
		checkSuccess(t, w)
	})
}
