// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsweb

import (
	"encoding/json"
	"net/http"
)

type response struct {
	Status string      `json:"status"`
	Error  string      `json:"error,omitempty"`
	Data   interface{} `json:"data,omitempty"`
}

// JSONHandlerFunc only take *http.Request as argument to avoid any misuse of http.ResponseWriter.
// The function's results must be (status int, data interface{}, err error)
type JSONHandlerFunc func(r *http.Request) (status int, data interface{}, err error)

// JSONHandler wraps a JSONHandlerFunc with a version that automatically marshals http responses.
//
// Use the following code to unmarshal thr request body
// body := new(DataType)
// if err := json.NewDecoder(r.Body).Decode(body); err != nil {
// 	return http.StatusBadRequest, nil, err
// }
//
// Check jsonhandler_text.go for examples
func JSONHandler(fn JSONHandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var resp *response
		status, data, err := fn(r)
		if err == nil {
			resp = &response{
				Status: "success",
				Data:   data,
			}
		} else {
			resp = &response{
				Status: "error",
				Error:  err.Error(),
				Data:   data,
			}
		}

		if status == 0 {
			status = http.StatusInternalServerError
			resp.Status = "error"
		}
		b, err := json.Marshal(resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"status":"error","error":"json marshal error"}`))
			return
		}

		w.WriteHeader(status)
		w.Write(b)
	})
}
