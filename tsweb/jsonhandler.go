// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsweb

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type response struct {
	Status string      `json:"status"`
	Error  string      `json:"error,omitempty"`
	Data   interface{} `json:"data,omitempty"`
}

// JSONHandlerFunc is an HTTP ReturnHandler that writes JSON responses to the client.
//
// Return a HTTPError to show an error message, otherwise JSONHandlerFunc will
// only report "internal server error" to the user with status code 500.
type JSONHandlerFunc func(r *http.Request) (status int, data interface{}, err error)

// ServeHTTPReturn implements the ReturnHandler interface.
//
// Use the following code to unmarshal the request body
//
//	body := new(DataType)
//	if err := json.NewDecoder(r.Body).Decode(body); err != nil {
//	  return http.StatusBadRequest, nil, err
//	}
//
// See jsonhandler_test.go for examples.
func (fn JSONHandlerFunc) ServeHTTPReturn(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	var resp *response
	status, data, err := fn(r)
	if err != nil {
		if werr, ok := err.(HTTPError); ok {
			resp = &response{
				Status: "error",
				Error:  werr.Msg,
				Data:   data,
			}
			// Unwrap the HTTPError here because we are communicating with
			// the client in this handler. We don't want the wrapping
			// ReturnHandler to do it too.
			err = werr.Err
			if werr.Msg != "" {
				err = fmt.Errorf("%s: %w", werr.Msg, err)
			}
			// take status from the HTTPError to encourage error handling in one location
			if status != 0 && status != werr.Code {
				err = fmt.Errorf("[unexpected] non-zero status that does not match HTTPError status, status: %d, HTTPError.code: %d: %w", status, werr.Code, err)
			}
			status = werr.Code
		} else {
			status = http.StatusInternalServerError
			resp = &response{
				Status: "error",
				Error:  "internal server error",
			}
		}
	} else if status == 0 {
		status = http.StatusInternalServerError
		resp = &response{
			Status: "error",
			Error:  "internal server error",
		}
	} else if err == nil {
		resp = &response{
			Status: "success",
			Data:   data,
		}
	}

	b, jerr := json.Marshal(resp)
	if jerr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"status":"error","error":"json marshal error"}`))
		if err != nil {
			return fmt.Errorf("%w, and then we could not respond: %v", err, jerr)
		}
		return jerr
	}

	w.WriteHeader(status)
	w.Write(b)
	return err
}
