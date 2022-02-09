// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsweb

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"go4.org/mem"
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

	if AcceptsEncoding(r, "gzip") {
		encb, err := gzipBytes(b)
		if err != nil {
			return err
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(encb)))
		w.WriteHeader(status)
		w.Write(encb)
	} else {
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.WriteHeader(status)
		w.Write(b)
	}
	return err
}

var gzWriterPool sync.Pool // of *gzip.Writer

// gzipBytes returns the gzipped encoding of b.
func gzipBytes(b []byte) (zb []byte, err error) {
	var buf bytes.Buffer
	zw, ok := gzWriterPool.Get().(*gzip.Writer)
	if ok {
		zw.Reset(&buf)
	} else {
		zw = gzip.NewWriter(&buf)
	}
	defer gzWriterPool.Put(zw)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	zb = buf.Bytes()
	zw.Reset(ioutil.Discard)
	return zb, nil
}

// AcceptsEncoding reports whether r accepts the named encoding
// ("gzip", "br", etc).
func AcceptsEncoding(r *http.Request, enc string) bool {
	h := r.Header.Get("Accept-Encoding")
	if h == "" {
		return false
	}
	if !strings.Contains(h, enc) && !mem.ContainsFold(mem.S(h), mem.S(enc)) {
		return false
	}
	remain := h
	for len(remain) > 0 {
		comma := strings.Index(remain, ",")
		var part string
		if comma == -1 {
			part = remain
			remain = ""
		} else {
			part = remain[:comma]
			remain = remain[comma+1:]
		}
		part = strings.TrimSpace(part)
		if i := strings.Index(part, ";"); i != -1 {
			part = part[:i]
		}
		if part == enc {
			return true
		}
	}
	return false
}
