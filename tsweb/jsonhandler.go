// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsweb

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tailscale.com/types/logger"
)

// JSONHandler is like net/http.Handler, but the handler has JSON and Form
// data parsed for it out of http.Request and returns JSON or an error
// that is converted to JSON instead of writing to its ResponseWriter.
type JSONHandler interface {
	// ServeHTTPJSON is like http.Handler.ServeHTTP,
	// except optimized for JSON REST APIs.
	//
	// If the request is a POST, then the request data is decoded
	// and passed as a map to ServeHTTPJSON. The data can be either
	// a url-encoded form or a JSON blob. The JSON blob is required
	// to be a property set (that is, start with '{').
	//
	// The caller will write a response to the ResponseWriter.
	// The response is always a JSON blob, either:
	//
	//	{"success": true, "data": <encoded obj>}
	//
	// or
	//
	//	{"success": false, "error": "<error message>"}
	//
	// If ServeHTTPJSON returns no error, the returned obj is
	// encoded as a JSON property list and sent to the client.
	//
	// If ServeHTTPJSON returns an error, it caller should handle
	// an error by serving an HTTP 500 response to the user. The
	// error details must not be sent to the client, as they may
	// contain sensitive information. If the error is an
	// HTTPError, though, callers should use the HTTP response
	// code and message as the response to the client.
	ServeHTTPJSON(http.ResponseWriter, *http.Request, map[string]interface{}) (obj interface{}, err error)
}

// StdJSONHandler converts a JSONHandler into a standard http.Handler.
// Handled requests are logged using logf, as are any errors. Errors
// are handled as specified by the Handler interface.
func StdJSONHandler(jh JSONHandler, logf logger.Logf) http.Handler {
	return jsonHandler{jh: jh, logf: logf, timeNow: time.Now, log200s: true}
}

// JSONHandlerFunc is an adapter to allow the use of ordinary
// functions as JSONHandlers. If f is a function with the
// appropriate signature, JSONHandlerFunc(f) is a JSONHandler that
// calls f.
//
// See the documentation on JSONHandler.ServeHTTPJSON for semantics
// of the parameters.
type JSONHandlerFunc func(http.ResponseWriter, *http.Request, map[string]interface{}) (interface{}, error)

// ServeHTTPJSON calls f(w, r).
func (f JSONHandlerFunc) ServeHTTPJSON(w http.ResponseWriter, r *http.Request, data map[string]interface{}) (interface{}, error) {
	return f(w, r, data)
}

// jsonHandler is an http.Handler that wraps a Handler and handles JSON.
type jsonHandler struct {
	jh      JSONHandler
	logf    logger.Logf
	timeNow func() time.Time
	log200s bool
}

func parseFormData(w http.ResponseWriter, r *http.Request) (map[string]interface{}, error) {
	postData := make(map[string]interface{})
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch ct {
	case "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		for k, values := range r.Form {
			if len(values) == 1 {
				postData[k] = values[0]
			} else {
				postData[k] = values
			}
		}
	default:
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		b, err := ioutil.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return nil, err
		}
		if len(b) == 0 {
			return nil, err
		}
		if err := json.Unmarshal(b, &postData); err != nil {
			return nil, fmt.Errorf("json decode request: %w", err)
		}
	}
	return postData, nil
}

// ServeHTTP implements the http.Handler interface.
func (h jsonHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	msg := AccessLogRecord{
		When:       h.timeNow(),
		RemoteAddr: r.RemoteAddr,
		Proto:      r.Proto,
		TLS:        r.TLS != nil,
		Host:       r.Host,
		Method:     r.Method,
		RequestURI: r.URL.RequestURI(),
		UserAgent:  r.UserAgent(),
		Referer:    r.Referer(),
	}

	var postData map[string]interface{}

	if r.Method == "POST" {
		var err error
		postData, err = parseFormData(w, r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			// These errors come purely from the parsing of input
			// data the client handed us, with no use of sensitive
			// server data. So give the client the entire error.
			msg.Code = http.StatusBadRequest
			msg.Err = err.Error()
			w.WriteHeader(msg.Code)
			fmt.Fprintf(w, `{"success":false,"error":%q}`+"\n", msg.Err)
			h.logf("%s", msg)
			return
		}
	}

	lw := &loggingResponseWriter{ResponseWriter: w, logf: h.logf}
	retObj, err := h.jh.ServeHTTPJSON(lw, r, postData)
	hErr, hErrOK := err.(HTTPError)

	msg.Seconds = h.timeNow().Sub(msg.When).Seconds()
	msg.Code = lw.code
	msg.Bytes = lw.bytes

	if lw.code == 0 && !lw.hijacked {
		// No response from handler, we will respond.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}

	switch {
	case lw.hijacked:
		// Connection no longer belongs to us, just log that we
		// switched protocols away from HTTP.
		if msg.Code == 0 {
			msg.Code = http.StatusSwitchingProtocols
		}
	case err != nil && r.Context().Err() == context.Canceled:
		msg.Code = 499 // nginx convention: Client Closed Request
		msg.Err = context.Canceled.Error()
	case hErrOK:
		// Handler asked us to send an error. Do so, if we haven't
		// already sent a response.
		if hErr.Err != nil {
			msg.Err = hErr.Err.Error()
		}
		if lw.code != 0 {
			h.logf("[unexpected] handler returned HTTPError %v, but already sent a response with code %d", hErr, lw.code)
			break
		}
		msg.Code = hErr.Code
		if msg.Code == 0 {
			h.logf("[unexpected] HTTPError %v did not contain an HTTP status code, sending internal server error", hErr)
			msg.Code = http.StatusInternalServerError
		}
		w.WriteHeader(msg.Code)
		fmt.Fprintf(w, `{"success":false,"error":%q}`+"\n", hErr.Msg)
	case err != nil:
		// Handler returned a generic error. Serve an internal server
		// error, if necessary.
		msg.Err = err.Error()
		if msg.Code == 0 {
			msg.Code = http.StatusInternalServerError
			w.WriteHeader(msg.Code)
			io.WriteString(w, `{"success":false,"error":"internal server error"}`+"\n")
		}
	case retObj == nil:
		if msg.Code == 0 {
			// Handler did nothing, this is success.
			msg.Code = 200
			w.WriteHeader(msg.Code)
			io.WriteString(w, `{"success":true}`+"\n")
		}
	case retObj != nil:
		if msg.Code != 0 {
			h.logf("[unexpected] handler returned JSON object %v, but already sent a response with code %d", retObj, msg.Code)
			break
		}

		ret := struct {
			Success bool        `json:"success"`
			Data    interface{} `json:"data"`
		}{
			Success: true,
			Data:    retObj,
		}
		b, err := json.Marshal(ret)
		if err != nil {
			h.logf("[unexpected] handler returned object that could not be JSON marshaled: %v", retObj)
			msg.Err = err.Error()
		} else {
			msg.Bytes = len(b)

			if acceptsGzip(r.Header.Get("Accept-Encoding")) {
				zbuf := new(bytes.Buffer)
				gz := gzip.NewWriter(zbuf)
				if _, err := gz.Write(b); err != nil {
					msg.Err = err.Error()
				} else if err := gz.Close(); err != nil {
					msg.Err = err.Error()
				} else {
					w.Header().Set("Content-Encoding", "gzip")
					b = zbuf.Bytes()
				}
			}
		}

		if msg.Err == "" {
			w.Header().Set("Content-Length", fmt.Sprint(len(b)))
			msg.Code = 200
			w.WriteHeader(msg.Code)
			w.Write(b)
		} else {
			msg.Code = http.StatusInternalServerError
			w.WriteHeader(msg.Code)
			fmt.Fprintf(w, `{"success":false,"error":"internal server error"}`+"\n")
		}
	}

	if msg.Code != 200 || h.log200s {
		h.logf("%s", msg)
	}
}

func acceptsGzip(acceptEncoding string) bool {
	for _, enc := range strings.Split(acceptEncoding, ",") {
		rem := ""
		if i := strings.IndexByte(enc, ';'); i > 0 {
			enc, rem = enc[:i], enc[i+1:]
		}
		if enc != "gzip" {
			continue
		}
		if rem == "" {
			return true
		}
		if !strings.HasPrefix(rem, ";q=") {
			continue
		}
		if q, _ := strconv.ParseFloat(strings.TrimPrefix(rem, ";q="), 64); q > 0 {
			return true
		}
	}
	return false
}
