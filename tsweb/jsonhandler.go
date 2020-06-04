// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsweb

import (
	"encoding/json"
	"net/http"
	"reflect"
)

type response struct {
	Status string      `json:"status"`
	Error  string      `json:"error,omitempty"`
	Data   interface{} `json:"data,omitempty"`
}

func responseSuccess(data interface{}) *response {
	return &response{
		Status: "success",
		Data:   data,
	}
}

func responseError(e string) *response {
	return &response{
		Status: "error",
		Error:  e,
	}
}

func writeResponse(w http.ResponseWriter, s int, resp *response) {
	b, _ := json.Marshal(resp)
	w.WriteHeader(s)
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func checkFn(t reflect.Type) {
	h := reflect.TypeOf(http.HandlerFunc(nil))
	switch t.NumIn() {
	case 2, 3:
		if !t.In(0).AssignableTo(h.In(0)) {
			panic("first argument must be http.ResponseWriter")
		}
		if !t.In(1).AssignableTo(h.In(1)) {
			panic("second argument must be *http.Request")
		}
	default:
		panic("JSONHandler: number of input parameter should be 2 or 3")
	}

	switch t.NumOut() {
	case 1:
		if !t.Out(0).Implements(reflect.TypeOf((*error)(nil)).Elem()) {
			panic("return value must be error")
		}
	case 2:
		if !t.Out(1).Implements(reflect.TypeOf((*error)(nil)).Elem()) {
			panic("second return value must be error")
		}
	default:
		panic("JSONHandler: number of return values should be 1 or 2")
	}
}

// JSONHandler wraps an HTTP handler function with a version that automatically
// unmarshals and marshals requests and responses respectively into fn's arguments
// and results.
//
// The fn parameter is a function. It must take two or three input arguments.
// The first two arguments must be http.ResponseWriter and *http.Request.
// The optional third argument can be of any type representing the JSON input.
// The function's results can be either (error) or (T, error), where T is the
// JSON-marshalled result type.
//
// For example:
// fn := func(w http.ResponseWriter, r *http.Request, in *Req) (*Res, error) { ... }
func JSONHandler(fn interface{}) http.Handler {
	v := reflect.ValueOf(fn)
	t := v.Type()
	checkFn(t)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wv := reflect.ValueOf(w)
		rv := reflect.ValueOf(r)
		var vs []reflect.Value

		switch t.NumIn() {
		case 2:
			vs = v.Call([]reflect.Value{wv, rv})
		case 3:
			dv := reflect.New(t.In(2))
			err := json.NewDecoder(r.Body).Decode(dv.Interface())
			if err != nil {
				writeResponse(w, http.StatusBadRequest, responseError("bad json"))
				return
			}
			vs = v.Call([]reflect.Value{wv, rv, dv.Elem()})
		default:
			panic("JSONHandler: number of input parameter should be 2 or 3")
		}

		switch len(vs) {
		case 1:
			// todo support other error types
			if vs[0].IsNil() {
				writeResponse(w, http.StatusOK, responseSuccess(nil))
			} else {
				err := vs[0].Interface().(error)
				writeResponse(w, http.StatusBadRequest, responseError(err.Error()))
			}
		case 2:
			if vs[1].IsNil() {
				writeResponse(w, http.StatusOK, responseSuccess(vs[0].Interface()))
			} else {
				err := vs[1].Interface().(error)
				writeResponse(w, http.StatusBadRequest, responseError(err.Error()))
			}
		default:
			panic("JSONHandler: number of return values should be 1 or 2")
		}
	})
}
