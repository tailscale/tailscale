// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsweb

import (
	"encoding/json"
	"net/http"
	"reflect"
)

// NewJSONHandler wraps an HTTP handler function with a version that automatically
// unmarshals and marshals requests and responses respectively into fn's arguments
// and results.
// fn must have a signature with 2 or 3 input arguments. The first two must be http.ResponseWriter and
// *http.Request. The optional third argument can be of any type.
// fn's result parameter can be either (error) or (T, error), where T is the JSON-marshalled result type.
func NewJSONHandler(fn interface{}) http.Handler {
	v := reflect.ValueOf(fn)
	t := v.Type()
	// reflect.Call games
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
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			vs = v.Call([]reflect.Value{wv, rv, dv.Elem()})
		default:
			panic("wrong")
		}

		switch len(vs) {
		case 1:
			// todo support other error types
			if vs[0].IsNil() {
				w.WriteHeader(http.StatusOK)
				b, _ := json.Marshal(struct {
					Status string
				}{
					Status: "success",
				})
				w.Header().Set("Content-Type", "application/json")
				w.Write(b)
			} else {
				err := vs[0].Interface().(error)
				w.WriteHeader(http.StatusBadRequest)
				b, _ := json.Marshal(struct {
					Status string
					Error  string
				}{
					Status: "error",
					Error:  err.Error(),
				})
				w.Header().Set("Content-Type", "application/json")
				w.Write(b)
			}
		case 2:
			if vs[1].IsNil() {
				w.WriteHeader(http.StatusOK)
				b, _ := json.Marshal(struct {
					Status string
					Data   interface{}
				}{
					Status: "success",
					Data:   vs[0].Interface(),
				})
				w.Header().Set("Content-Type", "application/json")
				w.Write(b)
			} else {
				err := vs[1].Interface().(error)
				w.WriteHeader(http.StatusBadRequest)
				b, _ := json.Marshal(struct {
					Status string
					Error  string
				}{
					Status: "error",
					Error:  err.Error(),
				})
				w.Header().Set("Content-Type", "application/json")
				w.Write(b)
			}
		default:
			panic("wrong")
		}
	})
}
