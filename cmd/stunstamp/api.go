// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	sq "github.com/Masterminds/squirrel"
)

type api struct {
	db  *db
	mux *http.ServeMux
}

func newAPI(db *db) *api {
	a := &api{
		db: db,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/query", a.query)
	a.mux = mux
	return a
}

type apiResult struct {
	At         int    `json:"at"` // time.Time.Unix()
	RegionID   int    `json:"regionID"`
	Hostname   string `json:"hostname"`
	Af         int    `json:"af"` // 4 or 6
	Addr       string `json:"addr"`
	Source     int    `json:"source"` // timestampSourceUserspace (0) or timestampSourceKernel (1)
	StableConn bool   `json:"stableConn"`
	DstPort    int    `json:"dstPort"`
	RttNS      *int   `json:"rttNS"`
}

func getTimeBounds(vals url.Values) (from time.Time, to time.Time, err error) {
	lastForm, ok := vals["last"]
	if ok && len(lastForm) > 0 {
		dur, err := time.ParseDuration(lastForm[0])
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		now := time.Now()
		return now.Add(-dur), now, nil
	}

	fromForm, ok := vals["from"]
	if ok && len(fromForm) > 0 {
		fromUnixSec, err := strconv.Atoi(fromForm[0])
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		from = time.Unix(int64(fromUnixSec), 0)
		toForm, ok := vals["to"]
		if ok && len(toForm) > 0 {
			toUnixSec, err := strconv.Atoi(toForm[0])
			if err != nil {
				return time.Time{}, time.Time{}, err
			}
			to = time.Unix(int64(toUnixSec), 0)
		} else {
			return time.Time{}, time.Time{}, errors.New("from specified without to")
		}
		return from, to, nil
	}

	// no time bounds specified, default to last 1h
	now := time.Now()
	return now.Add(-time.Hour), now, nil
}

func (a *api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

func (a *api) query(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	from, to, err := getTimeBounds(r.Form)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	sb := sq.Select("at_unix", "region_id", "hostname", "af", "address", "timestamp_source", "stable_conn", "dst_port", "rtt_ns").From("rtt")
	sb = sb.Where(sq.And{
		sq.GtOrEq{"at_unix": from.Unix()},
		sq.LtOrEq{"at_unix": to.Unix()},
	})
	query, args, err := sb.ToSql()
	if err != nil {
		return
	}

	rows, err := a.db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	results := make([]apiResult, 0)
	for rows.Next() {
		rtt := 0
		result := apiResult{
			RttNS: &rtt,
		}
		err = rows.Scan(&result.At, &result.RegionID, &result.Hostname, &result.Af, &result.Addr, &result.Source, &result.StableConn, &result.DstPort, &result.RttNS)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		results = append(results, result)
	}
	if rows.Err() != nil {
		http.Error(w, rows.Err().Error(), 500)
		return
	}
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		gz := gzip.NewWriter(w)
		defer gz.Close()
		w.Header().Set("Content-Encoding", "gzip")
		err = json.NewEncoder(gz).Encode(&results)
	} else {
		err = json.NewEncoder(w).Encode(&results)
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}
