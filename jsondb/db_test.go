// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jsondb

import (
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDB(t *testing.T) {
	dir, err := os.MkdirTemp("", "db-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "db.json")
	db, err := Open[testDB](path)
	if err != nil {
		t.Fatalf("creating empty DB: %v", err)
	}

	if diff := cmp.Diff(db.Data, &testDB{}, cmp.AllowUnexported(testDB{})); diff != "" {
		t.Fatalf("unexpected empty DB content (-got+want):\n%s", diff)
	}
	db.Data.MyString = "test"
	db.Data.unexported = "don't keep"
	db.Data.AnInt = 42
	if err := db.Save(); err != nil {
		t.Fatalf("saving database: %v", err)
	}

	db2, err := Open[testDB](path)
	if err != nil {
		log.Fatalf("opening DB again: %v", err)
	}
	want := &testDB{
		MyString: "test",
		AnInt:    42,
	}
	if diff := cmp.Diff(db2.Data, want, cmp.AllowUnexported(testDB{})); diff != "" {
		t.Fatalf("unexpected saved DB content (-got+want):\n%s", diff)
	}
}

type testDB struct {
	MyString   string
	unexported string
	AnInt      int64
}
