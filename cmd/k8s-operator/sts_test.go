// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// Test_statefulSetNameBase tests that parent name portion in a StatefulSet name
// base will be truncated if the parent name is longer than 43 chars to ensure
// that the total does not exceed 52 chars.
// How many chars need to be cut off parent name depends on an internal var in
// kube name generation code that can change at which point this test will break
// and need to be changed. This is okay as we do not rely on that value in
// code whilst being aware when it changes might still be useful.
// https://github.com/kubernetes/kubernetes/blob/v1.28.4/staging/src/k8s.io/apiserver/pkg/storage/names/generate.go#L45.
// https://github.com/kubernetes/kubernetes/pull/116430
func Test_statefulSetNameBase(t *testing.T) {
	// Service name lengths can be 1 - 63 chars, be paranoid and test them all.
	var b strings.Builder
	for b.Len() < 63 {
		if _, err := b.WriteString("a"); err != nil {
			t.Fatalf("error writing to string builder: %v", err)
		}
		baseLength := len(b.String())
		if baseLength > 43 {
			baseLength = 43 // currently 43 is the max base length
		}
		wantsNameR := regexp.MustCompile(`^ts-a{` + fmt.Sprint(baseLength) + `}-$`) // to match a string like ts-aaaa-
		gotName := statefulSetNameBase(b.String())
		if !wantsNameR.MatchString(gotName) {
			t.Fatalf("expected string %s to match regex %s ", gotName, wantsNameR.String()) // fatal rather than error as this test is called 63 times
		}
	}
}
