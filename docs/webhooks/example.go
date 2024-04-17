// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Command webhooks provides example consumer code for Tailscale
// webhooks.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type event struct {
	Timestamp string            `json:"timestamp"`
	Version   int               `json:"version"`
	Type      string            `json:"type"`
	Tailnet   string            `json:"tailnet"`
	Message   string            `json:"message"`
	Data      map[string]string `json:"data"`
}

const (
	currentVersion = "v1"
	secret         = "tskey-webhook-xxxxx" // sensitive, here just as an example
)

var (
	errNotSigned     = errors.New("webhook has no signature")
	errInvalidHeader = errors.New("webhook has an invalid signature")
)

func main() {
	http.HandleFunc("/webhook", webhooksHandler)
	if err := http.ListenAndServe(":80", nil); err != nil {
		log.Fatal(err)
	}
}

func webhooksHandler(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	events, err := verifyWebhookSignature(req, secret)
	if err != nil {
		log.Printf("error validating signature: %v\n", err)
	} else {
		log.Printf("events received %v\n", events)
		// Do something with your events. :)
	}

	// The handler should always report 2XX except in the case of
	// transient failures (e.g. database backend is down).
	// Otherwise your future events will be blocked by retries.
}

// verifyWebhookSignature checks the request's "Tailscale-Webhook-Signature"
// header to verify that the events were signed by your webhook secret.
// If verification fails, an error is reported.
// If verification succeeds, the list of contained events is reported.
func verifyWebhookSignature(req *http.Request, secret string) (events []event, err error) {
	defer req.Body.Close()

	// Grab the signature sent on the request header.
	timestamp, signatures, err := parseSignatureHeader(req.Header.Get("Tailscale-Webhook-Signature"))
	if err != nil {
		return nil, err
	}

	// Verify that the timestamp is recent.
	// Here, we use a threshold of 5 minutes.
	if timestamp.Before(time.Now().Add(-time.Minute * 5)) {
		return nil, fmt.Errorf("invalid header: timestamp older than 5 minutes")
	}

	// Form the expected signature.
	b, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprint(timestamp.Unix())))
	mac.Write([]byte("."))
	mac.Write(b)
	want := hex.EncodeToString(mac.Sum(nil))

	// Verify that the signatures match.
	var match bool
	for _, signature := range signatures[currentVersion] {
		if subtle.ConstantTimeCompare([]byte(signature), []byte(want)) == 1 {
			match = true
			break
		}
	}
	if !match {
		return nil, fmt.Errorf("signature does not match: want = %q, got = %q", want, signatures[currentVersion])
	}

	// If verified, return the events.
	if err := json.Unmarshal(b, &events); err != nil {
		return nil, err
	}
	return events, nil
}

// parseSignatureHeader splits header into its timestamp and included signatures.
// The signatures are reported as a map of version (e.g. "v1") to a list of signatures
// found with that version.
func parseSignatureHeader(header string) (timestamp time.Time, signatures map[string][]string, err error) {
	if header == "" {
		return time.Time{}, nil, fmt.Errorf("request has no signature")
	}

	signatures = make(map[string][]string)
	pairs := strings.Split(header, ",")
	for _, pair := range pairs {
		parts := strings.Split(pair, "=")
		if len(parts) != 2 {
			return time.Time{}, nil, errNotSigned
		}

		switch parts[0] {
		case "t":
			tsint, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return time.Time{}, nil, errInvalidHeader
			}
			timestamp = time.Unix(tsint, 0)
		case currentVersion:
			signatures[parts[0]] = append(signatures[parts[0]], parts[1])
		default:
			// Ignore unknown parts of the header.
			continue
		}
	}

	if len(signatures) == 0 {
		return time.Time{}, nil, errNotSigned
	}
	return
}
