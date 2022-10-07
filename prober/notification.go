// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package prober

import (
	"bytes"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	alertGenerated   = expvar.NewInt("alert_generated")
	alertFailed      = expvar.NewInt("alert_failed")
	warningGenerated = expvar.NewInt("warning_generated")
	warningFailed    = expvar.NewInt("warning_failed")
)

// SendAlert sends an alert to the incident response system, to
// page a human responder immediately.
// summary should be short and state the nature of the emergency.
// details can be longer, up to 29 KBytes.
func SendAlert(summary, details string) error {
	type squadcastAlert struct {
		Message     string            `json:"message"`
		Description string            `json:"description"`
		Tags        map[string]string `json:"tags,omitempty"`
		Status      string            `json:"status"`
		EventId     string            `json:"event_id"`
	}

	sqa := squadcastAlert{
		Message:     summary,
		Description: details,
		Tags:        map[string]string{"severity": "critical"},
		Status:      "trigger",
		EventId:     uuid.New().String(),
	}

	sqBody, err := json.Marshal(sqa)
	if err != nil {
		alertFailed.Add(1)
		return fmt.Errorf("encoding alert payload: %w", err)
	}

	webhookUrl := os.Getenv("SQUADCAST_WEBHOOK")
	if webhookUrl == "" {
		warningFailed.Add(1)
		return errors.New("no SQUADCAST_WEBHOOK configured")
	}

	req, err := http.NewRequest(http.MethodPost, webhookUrl, bytes.NewBuffer(sqBody))
	if err != nil {
		alertFailed.Add(1)
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		alertFailed.Add(1)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		alertFailed.Add(1)
		return errors.New(resp.Status)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		alertFailed.Add(1)
		return errors.New("non-ok response returned from Squadcast")
	}

	alertGenerated.Add(1)
	return nil
}

// SendWarning will post a message to Slack.
// details should be a description of the issue.
func SendWarning(details string) error {
	webhookUrl := os.Getenv("SLACK_WEBHOOK")
	if webhookUrl == "" {
		warningFailed.Add(1)
		return errors.New("no SLACK_WEBHOOK configured")
	}

	type slackRequestBody struct {
		Text string `json:"text"`
	}

	slackBody, err := json.Marshal(slackRequestBody{Text: details})
	if err != nil {
		warningFailed.Add(1)
		return err
	}

	req, err := http.NewRequest("POST", webhookUrl, bytes.NewReader(slackBody))
	if err != nil {
		warningFailed.Add(1)
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		warningFailed.Add(1)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		warningFailed.Add(1)
		return errors.New(resp.Status)
	}

	body, _ := io.ReadAll(resp.Body)
	if s := strings.TrimSpace(string(body)); s != "ok" {
		warningFailed.Add(1)
		return errors.New("non-ok response returned from Slack")
	}
	warningGenerated.Add(1)
	return nil
}
