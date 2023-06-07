// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tka

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

const (
	DeeplinkTailscaleURLScheme = "tailscale"
	DeeplinkCommandSign        = "sign-device"
)

type DeeplinkValidationResult struct {
	IsValid      bool
	Error        error
	Version      uint8
	NodeKey      string
	TLPub        string
	DeviceName   string
	OSName       string
	EmailAddress string
}

// GenerateHMAC computes a SHA-256 HMAC for the concatenation of components, using
// stateID as secret.
func generateHMAC(stateID uint64, components []string) []byte {
	key := make([]byte, 8)
	binary.LittleEndian.PutUint64(key, stateID)
	mac := hmac.New(sha256.New, key)
	for _, component := range components {
		mac.Write([]byte(component))
	}
	return mac.Sum(nil)
}

// ValidateDeeplink validates a device signing deeplink using the authority's stateID.
// The input urlString follows this structure:
//
// tailscale://sign-device/v1/?nk=xxx&tp=xxx&dn=xxx&os=xxx&em=xxx&hm=xxx
//
// where:
// - "nk" is the nodekey of the node being signed
// - "tp" is the tailnet lock public key
// - "dn" is the name of the node
// - "os" is the operating system of the node
// - "em" is the email address associated with the node
// - "hm" is a SHA-256 HMAC computed over the concatenation of the above fields, encoded as a hex string
func (a *Authority) ValidateDeeplink(urlString string) DeeplinkValidationResult {
	parsedUrl, err := url.Parse(urlString)
	if err != nil {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   err,
		}
	}

	if parsedUrl.Scheme != DeeplinkTailscaleURLScheme {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   fmt.Errorf("unhandled scheme %s, expected %s", parsedUrl.Scheme, DeeplinkTailscaleURLScheme),
		}
	}

	if parsedUrl.Host != DeeplinkCommandSign {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   fmt.Errorf("unhandled host %s, expected %s", parsedUrl.Host, DeeplinkCommandSign),
		}
	}

	path := parsedUrl.EscapedPath()
	pathComponents := strings.Split(path, "/")
	if len(pathComponents) == 0 {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   fmt.Errorf("no path components found"),
		}
	}

	if pathComponents[0] != "v1" {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   fmt.Errorf("expected v1 deeplink version, found something else"),
		}
	}

	nodeKey := parsedUrl.Query().Get("nk")
	if len(nodeKey) == 0 {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   fmt.Errorf("missing nk (NodeKey) query parameter"),
		}
	}

	tlPub := parsedUrl.Query().Get("tp")
	if len(tlPub) == 0 {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   fmt.Errorf("missing tp (TLPub) query parameter"),
		}
	}

	deviceName := parsedUrl.Query().Get("dn")
	if len(deviceName) == 0 {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   fmt.Errorf("missing dn (DeviceName) query parameter"),
		}
	}

	osName := parsedUrl.Query().Get("os")
	if len(deviceName) == 0 {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   fmt.Errorf("missing os (OSName) query parameter"),
		}
	}

	emailAddress := parsedUrl.Query().Get("em")
	if len(emailAddress) == 0 {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   fmt.Errorf("missing em (EmailAddress) query parameter"),
		}
	}

	hmacString := parsedUrl.Query().Get("hm")
	if len(hmacString) == 0 {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   fmt.Errorf("missing hm (HMAC) query parameter"),
		}
	}

	components := []string{nodeKey, tlPub, deviceName, osName, emailAddress}
	stateID1, _ := a.StateIDs()
	computedHMAC := generateHMAC(stateID1, components)

	hmacHexBytes, err := hex.DecodeString(hmacString)
	if err != nil {
		return DeeplinkValidationResult{IsValid: false, Error: fmt.Errorf("could not hex-decode hmac")}
	}
	if hmac.Equal(computedHMAC, hmacHexBytes) {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   fmt.Errorf("hmac authentication failed"),
		}
	}

	return DeeplinkValidationResult{
		IsValid:      true,
		NodeKey:      nodeKey,
		TLPub:        tlPub,
		DeviceName:   deviceName,
		OSName:       osName,
		EmailAddress: emailAddress,
	}
}
