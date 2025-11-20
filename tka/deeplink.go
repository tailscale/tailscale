// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

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

// generateHMAC computes a SHA-256 HMAC for the concatenation of components,
// using the Authority stateID as secret.
func (a *Authority) generateHMAC(params NewDeeplinkParams) []byte {
	stateID, _ := a.StateIDs()

	key := make([]byte, 8)
	binary.LittleEndian.PutUint64(key, stateID)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(params.NodeKey))
	mac.Write([]byte(params.TLPub))
	mac.Write([]byte(params.DeviceName))
	mac.Write([]byte(params.OSName))
	mac.Write([]byte(params.LoginName))
	return mac.Sum(nil)
}

type NewDeeplinkParams struct {
	NodeKey    string
	TLPub      string
	DeviceName string
	OSName     string
	LoginName  string
}

// NewDeeplink creates a signed deeplink using the authority's stateID as a
// secret. This deeplink can then be validated by ValidateDeeplink.
func (a *Authority) NewDeeplink(params NewDeeplinkParams) (string, error) {
	if params.NodeKey == "" || !strings.HasPrefix(params.NodeKey, "nodekey:") {
		return "", fmt.Errorf("invalid node key %q", params.NodeKey)
	}
	if params.TLPub == "" || !strings.HasPrefix(params.TLPub, "tlpub:") {
		return "", fmt.Errorf("invalid tlpub %q", params.TLPub)
	}
	if params.DeviceName == "" {
		return "", fmt.Errorf("invalid device name %q", params.DeviceName)
	}
	if params.OSName == "" {
		return "", fmt.Errorf("invalid os name %q", params.OSName)
	}
	if params.LoginName == "" {
		return "", fmt.Errorf("invalid login name %q", params.LoginName)
	}

	u := url.URL{
		Scheme: DeeplinkTailscaleURLScheme,
		Host:   DeeplinkCommandSign,
		Path:   "/v1/",
	}
	v := url.Values{}
	v.Set("nk", params.NodeKey)
	v.Set("tp", params.TLPub)
	v.Set("dn", params.DeviceName)
	v.Set("os", params.OSName)
	v.Set("em", params.LoginName)

	hmac := a.generateHMAC(params)
	v.Set("hm", hex.EncodeToString(hmac))

	u.RawQuery = v.Encode()
	return u.String(), nil
}

type DeeplinkValidationResult struct {
	IsValid      bool
	Error        string
	Version      uint8
	NodeKey      string
	TLPub        string
	DeviceName   string
	OSName       string
	EmailAddress string
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
			Error:   err.Error(),
		}
	}

	if parsedUrl.Scheme != DeeplinkTailscaleURLScheme {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   fmt.Sprintf("unhandled scheme %s, expected %s", parsedUrl.Scheme, DeeplinkTailscaleURLScheme),
		}
	}

	if parsedUrl.Host != DeeplinkCommandSign {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   fmt.Sprintf("unhandled host %s, expected %s", parsedUrl.Host, DeeplinkCommandSign),
		}
	}

	path := parsedUrl.EscapedPath()
	pathComponents := strings.Split(path, "/")
	if len(pathComponents) != 3 {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   "invalid path components number found",
		}
	}

	if pathComponents[1] != "v1" {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   fmt.Sprintf("expected v1 deeplink version, found something else: %s", pathComponents[1]),
		}
	}

	nodeKey := parsedUrl.Query().Get("nk")
	if len(nodeKey) == 0 {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   "missing nk (NodeKey) query parameter",
		}
	}

	tlPub := parsedUrl.Query().Get("tp")
	if len(tlPub) == 0 {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   "missing tp (TLPub) query parameter",
		}
	}

	deviceName := parsedUrl.Query().Get("dn")
	if len(deviceName) == 0 {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   "missing dn (DeviceName) query parameter",
		}
	}

	osName := parsedUrl.Query().Get("os")
	if len(deviceName) == 0 {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   "missing os (OSName) query parameter",
		}
	}

	emailAddress := parsedUrl.Query().Get("em")
	if len(emailAddress) == 0 {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   "missing em (EmailAddress) query parameter",
		}
	}

	hmacString := parsedUrl.Query().Get("hm")
	if len(hmacString) == 0 {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   "missing hm (HMAC) query parameter",
		}
	}

	computedHMAC := a.generateHMAC(NewDeeplinkParams{
		NodeKey:    nodeKey,
		TLPub:      tlPub,
		DeviceName: deviceName,
		OSName:     osName,
		LoginName:  emailAddress,
	})

	hmacHexBytes, err := hex.DecodeString(hmacString)
	if err != nil {
		return DeeplinkValidationResult{IsValid: false, Error: "could not hex-decode hmac"}
	}

	if !hmac.Equal(computedHMAC, hmacHexBytes) {
		return DeeplinkValidationResult{
			IsValid: false,
			Error:   "hmac authentication failed",
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
